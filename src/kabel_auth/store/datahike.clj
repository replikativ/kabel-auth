(ns kabel-auth.store.datahike
  "Datahike-backed implementation of AuthStore.

   Takes an existing Datahike connection (shared with system DB).
   Schema must already include the user/session attributes."
  (:require [kabel-auth.store.protocol :as p]
            [datahike.api :as d])
  (:import [java.util UUID]))

(defrecord DatahikeAuthStore [conn]
  p/AuthStore

  ;; User operations

  (create-user! [_ user-data]
    (let [email (:user/email user-data)]
      (when-not email
        (throw (ex-info "Email is required" {:type :validation-error})))
      (when (seq (d/q '[:find ?e :in $ ?email :where [?e :user/email ?email]]
                      @conn email))
        (throw (ex-info "Email already exists" {:type :email-exists :email email})))
      (let [user-id (UUID/randomUUID)
            user (assoc user-data
                        :user/id user-id
                        :user/created (p/now-instant))]
        (d/transact conn [(dissoc user :user/auth-providers)
                          ;; Auth providers as separate assertions (cardinality many)
                          {:user/id user-id
                           :user/auth-providers (or (:user/auth-providers user-data) #{:password})}])
        user)))

  (find-user-by-email [_ email]
    (when-let [eid (d/q '[:find ?e . :in $ ?email :where [?e :user/email ?email]]
                        @conn email)]
      (let [entity (d/pull @conn '[*] eid)]
        ;; Convert to flat map matching MemoryAuthStore shape
        (dissoc entity :db/id))))

  (find-user-by-id [_ user-id]
    (when-let [eid (d/q '[:find ?e . :in $ ?uid :where [?e :user/id ?uid]]
                        @conn user-id)]
      (let [entity (d/pull @conn '[*] eid)]
        (dissoc entity :db/id))))

  (update-user! [_ user-id updates]
    (if-let [eid (d/q '[:find ?e . :in $ ?uid :where [?e :user/id ?uid]]
                      @conn user-id)]
      (let [;; Check email uniqueness if changing email
            new-email (:user/email updates)]
        (when new-email
          (let [existing (d/q '[:find ?e . :in $ ?email :where [?e :user/email ?email]]
                              @conn new-email)]
            (when (and existing (not= existing eid))
              (throw (ex-info "Email already exists" {:type :email-exists :email new-email})))))
        ;; Transact updates with entity identity
        (d/transact conn [(assoc updates :user/id user-id)])
        ;; Return updated entity
        (let [entity (d/pull @conn '[*] eid)]
          (dissoc entity :db/id)))
      (throw (ex-info "User not found" {:type :user-not-found :user-id user-id}))))

  ;; Session operations

  (create-session! [_ session-data]
    (let [session-id (UUID/randomUUID)
          token-hash (:session/refresh-token-hash session-data)
          session (assoc session-data
                         :session/id session-id
                         :session/created (p/now-instant))]
      (when-not token-hash
        (throw (ex-info "Refresh token hash is required" {:type :validation-error})))
      (d/transact conn [session])
      session))

  (find-session-by-token-hash [_ token-hash]
    (when-let [eid (d/q '[:find ?e . :in $ ?hash
                           :where [?e :session/refresh-token-hash ?hash]]
                        @conn token-hash)]
      (let [session (dissoc (d/pull @conn '[*] eid) :db/id)]
        (when-not (p/expired? session)
          session))))

  (delete-session! [_ session-id]
    (if-let [eid (d/q '[:find ?e . :in $ ?sid :where [?e :session/id ?sid]]
                      @conn session-id)]
      (do (d/transact conn [[:db/retractEntity eid]])
          true)
      false))

  (delete-user-sessions! [_ user-id]
    (let [session-eids (d/q '[:find [?e ...] :in $ ?uid
                               :where [?e :session/user-id ?uid]]
                            @conn user-id)]
      (when (seq session-eids)
        (d/transact conn (mapv (fn [eid] [:db/retractEntity eid]) session-eids)))
      (count session-eids)))

  (delete-expired-sessions! [_]
    (let [now (p/now-instant)
          expired-eids (d/q '[:find [?e ...] :in $ ?now
                               :where
                               [?e :session/expires ?exp]
                               [(< ?exp ?now)]]
                            @conn now)]
      (when (seq expired-eids)
        (d/transact conn (mapv (fn [eid] [:db/retractEntity eid]) expired-eids)))
      (count expired-eids))))

(defn datahike-auth-store
  "Create a Datahike-backed auth store.

   Takes an existing Datahike connection. The database must already
   have the user/session schema attributes transacted.

   Usage:
     (def store (datahike-auth-store conn))
     (p/create-user! store {:user/email \"test@example.com\" :user/name \"Test\"})"
  [conn]
  (->DatahikeAuthStore conn))
