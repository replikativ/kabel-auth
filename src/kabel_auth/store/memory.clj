(ns kabel-auth.store.memory
  "In-memory implementation of AuthStore for testing.

   All data is stored in atoms and lost when the JVM exits.
   Thread-safe for concurrent access."
  (:require [kabel-auth.store.protocol :as p])
  (:import [java.util UUID]))

(defrecord MemoryAuthStore [users-by-id users-by-email sessions-by-id sessions-by-token-hash]
  p/AuthStore

  ;; User operations

  (create-user! [_ user-data]
    (let [email (:user/email user-data)]
      (when-not email
        (throw (ex-info "Email is required" {:type :validation-error})))
      (when (get @users-by-email email)
        (throw (ex-info "Email already exists" {:type :email-exists :email email})))
      (let [user-id (UUID/randomUUID)
            user (assoc user-data
                        :user/id user-id
                        :user/created (p/now-instant))]
        (swap! users-by-id assoc user-id user)
        (swap! users-by-email assoc email user)
        user)))

  (find-user-by-email [_ email]
    (get @users-by-email email))

  (find-user-by-id [_ user-id]
    (get @users-by-id user-id))

  (update-user! [_ user-id updates]
    (if-let [existing (get @users-by-id user-id)]
      (let [old-email (:user/email existing)
            new-email (:user/email updates)
            updated (merge existing updates)]
        ;; Handle email change
        (when (and new-email (not= old-email new-email))
          (when (get @users-by-email new-email)
            (throw (ex-info "Email already exists" {:type :email-exists :email new-email})))
          (swap! users-by-email dissoc old-email)
          (swap! users-by-email assoc new-email updated))
        (swap! users-by-id assoc user-id updated)
        (when-not (and new-email (not= old-email new-email))
          (swap! users-by-email assoc (:user/email updated) updated))
        updated)
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
      (swap! sessions-by-id assoc session-id session)
      (swap! sessions-by-token-hash assoc token-hash session)
      session))

  (find-session-by-token-hash [_ token-hash]
    (when-let [session (get @sessions-by-token-hash token-hash)]
      (when-not (p/expired? session)
        session)))

  (delete-session! [_ session-id]
    (if-let [session (get @sessions-by-id session-id)]
      (do
        (swap! sessions-by-id dissoc session-id)
        (swap! sessions-by-token-hash dissoc (:session/refresh-token-hash session))
        true)
      false))

  (delete-user-sessions! [_ user-id]
    (let [user-sessions (->> @sessions-by-id
                             vals
                             (filter #(= user-id (:session/user-id %))))]
      (doseq [session user-sessions]
        (swap! sessions-by-id dissoc (:session/id session))
        (swap! sessions-by-token-hash dissoc (:session/refresh-token-hash session)))
      (count user-sessions)))

  (delete-expired-sessions! [_]
    (let [expired (->> @sessions-by-id
                       vals
                       (filter p/expired?))]
      (doseq [session expired]
        (swap! sessions-by-id dissoc (:session/id session))
        (swap! sessions-by-token-hash dissoc (:session/refresh-token-hash session)))
      (count expired))))

(defn memory-auth-store
  "Create a new in-memory auth store.

   Usage:
     (def store (memory-auth-store))
     (p/create-user! store {:user/email \"test@example.com\" :user/name \"Test\"})"
  []
  (->MemoryAuthStore (atom {}) (atom {}) (atom {}) (atom {})))
