(ns kabel-auth.core
  "Authentication middleware for kabel."
  (:require [kabel.platform-log :refer [debug info warn error]]
            [konserve.core :as k]
            [hasch.core :refer [uuid]]
            [kabel-auth.session :as session]
            #?(:clj [superv.async :refer [S <? <?? go-try go-loop-try]])
            #?(:clj [clojure.core.async :as async
                     :refer [<! >! >!! <!! timeout chan alt! go put!
                             go-loop pub sub unsub close!]]
               :cljs [cljs.core.async :as async
                      :refer [<! >! timeout chan put! pub sub unsub close! alts!]]))
  #?(:cljs (:require-macros [superv.async :refer [<<? <? go-try go-loop-try]]
                          [cljs.core.async.macros :refer [go go-loop alt!]]
                          [kabel.platform-log :refer [debug info warn error]])))

(defn now [] #?(:clj (java.util.Date.)
                :cljs (js/Date.)))


(def external-tokens (atom {}))

(defn register-external-token
  "Use this function to create a token to communicate externally,
  e.g. exposed in an authenticating URL clicked by the user. You need
  to map this back via the external-tokens atom."
  [token]
  (let [ext-token (uuid token)]
    (swap! external-tokens assoc ext-token token)
    ext-token))

(def inbox-auth (chan))
(def ^:private p-in-auth (pub inbox-auth :token))


;; ===== receiver side =====

(defn auth-request [S receiver-token-store sender user session-id
                    request-fn out new-in a-msg request-timeout]
  (let [[[_ proto username]] (re-seq #"(.+):(.+)" user)
        token (uuid)
        a-ch (chan)]
    (sub p-in-auth token a-ch)
    (go-try S
      (debug "requesting auth" user "with timeout" request-timeout)
      (>! out {:type ::auth-request :user username :protocol (keyword proto)})
      (request-fn {:token token :user username :protocol (keyword proto)})
      (let [[v port] (async/alts! [a-ch (timeout request-timeout)])]
        (if (= port a-ch)
          (let [tok {:token token :time (now) :session session-id}]
            (debug "authenticated" user token)
            (>! out {:type ::auth-token :token token :user user})
            (<! (k/assoc-in receiver-token-store [sender user] tok))
            (>! new-in a-msg))
          (do
            (debug "timeout" user)
            (>! out {:type ::auth-timeout :msg a-msg})))))))



(defn authenticate [S trusted-hosts receiver-token-store
                    request-fn auth-ch new-in out token-timeout request-timeout]
  (let [session-id (uuid)]
    (go-loop-try S [a-msg (<? S auth-ch)]
      (if a-msg
        (let [{:keys [sender host user] msg-token :token} a-msg]
          (debug "authenticating" user "for" host)
          (cond
            (@trusted-hosts host)
            (do (debug "trusted host" host)
                (>! new-in a-msg))

      (let [{:keys [time token session]}
          (<? S (k/get-in receiver-token-store [sender user]))]
              (debug "token exists?" sender user token " msg-token: " msg-token)
              (or (= session-id session)
                  (and msg-token
                       (= msg-token token)
                       (< (- (.getTime (now)) (.getTime time)) token-timeout))))
            (do (debug "msg token is valid" msg-token)
                (>! new-in a-msg))

            :else
      (auth-request S receiver-token-store sender user session-id
                          request-fn out new-in a-msg request-timeout))
          (recur (<? S auth-ch)))
        nil))))

;; ===== sender side =====
(defn store-token [S token-store store-token-ch]
  (go-loop-try S [{:keys [user token host]} (<? S store-token-ch)]
    (if token
      (do
        (<? S (k/assoc-in token-store [host user] token))
        (recur (<? S store-token-ch)))
      nil)))

(defn add-tokens-to-out [S remote sender-token-store out new-out]
  (go-loop-try S [o (<? S new-out)]
    (if o
      (do
        (>! out (if-let [t (when (:user o)
                              (<? S (k/get-in sender-token-store [@remote (:user o)])))]
                   (assoc o :token t)
                   o))
        (recur (<? S new-out)))
      nil)))

(defn auth-reply [S auth-request-ch auth-fn]
  (go-loop-try S [{:keys [user protocol]} (<? S auth-request-ch)]
    (if user
      (do
        (<? S (auth-fn protocol user))
        (recur (<? S auth-request-ch)))
      nil)))


;; one sender-store per host
;; m sender-stores with tokens map to receiver-store, mapped by peer-id (TODO can disturb auth?)
(defn auth [trusted-hosts
            receiver-token-store
            sender-token-store
            dispatch-fn
            auth-fn
            request-fn
            [S peer [in out]]
            & {:keys [token-timeout request-timeout msg->user]
               :or {token-timeout (* 31 24 60 60 1000)
                    request-timeout (* 60 60 1000)}}]
  (let [new-in (chan)
        new-out (chan)
        remote (atom nil)
        p (pub in (fn [{:keys [type host] :as m}]
                    ;; TODO uglily taken from first message coming in
                    (when-not @remote (reset! remote host))
                    (case type
                      ;; sender
                      ::auth-request ::auth-request
                      ::auth-token ::auth-token
                      (dispatch-fn m))))
        auth-ch (chan)
        auth-request-ch (chan)
        store-token-ch (chan)]
    ;; receiver
    (sub p :auth auth-ch)
    (authenticate S trusted-hosts receiver-token-store request-fn auth-ch new-in out token-timeout request-timeout)


    ;; sender
    (sub p ::auth-request auth-request-ch)
    (auth-reply S auth-request-ch auth-fn)

    (sub p ::auth-token store-token-ch)
    (store-token S sender-token-store store-token-ch)

    (add-tokens-to-out S remote sender-token-store out new-out)


    (sub p :unrelated new-in) ;; pass-through
    [S peer [new-in new-out]]))

;; Re-export selected session utilities for convenience
(def strip-kabel-meta session/strip-kabel-meta)
(def session-middleware session/session-middleware)

;; ============================================================================
;; New API (v2) - JWT-based authentication with password and OAuth support
;; ============================================================================
;;
;; The legacy API above (auth, auth-request, etc.) uses konserve-based token
;; storage and a custom passwordless flow. The new API below uses industry-
;; standard JWT tokens and supports:
;; - Email/password authentication
;; - OAuth providers (Google, GitHub, etc.)
;; - Token refresh without reconnecting
;; - Dev mode for easy local development
;;
;; See doc/DESIGN.md for full documentation.
;;
;; Quick start:
;;   ;; 1. Create auth store
;;   (require '[kabel-auth.store.memory :refer [memory-auth-store]])
;;   (def store (memory-auth-store))
;;
;;   ;; 2. Configure auth
;;   (def config {:store store
;;                :dev-mode false
;;                :jwt {:secret "your-secret" :issuer "your-app"}})
;;
;;   ;; 3. HTTP routes for login/register
;;   (require '[kabel-auth.routes :as routes])
;;   (def http-handler (routes/auth-handler config))
;;
;;   ;; 4. WebSocket middleware for kabel
;;   (require '[kabel-auth.websocket :as ws])
;;   (def ws-auth-mw (ws/validate-middleware {:jwt (:jwt config)}))
;;
;;   ;; 5. Use with kabel peer
;;   (peer/server-peer S handler peer-id ws-auth-mw)
;;
;; ============================================================================

#?(:clj
   (do
     ;; Re-export main v2 API for convenience
     (require '[kabel-auth.routes :as routes]
              '[kabel-auth.websocket :as websocket]
              '[kabel-auth.middleware :as middleware]
              '[kabel-auth.store.protocol :as store-protocol]
              '[kabel-auth.store.memory :as store-memory]
              '[kabel-auth.password :as password]
              '[kabel-auth.config :as config])

     ;; HTTP routes
     (def auth-routes routes/auth-routes)
     (def auth-handler routes/auth-handler)

     ;; Authentication middleware
     (def validate-middleware websocket/validate-middleware)
     (def authenticate-middleware websocket/authenticate-middleware)
     (def auth-middleware websocket/auth-middleware)

     ;; Ring middleware
     (def wrap-auth middleware/wrap-auth)
     (def require-auth middleware/require-auth)

     ;; Store
     (def memory-auth-store store-memory/memory-auth-store)

     ;; Password utilities
     (def hash-password password/hash-password)
     (def verify-password password/verify-password)
     (def validate-password password/validate-password)
     (def generate-refresh-token password/generate-refresh-token)

     ;; Principal helpers
     (def ^:dynamic *principal* websocket/*principal*)
     (def with-principal websocket/with-principal)
     (def current-principal websocket/current-principal)
     (def require-principal websocket/require-principal)

     ;; Config
     (def merge-config config/merge-config)
     (def validate-config config/validate-config)))
