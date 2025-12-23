(ns kabel-auth.store.protocol
  "Protocol for user and session storage in kabel-auth.

   Implementations:
   - kabel-auth.store.memory - In-memory store for testing
   - kabel-auth.store.datahike - Datahike-backed store (optional dep)")

(defprotocol AuthStore
  "Abstraction over user and session storage."

  ;; User operations
  (create-user! [store user-data]
    "Create a new user. user-data should contain at minimum :user/email.
     Returns the created user map with :user/id (UUID) added.
     Throws if email already exists.")

  (find-user-by-email [store email]
    "Find user by email address.
     Returns user map or nil if not found.")

  (find-user-by-id [store user-id]
    "Find user by UUID.
     Returns user map or nil if not found.")

  (update-user! [store user-id updates]
    "Update user attributes. updates is a map of attributes to change.
     Returns updated user map.
     Throws if user not found.")

  ;; Session operations
  (create-session! [store session-data]
    "Create a new session. session-data should contain:
     - :session/user-id - UUID of the user
     - :session/refresh-token-hash - SHA-256 hash of refresh token
     - :session/expires - Instant when session expires
     Optional:
     - :session/user-agent
     - :session/ip
     Returns session map with :session/id added.")

  (find-session-by-token-hash [store token-hash]
    "Find session by the hashed refresh token.
     Returns session map or nil if not found or expired.")

  (delete-session! [store session-id]
    "Delete a specific session by ID.
     Returns true if deleted, false if not found.")

  (delete-user-sessions! [store user-id]
    "Delete all sessions for a user (logout all devices).
     Returns count of deleted sessions.")

  (delete-expired-sessions! [store]
    "Clean up expired sessions.
     Returns count of deleted sessions."))

;; Helper functions for implementations

(defn now-instant
  "Get current time as java.util.Date (compatible with Datahike :db.type/instant)."
  []
  (java.util.Date.))

(defn expired?
  "Check if a session is expired."
  [session]
  (when-let [expires (:session/expires session)]
    (neg? (compare expires (now-instant)))))

(defn hash-token
  "SHA-256 hash a token string for storage."
  [token]
  (let [md (java.security.MessageDigest/getInstance "SHA-256")
        bytes (.digest md (.getBytes token "UTF-8"))]
    (apply str (map #(format "%02x" %) bytes))))
