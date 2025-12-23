(ns kabel-auth.jwt
  "Minimal JWT utilities to validate Bearer tokens in Ring requests.
  Focuses on HS256 (HMAC-SHA256) to keep dependencies light. For RS256/ES256,
  supply your own verifier function with a public key.

  Provides:
  - sign-hs256: helper for tests to construct tokens.
  - build-bearer-validator: returns a (fn [req] principal-or-nil) for http-kit.
  "
  (:require [jsonista.core :as j]
            [clojure.string :as str])
  (:import (java.util Base64 Date)
           (java.security KeyFactory PublicKey PrivateKey Signature)
           (java.security.spec X509EncodedKeySpec PKCS8EncodedKeySpec)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(def ^:private utf8 "UTF-8")
(def ^:private json-mapper (j/object-mapper {:decode-key-fn true}))

(defn- b64url-encode-bytes [^bytes bs]
  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bs))

(defn- b64url-decode-bytes [^String s]
  (.decode (Base64/getUrlDecoder) s))

(defn- json->b64 [m]
  (-> (j/write-value-as-bytes m)
      (b64url-encode-bytes)))

(defn- b64->json [^String s]
  (-> s b64url-decode-bytes (j/read-value json-mapper)))

;; --- RSA helpers (PEM <-> keys) ---
(defn- strip-pem ^String [^String pem]
  (-> pem
      (str/replace #"-----BEGIN [^-]+-----" "")
      (str/replace #"-----END [^-]+-----" "")
      (str/replace #"\s" "")))

(defn- public-key-from-pem ^PublicKey [^String pem]
  (let [kf (KeyFactory/getInstance "RSA")
        bytes (.decode (Base64/getDecoder) (strip-pem pem))
        spec (X509EncodedKeySpec. bytes)]
    (.generatePublic kf spec)))

(defn- private-key-from-pem ^PrivateKey [^String pem]
  (let [kf (KeyFactory/getInstance "RSA")
        bytes (.decode (Base64/getDecoder) (strip-pem pem))
        spec (PKCS8EncodedKeySpec. bytes)]
    (.generatePrivate kf spec)))

(defn- hmac-sha256 [^bytes key-bytes ^bytes data]
  (let [algo "HmacSHA256"
        mac (Mac/getInstance algo)]
    (.init mac (SecretKeySpec. key-bytes algo))
    (.doFinal mac data)))

(defn sign-hs256
  "Create an HS256 JWT for testing.
  claims map may include :exp and :nbf as epoch seconds."
  [^String secret claims]
  (let [header {:alg "HS256" :typ "JWT"}
        header-b64 (json->b64 header)
        payload-b64 (json->b64 claims)
        signing-input (.getBytes (str header-b64 "." payload-b64) utf8)
        sig-bytes (hmac-sha256 (.getBytes secret utf8) signing-input)
        sig-b64 (b64url-encode-bytes sig-bytes)]
    (str header-b64 "." payload-b64 "." sig-b64)))

(defn sign-rs256
  "Create an RS256 JWT for testing from a PrivateKey or PEM string."
  [priv-key-or-pem claims]
  (let [^PrivateKey priv-key (if (instance? PrivateKey priv-key-or-pem)
                               priv-key-or-pem
                               (private-key-from-pem priv-key-or-pem))
        header {:alg "RS256" :typ "JWT"}
        header-b64 (json->b64 header)
        payload-b64 (json->b64 claims)
        signing-input (.getBytes (str header-b64 "." payload-b64) utf8)
        ^Signature sig (Signature/getInstance "SHA256withRSA")]
    (.initSign sig priv-key)
    (.update sig signing-input)
    (let [sig-bytes (.sign sig)
          sig-b64 (b64url-encode-bytes sig-bytes)]
      (str header-b64 "." payload-b64 "." sig-b64))))

(defn- parse-token [^String token]
  (let [[h p s :as parts] (when token (str/split token #"\."))]
    (when (not= 3 (count parts))
      (throw (ex-info "Malformed JWT (expected 3 parts)" {:token token :parts parts})))
    (let [header (b64->json h)
          payload (b64->json p)
          sig-bytes (b64url-decode-bytes s)
          signing-input (.getBytes (str h "." p) utf8)]
      {:header header :payload payload :sig sig-bytes :signing-input signing-input})))

(defn- now-epoch [] (long (/ (.getTime (Date.)) 1000)))

(defn- check-time-claims! [claims leeway]
  (let [now (now-epoch)
        exp (:exp claims)
        nbf (:nbf claims)
        iat (:iat claims)]
    (when (and exp (> (- now leeway) exp))
      (throw (ex-info "JWT expired" {:now now :exp exp :leeway leeway})))
    (when (and nbf (< (+ now leeway) nbf))
      (throw (ex-info "JWT not yet valid" {:now now :nbf nbf :leeway leeway})))
    (when (and iat (< (+ now leeway) iat))
      (throw (ex-info "JWT issued in the future" {:now now :iat iat :leeway leeway})))
    true))

(defn- check-required-claims! [claims {:keys [iss aud]}]
  (when (and iss (not= iss (:iss claims)))
    (throw (ex-info "Invalid issuer" {:expected iss :actual (:iss claims)})))
  (when (and aud (not= aud (:aud claims)))
    (throw (ex-info "Invalid audience" {:expected aud :actual (:aud claims)})))
  true)

(defn build-bearer-validator
  [{:keys [alg secret public-key required-claims leeway-seconds]
    :or {alg :HS256 leeway-seconds 60}}]
  (fn [req]
    (try
      (when-let [auth (get-in req [:headers "authorization"])]
        (when-let [[_ token] (re-matches #"(?i)^Bearer\s+(.+)$" auth)]
          (let [{:keys [payload sig signing-input]} (parse-token token)]
            (case alg
              :HS256 (let [expected (hmac-sha256 (.getBytes (or secret "") utf8) signing-input)]
                       (when-not (java.util.Arrays/equals ^bytes expected ^bytes sig)
                         (throw (ex-info "Invalid signature" {})))
                       (check-time-claims! payload leeway-seconds)
                       (when required-claims
                         (check-required-claims! payload required-claims))
                       ;; Return principal claims (entire payload)
                       payload)
              :RS256 (let [^PublicKey pub (cond
                                            (instance? PublicKey public-key) public-key
                                            (string? public-key) (public-key-from-pem public-key)
                                            :else (throw (ex-info ":public-key must be a PublicKey or PEM string" {:got (type public-key)})))
                           ^Signature v (Signature/getInstance "SHA256withRSA")]
                       (.initVerify v pub)
                       (.update v signing-input)
                       (when-not (.verify v sig)
                         (throw (ex-info "Invalid signature" {})))
                       (check-time-claims! payload leeway-seconds)
                       (when required-claims
                         (check-required-claims! payload required-claims))
                       payload)
              (throw (ex-info "Unsupported alg" {:alg alg}))))))
      (catch Exception _
        ;; Be conservative: return nil on any error.
        nil))))
