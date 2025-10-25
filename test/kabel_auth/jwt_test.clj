(ns kabel-auth.jwt-test
  (:require [clojure.test :refer [deftest is testing]]
            [kabel-auth.jwt :as jwt])
  (:import (java.security KeyPairGenerator)))

(deftest hs256-valid-token
  (testing "Validator returns principal map for a valid HS256 token"
    (let [secret "topsecret"
          now (quot (System/currentTimeMillis) 1000)
          claims {:sub "alice@example.org"
                  :iss "test-issuer"
                  :aud "test-aud"
                  :iat now
                  :nbf (- now 10)
                  :exp (+ now 60)}
          token (jwt/sign-hs256 secret claims)
          validate (jwt/build-bearer-validator {:alg :HS256
                                                :secret secret
                                                :required-claims {:iss "test-issuer" :aud "test-aud"}
                                                :leeway-seconds 5})
          req {:headers {"authorization" (str "Bearer " token)}}
          principal (validate req)]
      (is (map? principal))
      (is (= "alice@example.org" (:sub principal))))))

(deftest hs256-wrong-signature
  (testing "Validator returns nil for wrong signature"
    (let [secret "topsecret"
          now (quot (System/currentTimeMillis) 1000)
          claims {:sub "bob@example.org" :exp (+ now 60)}
          token (jwt/sign-hs256 secret claims)
          tampered (str token "x")
          validate (jwt/build-bearer-validator {:alg :HS256 :secret secret})
          req {:headers {"authorization" (str "Bearer " tampered)}}]
      (is (nil? (validate req))))))

(deftest hs256-expired
  (testing "Validator returns nil for expired token"
    (let [secret "topsecret"
          now (quot (System/currentTimeMillis) 1000)
          claims {:sub "carol@example.org" :exp (- now 10)}
          token (jwt/sign-hs256 secret claims)
          validate (jwt/build-bearer-validator {:alg :HS256 :secret secret :leeway-seconds 0})
          req {:headers {"authorization" (str "Bearer " token)}}]
      (is (nil? (validate req))))))

(deftest rs256-valid-token
  (testing "Validator returns principal map for a valid RS256 token"
    (let [kpg (doto (KeyPairGenerator/getInstance "RSA") (.initialize 2048))
          kp (.generateKeyPair kpg)
          now (quot (System/currentTimeMillis) 1000)
          claims {:sub "dave@example.org" :exp (+ now 60)}
          token (jwt/sign-rs256 (.getPrivate kp) claims)
          validate (jwt/build-bearer-validator {:alg :RS256 :public-key (.getPublic kp)})
          req {:headers {"authorization" (str "Bearer " token)}}
          principal (validate req)]
      (is (= "dave@example.org" (:sub principal))))))

(deftest rs256-wrong-signature
  (testing "Validator returns nil for wrong RS256 signature"
    (let [kpg (doto (KeyPairGenerator/getInstance "RSA") (.initialize 2048))
          kpA (.generateKeyPair kpg)
          kpB (.generateKeyPair kpg)
          now (quot (System/currentTimeMillis) 1000)
          claims {:sub "erin@example.org" :exp (+ now 60)}
          token (jwt/sign-rs256 (.getPrivate kpA) claims)
          validate (jwt/build-bearer-validator {:alg :RS256 :public-key (.getPublic kpB)})
          req {:headers {"authorization" (str "Bearer " token)}}]
      (is (nil? (validate req))))))
