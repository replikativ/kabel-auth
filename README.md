# kabel-auth

<p align="center">
<a href="https://clojurians.slack.com/archives/CB7GJAN0L"><img src="https://badgen.net/badge/-/slack?icon=slack&label"/></a>
<a href="https://clojars.org/io.replikativ/kabel-auth"><img src="https://img.shields.io/clojars/v/io.replikativ/kabel-auth.svg"/></a>
<a href="https://circleci.com/gh/replikativ/kabel-auth"><img src="https://circleci.com/gh/replikativ/kabel-auth.svg?style=shield"/></a>
<a href="https://github.com/replikativ/kabel-auth/tree/main"><img src="https://img.shields.io/github/last-commit/replikativ/kabel-auth/main"/></a>
<a href="https://cljdoc.org/d/io.replikativ/kabel-auth"><img src="https://badgen.net/badge/cljdoc/kabel-auth/blue"/></a>
</p>

Authentication middleware for [kabel](https://github.com/replikativ/kabel). Provides multiple authentication strategies for WebSocket connections:

- **JWT validation** (HS256, RS256) for token-based auth
- **Password hashing** via bcrypt for traditional auth flows
- **Passwordless authentication** via email/SMS token verification
- **Session middleware** for attaching identity to messages
- **HTTP routes** for auth endpoints (login, register, refresh)
- **Pluggable storage** for tokens and user data

Used in [replikativ](https://github.com/replikativ/replikativ) to build authenticated p2p networks.

## Installation

Add to your dependencies:

[![Clojars Project](http://clojars.org/io.replikativ/kabel-auth/latest-version.svg)](http://clojars.org/io.replikativ/kabel-auth)

```clojure
;; deps.edn
{:deps {io.replikativ/kabel-auth {:mvn/version "LATEST"}}}
```

## JWT Authentication

Validate JWT tokens on WebSocket upgrade using the authenticated http-kit handler:

### HS256 (Shared Secret)

```clojure
(require '[kabel-auth.http-kit :as auth-hk]
         '[kabel-auth.jwt :as jwt]
         '[superv.async :refer [S]])

(def validate-request!
  (jwt/build-bearer-validator {:alg :HS256
                               :secret "your-secret-key"
                               :required-claims {:iss "your-issuer" :aud "your-audience"}}))

(def handler
  (auth-hk/create-authenticated-http-kit-handler! S "ws://localhost:8080/ws" :peer-id validate-request!))
```

### RS256 (Public Key)

```clojure
(def validate-rs256!
  (jwt/build-bearer-validator {:alg :RS256
                               :public-key "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}))

(def handler
  (auth-hk/create-authenticated-http-kit-handler! S "ws://localhost:8080/ws" :peer-id validate-rs256!))
```

Messages received on the input channel will include `:kabel/principal` when authentication succeeds.

## Password Hashing

Secure password hashing via bcrypt (buddy-hashers):

```clojure
(require '[kabel-auth.password :as password])

;; Hash a password
(def hashed (password/hash-password "user-password"))

;; Verify a password
(password/verify-password "user-password" hashed) ;; => true
```

## Session Middleware

Attach identity to inbound messages and strip local metadata from outbound:

```clojure
(require '[kabel-auth.session :as session]
         '[superv.async :refer [S]])

(defn session-fn [S peer msg]
  (when-let [u (:user msg)]
    {:kabel/principal {:user u}}))

(def wrapped [S peer-ch]
  (session/session-middleware session-fn [S peer-ch]))

;; Outbound messages will have :kabel/* keys removed automatically
```

## HTTP Routes

Reitit-based HTTP routes for auth endpoints:

```clojure
(require '[kabel-auth.routes :as routes])

;; Create auth routes with your store and config
(def auth-routes (routes/auth-routes store config))

;; Mount in your Reitit router
```

## Pluggable Storage

Protocol-based storage with a memory implementation included:

```clojure
(require '[kabel-auth.store.protocol :as store-proto]
         '[kabel-auth.store.memory :as memory-store])

;; Create an in-memory store
(def store (memory-store/create-memory-store))

;; Implement the protocol for your own storage backend
```

## Passwordless Authentication

The original passwordless flow for email/SMS-based authentication:

> Instead of asking users for a password when they try to log in, just ask them for their username (or email or mobile phone number). Create a temporary authorization code on the backend and store it in your database. Send the user an email or SMS with a link that contains the code. The user clicks the link which opens your app and sends the authorization code to your backend. Verify that the code is valid and exchange it for a long-lived token.

```clojure
(require '[kabel-auth.core :refer [auth inbox-auth register-external-token external-tokens]]
         '[postal.core :refer [send-message]]
         '[superv.async :refer [S]])

(auth (atom #{"trusted-peer.com" "localhost" "127.0.0.1"})
      receiver-token-store ;; konserve store for receiver tokens
      sender-token-store   ;; konserve store for sender tokens
      ;; decide which messages need protection
      (fn [{:keys [type]}] (or ({:state-changing-msg-type :auth} type)
                               :unrelated))
      ;; notification when authentication is needed
      (fn [protocol user] (alert! "Check channel " protocol " for " user))
      ;; send authentication link
      (fn [{:keys [protocol token user]}]
        (let [ext-tok (register-external-token token)]
          (send-message {:host "smtp.your-host.com"}
                        {:from "no-reply@your-host.com"
                         :to user
                         :subject "Please authenticate"
                         :body (str "Visit http://your-end-point/auth/" ext-tok)})))
  [S peer [in out]])
```

Provide an endpoint for authentication:

```clojure
(routes
  (GET "/auth/:token" [token]
    (put! inbox-auth {:token (@external-tokens (java.util.UUID/fromString token))})))
```

A full example using an early prototype of kabel-auth can be found in [topiq](https://github.com/whilo/topiq/blob/master/src/topiq/core.cljs).

## Build

```bash
# Run tests
clj -M:test

# Check code formatting
clj -M:format

# Auto-fix formatting
clj -M:ffix

# Build JAR
clj -T:build jar

# Deploy to Clojars
clj -T:build deploy
```

## Development

For local development against a sibling kabel checkout:

```bash
clj -M:dev:test
```

The `:dev` alias overrides kabel with `{:local/root "../kabel"}`.

## License

Copyright © 2016-2025 Christian Weilbach

Distributed under the Eclipse Public License either version 1.0 or (at your option) any later version.
