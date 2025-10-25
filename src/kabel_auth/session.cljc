(ns kabel-auth.session
	"Session and kabel metadata helpers and middleware.

	- strip-kabel-meta: remove any top-level :kabel/* keys from messages so that
		local-only metadata never leaves the process.
	- session-middleware: attach optional session/principal info to inbound
		messages and ensure outbound messages are sanitized.
	"
				(:require #?(:clj  [clojure.core.async :as async :refer [chan close! >! <! go-loop]]
									 :cljs [clojure.core.async :as async :refer [chan close! >! <!]]))
			#?(:cljs (:require-macros [clojure.core.async :refer [go-loop]])))

(defn- kabel-meta-key? [k]
	(and (keyword? k) (= "kabel" (namespace k))))

(defn strip-kabel-meta
	"Remove top-level :kabel/* keys from a message map."
	[m]
	(cond
		(map? m) (into {} (remove (fn [[k _]] (kabel-meta-key? k)) m))
		:else m))

(defn session-middleware
	"Middleware wrapper that:
	- Enriches inbound messages by merging the map returned by (session-fn S peer msg)
		if provided (e.g., {:kabel/principal {...}} or {:kabel/session {...}}).
	- Strips :kabel/* keys from outbound messages before they are passed downstream.

	Usage: (session-middleware [S peer [in out]]) or with custom session-fn.
	Returns the usual [S peer [in' out']].
	"
	([ctx]
	 (session-middleware (constantly nil) ctx))
	([session-fn [S peer [in out]]]
	 (let [in'  (chan)
        out' (chan)]
    ;; inbound: attach session/principal if provided
    (go-loop [i (<! in)]
      (if i
        (let [extra (try (session-fn S peer i)
                         (catch #?(:clj Exception :cljs :default) _ nil))
              i'    (if (map? extra) (merge i extra) i)]
          (>! in' i')
          (recur (<! in)))
        (close! in')))
    ;; outbound: remove any :kabel/* keys
    (go-loop [o (<! out')]
      (if o
        (do (>! out (strip-kabel-meta o))
            (recur (<! out')))
        (close! out)))
    [S peer [in' out']]))
	)
