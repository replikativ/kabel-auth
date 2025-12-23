(ns kabel-auth.http-kit
  "Authenticated http-kit handler that enriches inbound Kabel messages with
	:kabel/principal based on the initial Ring request (e.g., Authorization header
	or cookies). Falls back gracefully when no principal is available."
  (:require [kabel.platform-log :refer [debug info warn error]]
            [kabel.binary :refer [from-binary to-binary]]
            [superv.async :refer [<? go-try -error go-loop-super]]
            [clojure.core.async :as async
             :refer [<! >! timeout chan alt! put! close! buffer]]
            [org.httpkit.server :refer :all]))

(defn create-authenticated-http-kit-handler!
  "Creates an http-kit WebSocket handler that attaches a validated principal to
	every inbound message as :kabel/principal. The principal is derived once from
	the initial Ring request using the provided `validate-request-fn`, which
	should return a map (e.g., {:sub " user " ...}) or nil if unauthenticated.

	Returns a map compatible with kabel's server peer: {:new-conns :channel-hub
	:start-fn :url :handler}.

	Notes:
	- This mirrors kabel.http-kit/create-http-kit-handler! while adding principal
		injection. Outbound messages are sent unchanged; downstream middleware like
		kabel-auth.session/session-middleware will strip :kabel/* on outbound.
	- If you want to reject unauthenticated connections up-front, have
		`validate-request-fn` throw; this handler will close the channel immediately.
	"
  ([S url peer-id validate-request-fn]
   (create-authenticated-http-kit-handler! S url peer-id validate-request-fn (atom {}) (atom {})))
  ([S url peer-id validate-request-fn _read-handlers _write-handlers]
   (let [channel-hub (atom {})
         principal-hub (atom {})
         conns (chan)
         handler (fn [request]
                   (let [in-buffer (buffer 1024)
                         in (chan in-buffer)
                         out (chan)]
                     (async/put! conns [in out])
                     (with-channel request channel
                       (let [principal (try
                                         (validate-request-fn request)
                                         (catch Exception e
                                           (warn {:event :auth-validation-error
                                                  :error e})
                                           nil))]
                         (swap! channel-hub assoc channel request)
                         (when principal
                           (swap! principal-hub assoc channel principal))
                         (go-loop-super S [m (<? S out)]
                                        (if m
                                          (do
                                            (if (@channel-hub channel)
                                              (do (debug {:event :sending-msg})
                                                  (if (= (:kabel/serialization m) :string)
                                                    (send! channel (:kabel/payload m))
                                                    (send! channel (to-binary m))))
                                              (warn {:event :dropping-msg-because-of-closed-channel
                                                     :url url :message m}))
                                            (recur (<? S out)))
                                          (close channel)))
                         (on-close channel (fn [status]
                                             (let [e (ex-info "Connection closed!" {:status status})
                                                   host (:remote-addr request)]
                                               (debug {:event :channel-closed
                                                       :host host :status status})
                                               #_(put! (-error S) e))
                                             (swap! channel-hub dissoc channel)
                                             (swap! principal-hub dissoc channel)
                                             (go-try S (while (<! in)))
                                             (close! in)))
                         (on-receive channel (fn [data]
                                               (let [host (:remote-addr request)
                                                     principal (@principal-hub channel)]
                                                 (try
                                                   (debug {:event :received-byte-message})
                                                   (when (> (count in-buffer) 100)
                                                     (close channel)
                                                     (throw (ex-info
                                                             (str "incoming buffer for " (:remote-addr request)
                                                                  " too full:" (count in-buffer))
                                                             {:url url
                                                              :count (count in-buffer)})))
                                                   (if (string? data)
                                                     (async/put! in {:kabel/serialization :string
                                                                     :kabel/payload data
                                                                     :kabel/host host
                                                                     :kabel/principal principal})
                                                     (let [m (from-binary data)
                                                           m' (cond-> m
                                                                (associative? m)
                                                                (assoc :kabel/host host)
                                                                principal
                                                                (assoc :kabel/principal principal))]
                                                       (async/put! in m')))
                                                   (catch Exception e
                                                     (put! (-error S)
                                                           (ex-info "Cannot receive data." {:data data
                                                                                            :host host
                                                                                            :error e}))
                                                     (close channel))))))))))]
     {:new-conns conns
      :channel-hub channel-hub
      :start-fn (fn start-fn [{:keys [handler] :as volatile}]
                  (when-not (:stop-fn handler)
                    (-> volatile
                        (assoc :stop-fn
                               (run-server handler
                                           {:port (->> url
                                                       (re-seq #":(\d+)")
                                                       first
                                                       second
                                                       read-string)
                                            :max-body (* 100 1024 1024)
                                            :max-ws (* 100 1024 1024)})))))
      :url url
      :handler handler})))
