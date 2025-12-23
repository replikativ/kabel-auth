(ns kabel-auth.core-test
  (:require [clojure.test :refer :all]
            [kabel-auth.core :refer [inbox-auth auth]]
            [konserve.core :as k]
            [konserve.memory :refer [new-mem-store]]
            [superv.async :refer [S <? <?? go-try go-loop-try alt?]]
            [clojure.core.async :as async
             :refer [<! >! >!! <!! timeout chan alt! go put!
                     go-loop pub sub unsub close!]]))

;; dummy authentication loop for testing
(deftest token-auth
  (testing "Testing token authentication exchange for receiver."
    (let [mapping {:pub/downstream :auth}
          dispatch-fn (fn [m] (or (mapping (:type m)) :unrelated))
          auth-fn (fn [protocol user] (println "Check channel " protocol " for " user))
          in (chan)
          out (chan)
          trusted-connections (atom #{})
          receiver-token-store (<?? S (new-mem-store))
          sender-token-store (<?? S (new-mem-store))
          [_ _ [new-in new-out]] (auth trusted-connections
                                       receiver-token-store
                                       sender-token-store
                                       dispatch-fn
                                       auth-fn
                                       #(put! inbox-auth %) ;; loop
                                       [S nil [in out]])]
      #_(go-loop [i (<! new-in)]
          (debug "PASSED:" i)
          (recur (<! new-in)))
      #_(go-loop [o (<! out)]
          (debug "SENDING:" o)
          (recur (<! out)))
      (>!! in {:type :pub/downstream
               :downstream {:foo :bar}
               :user "loop:eve@topiq.es"
               :crdt-id 1
               :connection "localhost"
               :sender 4441})
      (is (= (<?? S out)
             {:type :kabel-auth.core/auth-request,
              :user "eve@topiq.es",
              :protocol :loop}))
      (let [m (<?? S out)]
        (is (= (:type m) :kabel-auth.core/auth-token))
        (is (contains? m :token)))
      (is (= (<?? S new-in)
             {:type :pub/downstream,
              :downstream {:foo :bar},
              :user "loop:eve@topiq.es",
              :crdt-id 1,
              :connection "localhost"
              :sender 4441}))
      (>!! in {:type :pub/downstream ;; will pass through with session
               :downstream {:foo :bars}
               :user "loop:eve@topiq.es"
               :crdt-id 1
               :connection "localhost"
               :sender 4441})
      (is (= (<?? S new-in)
             {:type :pub/downstream,
              :downstream {:foo :bars},
              :user "loop:eve@topiq.es",
              :crdt-id 1,
              :connection "localhost"
              :sender 4441})))))
