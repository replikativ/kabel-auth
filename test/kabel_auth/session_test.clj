(ns kabel-auth.session-test
  (:require [clojure.test :refer [deftest is]]
            [clojure.core.async :as async :refer [chan <!! close! put!]]
            [kabel-auth.session :as session]))

(deftest strip-kabel-meta-basic
  (is (= {:a 1}
         (session/strip-kabel-meta {:a 1 :kabel/session {:sub "u"} :kabel/host "h"})))
  (is (= {:type :x}
         (session/strip-kabel-meta {:type :x :kabel/internal true})))
  (is (= 42 (session/strip-kabel-meta 42))))

(deftest session-middleware-outbound-strips
  ;; Build a tiny pipeline and ensure :kabel/* keys do not flow to sink
  (let [S (atom {})
        in (chan)
        out (chan)
        [S' _ [in' out']] (session/session-middleware [S (atom {}) [in out]])]
    (is (identical? S S'))
    ;; Send an outbound message (upstream -> out') that includes kabel meta
    (put! out' {:type :foo :payload 1 :kabel/session {:sub "u"}})
    (is (= {:type :foo :payload 1}
           (<!! out)))
    (close! out')
    (close! in')))