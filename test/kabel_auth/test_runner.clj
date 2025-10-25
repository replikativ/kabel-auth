(ns kabel-auth.test-runner
  (:require [clojure.test :as t]
            ;; ensure tests are loaded
            [kabel-auth.core-test]
            [kabel-auth.session-test]
            [kabel-auth.jwt-test]))

(defn -main [& _]
  (let [;; Limit to our project test namespaces only
        summary (t/run-all-tests #"^kabel-auth(\..*)?-test$")]
    (let [fails (+ (or (:fail summary) 0)
                   (or (:error summary) 0))]
      (shutdown-agents)
      (System/exit (if (pos? fails) 1 0)))))
