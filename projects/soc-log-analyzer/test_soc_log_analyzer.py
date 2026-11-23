import unittest
from soc_log_analyzer import analyze

class AnalyzerTests(unittest.TestCase):
    def test_repeated_failures_and_success(self):
        events = [{"timestamp": str(i), "username": "admin", "source_ip": "192.0.2.1",
                   "event": "login", "result": "failed"} for i in range(5)]
        events.append({"timestamp": "6", "username": "admin", "source_ip": "192.0.2.1",
                       "event": "login", "result": "success"})
        alerts = analyze(events, threshold=5)
        self.assertEqual(alerts[0]["type"], "SUCCESS_AFTER_REPEATED_FAILURES")
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_below_threshold_is_not_alerted(self):
        events = [{"timestamp": str(i), "username": "user", "source_ip": "192.0.2.2",
                   "event": "login", "result": "failed"} for i in range(2)]
        self.assertEqual(analyze(events, threshold=5), [])

if __name__ == "__main__":
    unittest.main()
