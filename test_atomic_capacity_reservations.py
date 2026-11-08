import os
import sys
import time
import unittest
import concurrent.futures
from unittest.mock import patch, MagicMock
import requests
from fastapi.testclient import TestClient
import link_server

class AtomicCapacityReservationsTestCase(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(link_server.app)
        link_server.clear_gsb_cache_for_testing()

    def tearDown(self):
        link_server.clear_gsb_cache_for_testing()

    # 1. One free slot with two simultaneous requests for different URLs
    def test_one_free_slot_simultaneous_requests_atomic_admission(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            with patch.object(link_server, "MAX_CACHE_ENTRIES", 1):
                mock_res = MagicMock()
                mock_res.status_code = 200
                mock_res.json.return_value = {"threats": [], "cacheDuration": "300s"}

                def slow_get(*args, **kwargs):
                    time.sleep(0.1)
                    return mock_res

                # Dispatches two simultaneous requests for different URLs
                urlA = "https://url-a.com"
                urlB = "https://url-b.com"

                with patch("requests.get", side_effect=slow_get) as mock_get:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        fA = executor.submit(link_server.check_google_safe_browsing, urlA)
                        fB = executor.submit(link_server.check_google_safe_browsing, urlB)
                        resA = fA.result()
                        resB = fB.result()

                    # Exactly ONE request succeeded, and ONE was blocked at capacity reservation
                    statuses = [resA, resB]
                    self.assertIn("no_match", statuses)
                    self.assertIn("unavailable", statuses)

                    # Exactly ONE network GET call was executed! Zero uncached Google requests!
                    self.assertEqual(mock_get.call_count, 1)

                    # Exactly ONE entry in cache (1/1 slot filled)
                    with link_server._gsb_cache_lock:
                        self.assertEqual(len(link_server._gsb_cache), 1)
                        self.assertEqual(len(link_server._gsb_reserved), 0)

    # 2. Reservation cleanup after network failure / timeout / malformed JSON
    def test_reservation_cleanup_on_failure(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            # Network Timeout
            with patch("requests.get", side_effect=requests.RequestException("Timeout")):
                status = link_server.check_google_safe_browsing("https://fail-url.com")
                self.assertEqual(status, "unavailable")
                with link_server._gsb_cache_lock:
                    self.assertNotIn("https://fail-url.com", link_server._gsb_reserved)

            # HTTP 500
            mock_res = MagicMock()
            mock_res.status_code = 500
            with patch("requests.get", return_value=mock_res):
                status2 = link_server.check_google_safe_browsing("https://fail-url-2.com")
                self.assertEqual(status2, "unavailable")
                with link_server._gsb_cache_lock:
                    self.assertNotIn("https://fail-url-2.com", link_server._gsb_reserved)

    # 3. Full cache does not evict unexpired entries
    def test_full_cache_never_evicts_unexpired_entries(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            with patch.object(link_server, "MAX_CACHE_ENTRIES", 2):
                mock_res = MagicMock()
                mock_res.status_code = 200
                mock_res.json.return_value = {"threats": [], "cacheDuration": "300s"}

                with patch("requests.get", return_value=mock_res):
                    link_server.check_google_safe_browsing("https://url1.com")
                    link_server.check_google_safe_browsing("https://url2.com")

                    with link_server._gsb_cache_lock:
                        self.assertIn("https://url1.com", link_server._gsb_cache)
                        self.assertIn("https://url2.com", link_server._gsb_cache)

                    # 3rd lookup when at capacity (2/2 unexpired) -> must NOT evict url1 or url2!
                    # And must return unavailable without calling requests.get!
                    with patch("requests.get") as mock_get_blocked:
                        status3 = link_server.check_google_safe_browsing("https://url3.com")
                        self.assertEqual(status3, "unavailable")
                        self.assertEqual(mock_get_blocked.call_count, 0)

                    # Verify url1 and url2 are still present and unevicted!
                    with link_server._gsb_cache_lock:
                        self.assertIn("https://url1.com", link_server._gsb_cache)
                        self.assertIn("https://url2.com", link_server._gsb_cache)
                        self.assertNotIn("https://url3.com", link_server._gsb_cache)

    # 4. Concurrent waiters receive the result belonging to their shared request
    def test_coalesced_waiters_receive_shared_result(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = {
                "threats": [{"url": "https://shared-target.com", "threatTypes": ["MALWARE"]}],
                "cacheDuration": "300s"
            }

            def slow_get(*args, **kwargs):
                time.sleep(0.1)
                return mock_res

            url = "https://shared-target.com"
            with patch("requests.get", side_effect=slow_get) as mock_get:
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [executor.submit(link_server.check_google_safe_browsing, url) for _ in range(5)]
                    results = [f.result() for f in concurrent.futures.as_completed(futures)]

                self.assertTrue(all(r == "confirmed_threat" for r in results))
                self.assertEqual(mock_get.call_count, 1)  # Coalesced into 1 network call!

            with link_server._in_flight_lock:
                self.assertEqual(len(link_server._in_flight_requests), 0)

    # 5. Strict cacheDuration parsing (Valid fractional vs Malformed/Zero/Negative)
    def test_strict_cacheduration_parsing(self):
        self.assertEqual(link_server.parse_cache_duration("300s"), 300.0)
        self.assertEqual(link_server.parse_cache_duration("300.5s"), 300.5)
        self.assertEqual(link_server.parse_cache_duration("0.1s"), 0.1)

        self.assertIsNone(link_server.parse_cache_duration("300ss"))
        self.assertIsNone(link_server.parse_cache_duration("300seconds"))
        self.assertIsNone(link_server.parse_cache_duration("invalid"))
        self.assertIsNone(link_server.parse_cache_duration("0s"))
        self.assertIsNone(link_server.parse_cache_duration("0.0s"))
        self.assertIsNone(link_server.parse_cache_duration("-10s"))
        self.assertIsNone(link_server.parse_cache_duration(None))

    # 6. Android Response Contract Compatibility
    def test_android_response_contract(self):
        res = self.client.post("/scan_link", json={"url": "https://google.com"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("score", data)
        self.assertIn("verdict", data)
        self.assertIn("signals", data)
        self.assertIn("processing_time_ms", data)
        self.assertIn("threat_intel_status", data)

if __name__ == '__main__':
    unittest.main()
