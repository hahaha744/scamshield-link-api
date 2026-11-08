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
                mock_res.json.return_value = {
                    "matches": [{"threat": {"url": "https://threat.com"}, "cacheDuration": "300s"}]
                }

                def slow_post(*args, **kwargs):
                    time.sleep(0.1)
                    return mock_res

                # Dispatches two simultaneous requests for different URLs
                urlA = "https://url-a.com"
                urlB = "https://url-b.com"

                with patch("requests.post", side_effect=slow_post) as mock_post:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        fA = executor.submit(link_server.check_google_safe_browsing, urlA)
                        fB = executor.submit(link_server.check_google_safe_browsing, urlB)
                        resA = fA.result()
                        resB = fB.result()

                    # Exactly ONE request succeeded, and ONE was blocked at capacity reservation
                    statuses = [resA, resB]
                    self.assertIn("confirmed_threat", statuses)
                    self.assertIn("unavailable", statuses)

                    # Exactly ONE network POST call was executed! Zero uncached Google requests!
                    self.assertEqual(mock_post.call_count, 1)

                    # Exactly ONE entry in cache (1/1 slot filled)
                    with link_server._gsb_cache_lock:
                        self.assertEqual(len(link_server._gsb_cache), 1)
                        self.assertEqual(len(link_server._gsb_reserved), 0)

    # 2. Reservation cleanup after network failure / timeout / malformed JSON
    def test_reservation_cleanup_on_failure(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            # Network Timeout
            with patch("requests.post", side_effect=requests.RequestException("Timeout")):
                status = link_server.check_google_safe_browsing("https://fail-url.com")
                self.assertEqual(status, "unavailable")
                with link_server._gsb_cache_lock:
                    self.assertNotIn("https://fail-url.com", link_server._gsb_reserved)

            # HTTP 500
            mock_res = MagicMock()
            mock_res.status_code = 500
            with patch("requests.post", return_value=mock_res):
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
                mock_res.json.return_value = {
                    "matches": [{"threat": {"url": "https://threat.com"}, "cacheDuration": "300s"}]
                }

                with patch("requests.post", return_value=mock_res):
                    link_server.check_google_safe_browsing("https://url1.com")
                    link_server.check_google_safe_browsing("https://url2.com")

                    with link_server._gsb_cache_lock:
                        self.assertIn("https://url1.com", link_server._gsb_cache)
                        self.assertIn("https://url2.com", link_server._gsb_cache)

                    # 3rd lookup when at capacity (2/2 unexpired) -> must NOT evict url1 or url2!
                    # And must return unavailable without calling requests.post!
                    with patch("requests.post") as mock_post_blocked:
                        status3 = link_server.check_google_safe_browsing("https://url3.com")
                        self.assertEqual(status3, "unavailable")
                        self.assertEqual(mock_post_blocked.call_count, 0)

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
                "matches": [{"threat": {"url": "https://shared-target.com"}, "threatType": "MALWARE"}],
                "minimumWaitDuration": "300s"
            }

            def slow_post(*args, **kwargs):
                time.sleep(0.1)
                return mock_res

            url = "https://shared-target.com"
            with patch("requests.post", side_effect=slow_post) as mock_post:
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [executor.submit(link_server.check_google_safe_browsing, url) for _ in range(5)]
                    results = [f.result() for f in concurrent.futures.as_completed(futures)]

                self.assertTrue(all(r == "confirmed_threat" for r in results))
                self.assertEqual(mock_post.call_count, 1)  # Coalesced into 1 network call!

            with link_server._in_flight_lock:
                self.assertEqual(len(link_server._in_flight_requests), 0)

    # 4b. Timed-out coalesced waiter receives unavailable
    def test_coalesced_waiter_timeout_returns_unavailable(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            in_flight = link_server.InFlightRequest()
            url = "https://timeout-test.com"

            with link_server._in_flight_lock:
                link_server._in_flight_requests[url] = in_flight

            # Patch event.wait on in_flight to return False (simulating timeout)
            with patch.object(in_flight.event, "wait", return_value=False):
                res = link_server.check_google_safe_browsing(url)
                self.assertEqual(res, "unavailable")

            with link_server._in_flight_lock:
                link_server._in_flight_requests.pop(url, None)

    # 4c. Concurrent requests for same URL do not reserve multiple cache slots
    def test_concurrent_same_url_does_not_reserve_multiple_slots(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            url = "https://same-url-test.com"
            link_server.reserve_cache_capacity(url)
            with link_server._gsb_cache_lock:
                self.assertIn(url, link_server._gsb_reserved)
                initial_reserved_count = len(link_server._gsb_reserved)

            # Secondary reservation for same URL
            res2 = link_server.reserve_cache_capacity(url)
            self.assertTrue(res2)
            with link_server._gsb_cache_lock:
                self.assertEqual(len(link_server._gsb_reserved), initial_reserved_count)

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

    # 6. Response Handling Tests
    def test_gsb_http_403_returns_unavailable(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            mock_res = MagicMock()
            mock_res.status_code = 403
            with patch("requests.post", return_value=mock_res):
                status = link_server.check_google_safe_browsing("https://test.com")
                self.assertEqual(status, "unavailable")

    def test_gsb_http_400_returns_unavailable(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            mock_res = MagicMock()
            mock_res.status_code = 400
            with patch("requests.post", return_value=mock_res):
                status = link_server.check_google_safe_browsing("https://test.com")
                self.assertEqual(status, "unavailable")

    def test_gsb_http_200_empty_dict_returns_no_match(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = {}
            with patch("requests.post", return_value=mock_res):
                status = link_server.check_google_safe_browsing("https://test.com")
                self.assertEqual(status, "no_match")
                with link_server._gsb_cache_lock:
                    self.assertNotIn("https://test.com", link_server._gsb_cache)

    def test_gsb_http_200_empty_matches_array_returns_no_match_without_cache(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = {"matches": []}
            with patch("requests.post", return_value=mock_res):
                status = link_server.check_google_safe_browsing("https://test.com")
                self.assertEqual(status, "no_match")
                with link_server._gsb_cache_lock:
                    self.assertNotIn("https://test.com", link_server._gsb_cache)

    def test_gsb_http_200_matches_with_cacheduration(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = {
                "matches": [{"threat": {"url": "https://threat.com"}, "cacheDuration": "300s"}]
            }
            with patch("requests.post", return_value=mock_res):
                status = link_server.check_google_safe_browsing("https://threat.com")
                self.assertEqual(status, "confirmed_threat")
                with link_server._gsb_cache_lock:
                    self.assertIn("https://threat.com", link_server._gsb_cache)

    def test_gsb_multiple_matches_uses_shortest_cacheduration(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = {
                "matches": [
                    {"threat": {"url": "https://threat.com"}, "cacheDuration": "600s"},
                    {"threat": {"url": "https://threat.com"}, "cacheDuration": "120s"},
                    {"threat": {"url": "https://threat.com"}, "cacheDuration": "300s"}
                ]
            }
            with patch("requests.post", return_value=mock_res):
                now_before = time.monotonic()
                status = link_server.check_google_safe_browsing("https://threat.com")
                self.assertEqual(status, "confirmed_threat")
                with link_server._gsb_cache_lock:
                    self.assertIn("https://threat.com", link_server._gsb_cache)
                    cached_val, expire_time = link_server._gsb_cache["https://threat.com"]
                    self.assertEqual(cached_val, "confirmed_threat")
                    self.assertAlmostEqual(expire_time - now_before, 120.0, delta=2.0)

    def test_gsb_http_200_matches_without_cacheduration(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = {
                "matches": [{"threat": {"url": "https://threat.com"}}]
            }
            with patch("requests.post", return_value=mock_res):
                status = link_server.check_google_safe_browsing("https://threat.com")
                self.assertEqual(status, "confirmed_threat")
                with link_server._gsb_cache_lock:
                    self.assertNotIn("https://threat.com", link_server._gsb_cache)

    def test_cache_insertion_failure_preserves_confirmed_threat(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            with patch.object(link_server, "convert_reservation_to_cache", return_value=False):
                mock_res = MagicMock()
                mock_res.status_code = 200
                mock_res.json.return_value = {
                    "matches": [{"threat": {"url": "https://threat.com"}, "cacheDuration": "300s"}]
                }
                with patch("requests.post", return_value=mock_res):
                    status = link_server.check_google_safe_browsing("https://threat.com")
                    self.assertEqual(status, "confirmed_threat")

    def test_gsb_malformed_json_returns_unavailable(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.side_effect = Exception("Malformed JSON")
            with patch("requests.post", return_value=mock_res):
                status = link_server.check_google_safe_browsing("https://test.com")
                self.assertEqual(status, "unavailable")

    def test_gsb_invalid_match_item_returns_unavailable(self):
        with patch.dict(os.environ, {"GSB_API_KEY": "test_key"}):
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = {
                "matches": ["invalid_string_instead_of_dict"]
            }
            with patch("requests.post", return_value=mock_res):
                status = link_server.check_google_safe_browsing("https://test.com")
                self.assertEqual(status, "unavailable")

    # 7. Android Response Contract Compatibility
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
