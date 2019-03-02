import unittest
from howmanypeoplearearound.scanner import Scanner


class En0AdapterTest(unittest.TestCase):
    scanner = Scanner('en0')

    def test_single_adapter_scan(self):
        results = self.scanner.scan_network()

        self.assertIs(type(results.data), list)
        self.assertIs(type(results.data[0]), dict)

    def test_looping_adapter_scan(self):
        scan_results = []
        for _ in range(2):
            results = self.scanner.scan_network()

            scan_results.append(results)

        self.assertIs(type(scan_results), list)
        self.assertIs(type(scan_results[0].data), list)
        self.assertIs(type(scan_results[0].data[1]), dict)

    def test_scan_results_against_known_devices(self):
        results = self.scanner.scan_network()

        active_known_devices = results.get_known_devices(['00:AB:00:0A:0B'])

        self.assertEqual(len(active_known_devices), 0)
