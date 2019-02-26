import os
import subprocess

from howmanypeoplearearound.oui import load_dictionary, download_oui
from howmanypeoplearearound.functions import which, file_to_mac_set
from howmanypeoplearearound.scan_result import ScanResult

try:
    # Python 3
    from urllib.request import urlopen
except ImportError:
    # Python 2
    from urllib2 import urlopen

devices = [
    'Motorola Mobility LLC, a Lenovo Company',
    'GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD',
    'Huawei Symantec Technologies Co.,Ltd.',
    'Microsoft',
    'HTC Corporation',
    'Samsung Electronics Co.,Ltd',
    'SAMSUNG ELECTRO-MECHANICS(THAILAND)',
    'BlackBerry RTS',
    'LG ELECTRONICS INC',
    'Apple, Inc.',
    'LG Electronics',
    'OnePlus Tech (Shenzhen) Ltd',
    'Xiaomi Communications Co Ltd',
    'LG Electronics (Mobile Communications)'
]


class Scanner(object):

    def __init__(self, adapter='', scantime=10, dictionary='oui.txt', nearby=False, allmacaddresses=False, port=8001,
                 targetmacs=False):
        self.adapter = adapter
        self.scantime = scantime
        self.dictionary = dictionary
        self.nearby = nearby
        self.allmacaddresses = allmacaddresses
        self.port = port
        self.targetmacs = targetmacs  # TODO: Make this attr the result of SQLAlchemy query

        self.oui = self._get_oui(dictionary)

    def main(self):
        scan_results = self.scan_network()

        if not scan_results:
            return []

        for key, value in scan_results.items():
            scan_results[key] = float(sum(value)) / float(len(value))

        # TODO: Rip this out when you're setting self.target_macs with a SQLAlchemy query
        target_mac_set = file_to_mac_set(self.targetmacs) if self.targetmacs else set()

        # Find target MAC address in found_macs
        if target_mac_set:
            for mac in scan_results:
                if mac in target_mac_set:
                    # TODO: Don't forget the print statements
                    print("Found MAC address: %s" % mac)
                    print("rssi: %s" % str(scan_results[mac]))

        unique_devices = []

        for mac in scan_results:
            oui_id = 'Not in OUI'
            if mac[:8] in self.oui:
                oui_id = self.oui[mac[:8]]
            if self.allmacaddresses or oui_id in devices:
                if not self.nearby or (self.nearby and scan_results[mac] > -70):
                    unique_devices.append({'company': oui_id, 'rssi': scan_results[mac], 'mac': mac})

        return unique_devices

    def scan_network(self):
        tshark = which('tshark')

        dump_file = '/tmp/tshark-temp'

        # Scan with tshark
        command = [tshark, '-I', '-i', str(self.adapter), '-a', 'duration:{}'.format(self.scantime), '-w', dump_file]
        run_tshark = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = run_tshark.communicate()

        # Read tshark output
        command = [
            tshark, '-r',
            dump_file, '-T',
            'fields', '-e',
            'wlan.sa', '-e',
            'wlan.bssid', '-e',
            'radiotap.dbm_antsignal'
        ]

        run_tshark = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, _ = run_tshark.communicate()

        return ScanResult(output).process()

    @staticmethod
    def _get_oui(dictionary):
        if (not os.path.isfile(dictionary)) or (not os.access(dictionary, os.R_OK)):
            download_oui(dictionary)

        return load_dictionary(dictionary)
