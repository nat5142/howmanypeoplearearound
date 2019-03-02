import os

from howmanypeoplearearound.oui import load_dictionary, download_oui


class ScanResult(object):

    def __init__(self, tshark_output, dictionary='oui.txt'):
        self.tshark_output = tshark_output
        self.oui = self._get_oui(dictionary)
        self.data = self.process()

    def process(self):
        found_macs = {}
        for line in self.tshark_output.decode('utf-8').split('\n'):
            if not line.strip():
                continue
            mac = line.split()[0].strip().split(',')[0]
            dats = line.split()
            if len(dats) == 3:
                if ':' not in dats[0] or len(dats) != 3:
                    continue
                if mac not in found_macs:
                    found_macs[mac] = []
                dats_2_split = dats[2].split(',')
                if len(dats_2_split) > 1:
                    rssi = float(dats_2_split[0]) / 2 + float(dats_2_split[1]) / 2
                else:
                    rssi = float(dats_2_split[0])
                found_macs[mac].append(rssi)

        if not found_macs:
            return []

        unique_devices = []

        for mac, location in found_macs.items():
            found_macs[mac] = float(sum(location)) / float(len(location))
            oui_id = self.oui[mac[:8]] if mac[:8] in self.oui else 'Not in OUI'
            unique_devices.append({'company': oui_id, 'rssi': found_macs[mac], 'mac': mac})

        return unique_devices

    def get_known_devices(self, target_macs):
        """ Check results of network scan for known devices.

        :param target_macs: a list of known MAC Addresses
        :type target_macs: list[str]
        :return: list of known devices in format of self.data
        """
        if not target_macs:
            raise AttributeError('A list of target MAC addresses must be specified for this function')

        return [device for device in self.data if device['mac'] in target_macs]

    @staticmethod
    def _get_oui(dictionary):
        if (not os.path.isfile(dictionary)) or (not os.access(dictionary, os.R_OK)):
            download_oui(dictionary)

        return load_dictionary(dictionary)

