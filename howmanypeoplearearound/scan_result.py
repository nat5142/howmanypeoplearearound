

class ScanResult(object):

    def __init__(self, tshark_output, target_macs=[]):
        self.tshark_output = tshark_output
        self.target_macs = target_macs

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

        return found_macs
