import os
import sys
import platform
import subprocess
import json
import threading
import time

import netifaces

from howmanypeoplearearound.oui import load_dictionary, download_oui
from howmanypeoplearearound.analysis import analyze_file
from howmanypeoplearearound.functions import which, show_timer, file_to_mac_set


if os.name != 'nt':
    from pick import pick
    import curses


class Scanner(object):

    def __init__(self, adapter='', scantime=10, verbose=False, dictionary='oui.txt', number=False, nearby=False,
                 jsonprint=False, out='', allmacaddresses=False, manufacturers='', nocorrection=True,
                 analyze=False, port=8001, sort=False, targetmacs=False, pcap=None):
        self.adapter = adapter
        self.scantime = scantime
        self.verbose = verbose
        self.dictionary = dictionary
        self.number = number
        self.nearby = nearby
        self.jsonprint = jsonprint
        self.out = out
        self.allmacaddresses = allmacaddresses
        self.manufacturers = manufacturers
        self.nocorrection = nocorrection
        self.analyze = analyze
        self.port = port
        self.sort = sort
        self.targetmacs = targetmacs
        self.pcap = pcap

    def main(self):
        if self.analyze:
            analyze_file(self.analyze, self.port)
            return
        else:
            return self.scan()

    def scan(self):
        if (not os.path.isfile(self.dictionary)) or (not os.access(self.dictionary, os.R_OK)):
            download_oui(self.dictionary)

        oui = load_dictionary(self.dictionary)

        if not oui:
            print('couldn\'t load [%s]' % self.dictionary)
            sys.exit(1)

        try:
            tshark = which("tshark")
        except:
            if platform.system() != 'Darwin':
                raise OSError('tshark not found, install using\n\napt-get install tshark\n')
            else:
                raise OSError('wireshark not found, install using: \n\tbrew install wireshark\n'
                              'you may also need to execute: \n\tbrew cask install wireshark-chmodbpf')

        if self.jsonprint:
            number = True
        if self.number:
            verbose = False

        if not self.pcap:
            if not self.adapter:
                if os.name == 'nt':
                    raise OSError('You must specify the adapter with   -a ADAPTER\n'
                                  'Choose from the following: {}'.format(', '.join(netifaces.interfaces())))
                title = 'Please choose the adapter you want to use: '
                try:
                    adapter, index = pick(netifaces.interfaces(), title)
                except curses.error as e:
                    raise OSError('Please check your $TERM settings: {}'.format(e))

            print("Using {} adapter and scanning for {} seconds...".format(self.adapter, self.scantime))

            if not self.number:
                # Start timer
                t1 = threading.Thread(target=show_timer, args=(self.scantime,))
                t1.daemon = True
                t1.start()

            dump_file = '/tmp/tshark-temp'
            # Scan with tshark
            command = [tshark, '-I', '-i', str(self.adapter), '-a', 'duration:{}'.format(self.scantime), '-w', dump_file]

            if self.verbose:
                print(' '.join(command))
            run_tshark = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout, nothing = run_tshark.communicate()

            if not self.number:
                t1.join()

        else:
            dump_file = self.pcap

        # Read tshark output
        command = [
            tshark, '-r',
            dump_file, '-T',
            'fields', '-e',
            'wlan.sa', '-e',
            'wlan.bssid', '-e',
            'radiotap.dbm_antsignal'
        ]
        if self.verbose:
            print(' '.join(command))
        run_tshark = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        output, nothing = run_tshark.communicate()

        targetmacset = set()
        if self.targetmacs:
            targetmacset = file_to_mac_set(self.targetmacs)

        found_macs = {}

        for line in output.decode('utf-8').split('\n'):
            if self.verbose:
                print(line)
            if line.strip() == '':
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
            # TODO: Return no data?
            print('Found no signals, are you sure {} supports monitor mode?'.format(self.adapter))

        for key, value in found_macs.items():
            found_macs[key] = float(sum(value)) / float(len(value))

        # Find target MAC address in found_macs
        if targetmacset:
            for mac in found_macs:
                if mac in targetmacset:
                    print("Found MAC address: %s" % mac)
                    print("rssi: %s" % str(found_macs[mac]))

        if self.manufacturers:
            f = open(self.manufacturers, 'r')
            cellphone = [line.rstrip('\n') for line in f.readlines()]
            f.close()
        else:
            cellphone = [
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
                'LG Electronics (Mobile Communications)']

        cellphone_people = []

        for mac in found_macs:
            oui_id = 'Not in OUI'
            if mac[:8] in oui:
                oui_id = oui[mac[:8]]
            if self.verbose:
                print(mac, oui_id, oui_id in cellphone)
            if self.allmacaddresses or oui_id in cellphone:
                if not self.nearby or (self.nearby and found_macs[mac] > -70):
                    cellphone_people.append(
                        {'company': oui_id, 'rssi': found_macs[mac], 'mac': mac})
        if self.sort:
            cellphone_people.sort(key=lambda x: x['rssi'], reverse=True)
        if self.verbose:
            # TODO: Return this data
            print(json.dumps(cellphone_people, indent=2))

        # US / Canada: https://twitter.com/conradhackett/status/701798230619590656
        percentage_of_people_with_phones = 0.7
        if self.nocorrection:
            percentage_of_people_with_phones = 1
        num_people = int(round(len(cellphone_people) / percentage_of_people_with_phones))

        if self.number and not self.jsonprint:
            # TODO: Return this data
            print(num_people)
        elif self.jsonprint:
            # TODO: Return this data
            pass
        else:
            if num_people == 0:
                print("No one around (not even you!).")
            elif num_people == 1:
                print("No one around, but you.")
            else:
                print("There are about %d people around." % num_people)

        if self.out:
            with open(self.out, 'a') as f:
                data_dump = {'cellphones': cellphone_people, 'time': time.time()}
                f.write(json.dumps(data_dump) + "\n")
        if self.verbose:
            print("Wrote %d records to %s" % (len(cellphone_people), self.out))
        if not self.pcap:
            try:
                os.remove(dump_file)
            except FileNotFoundError:
                pass
        return cellphone_people
