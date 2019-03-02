import subprocess

from howmanypeoplearearound.functions import which
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

    def __init__(self, adapter='', scantime=10, nearby=False, allmacaddresses=False, port=8001,
                 targetmacs=False, dumpfile='/tmp/tshark-tmp'):
        self.adapter = adapter
        self.scantime = scantime
        self.nearby = nearby
        self.allmacaddresses = allmacaddresses
        self.port = port
        self.targetmacs = targetmacs  # TODO: Make this attr the result of SQLAlchemy query?
        self.dumpfile = dumpfile

    def scan_network(self):
        tshark = which('tshark')

        # Scan with tshark
        command = [tshark, '-I', '-i', str(self.adapter), '-a', 'duration:{}'.format(self.scantime), '-w', self.dumpfile]
        stdout, stderr = self.run_subprocess(command)

        # Read tshark output
        command = [
            tshark, '-r',
            self.dumpfile, '-T',
            'fields', '-e',
            'wlan.sa', '-e',
            'wlan.bssid', '-e',
            'radiotap.dbm_antsignal'
        ]

        output, stderr = self.run_subprocess(command)

        return ScanResult(output)

    def run_subprocess(self, command):
        stdout, stderr = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

        if stderr and not self.validate_output(stderr):
            raise Exception(stderr.decode('utf-8'))

        return stdout, stderr

    @staticmethod
    def validate_output(stderr):
        """Method that ensures content was returned from the network scan. The `run_subprocess` method will
        return a message as stderr that will include a number of bytes that the tshark scan yields. If that
        number is greater than 0, the output process should proceed."""
        item = stderr.decode('utf-8').strip('\n').split('\n')[-1].split(' ')[0]
        try:
            return int(item) > 0
        except ValueError:
            return False
