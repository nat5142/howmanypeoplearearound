import os
import json
try:
    # Python3
    from urllib.request import urlopen
except ImportError:
    # Python2
    from urllib2 import urlopen


def collect_oui(oui_filename='oui.json', force_download=False):
    if not ((os.path.isfile(oui_filename) or os.access(oui_filename, os.R_OK)) or force_download):
        oui_text = download_oui()
        oui_dict = write_oui_to_json(oui_filename, oui_text)
    else:
        with open(oui_filename, 'r') as jfile:
            oui_dict = json.loads(jfile.read())

    return oui_dict


def download_oui():
    """Downloads plaintext file consisting of all Organizationally Unique Identifiers registered by
    the Institute of Electrical and Electronics Engineers Registration Authority."""
    oui_text = urlopen('http://standards-oui.ieee.org/oui/oui.txt', timeout=10).read().decode('utf-8')

    return oui_text


def write_oui_to_json(oui_filename, oui_text):
    oui_dict = {}
    for line in oui_text.split('\n'):
        if '(hex)' in line:
            data = line.split('(hex)')
            key = data[0].replace('-', ':').lower().strip()
            company = data[1].strip()
            oui_dict[key] = company

    with open(oui_filename, 'w') as jfile:
        jfile.write(json.dumps(oui_dict))

    return oui_dict
