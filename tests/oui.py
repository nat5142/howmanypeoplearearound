from howmanypeoplearearound.oui import collect_oui, download_oui
import unittest
import json
import os


class OuiDictionaryTest(unittest.TestCase):

    def test_force_download_oui(self):
        oui_dictionary = collect_oui(oui_filename='./oui_test.json', force_download=True)

        with open('./oui_test.json', 'r') as jfile:
            file_content = json.loads(jfile.read())

        self.assertDictEqual(oui_dictionary, file_content)
        os.remove('./oui_test.json')

    def test_download_oui_as_text(self):
        oui_text = download_oui()

        self.assertIsNotNone(oui_text)
