#!/usr/bin/env python3

import unittest
import os
import json
import tempfile
from wifipasswords import WifiPasswords


class TestRunner(unittest.TestCase):
    def setUp(self) -> None:
        self.wifipw = WifiPasswords()

    def test_get_passwords_returns_dictionary(self):
        self.assertTrue(type(self.wifipw.get_passwords()) is dict)

    def test_get_passwords_dummy_returns_dictionary(self):
        self.assertTrue(type(self.wifipw.get_passwords_dummy()) is dict)

    def test_get_passwords_data_returns_dictionary(self):
        self.wifipw.get_passwords_dummy()
        self.assertTrue(type(self.wifipw.get_passwords_data()) is dict)

    def test_get_visible_networks_is_string(self):
        self.assertTrue(type(self.wifipw.get_visible_networks()) is str)

    def test_get_visible_networks_is_dictionary(self):
        self.assertTrue(type(self.wifipw.get_visible_networks(True)) is dict)

    def test_get_dns_config_is_string(self):
        self.assertTrue(type(self.wifipw.get_dns_config()) is str)

    def test_get_dns_config_is_dictionary(self):
        self.assertTrue(type(self.wifipw.get_dns_config(True)) is dict)

    def test_save_wpa_supplicant_file_created(self):
        data = self.wifipw.get_passwords_dummy()
        with tempfile.TemporaryDirectory() as temp_dir:
            self.wifipw.save_wpa_supplicant(
                os.path.join(temp_dir, "wpa_supplicant.conf"), data, True, "GB"
            )
            self.assertTrue(os.path.exists(os.path.join(temp_dir, "wpa_supplicant.conf")))

    def test_save_json_file_created(self):
        data = self.wifipw.get_passwords_dummy()
        with tempfile.TemporaryDirectory() as temp_dir:
            self.wifipw.save_json(os.path.join(temp_dir, "networks.json"), data)
            self.assertTrue(os.path.exists(os.path.join(temp_dir, "networks.json")))

    def test_save_json_file_contains_valid_json(self):
        data = self.wifipw.get_passwords_dummy()
        with tempfile.TemporaryDirectory() as temp_dir:
            self.wifipw.save_json(os.path.join(temp_dir, "networks.json"), data)
            with open(os.path.join(temp_dir, "networks.json"), "r") as json_file:
                try:
                    json.load(json_file)
                except Exception as e:
                    self.fail(f"Raised {e} unexpectedly!")

    def test_get_number_visible_networks_returns_int(self):
        self.wifipw.get_visible_networks()
        self.assertTrue(type(self.wifipw.get_number_visible_networks()) is int)

    def test_get_number_interfaces_returns_int(self):
        self.wifipw.get_dns_config()
        self.assertTrue(type(self.wifipw.get_number_interfaces()) is int)

    def test_get_number_profiles_returns_int(self):
        self.wifipw.get_passwords_dummy()
        self.assertTrue(type(self.wifipw.get_number_profiles()) is int)

    def test_get_currently_connected_ssids_returns_list(self):
        self.assertTrue(type(self.wifipw.get_currently_connected_ssids()) is list)

    def test_get_currently_passwords_returns_list(self):
        self.assertTrue(type(self.wifipw.get_currently_connected_passwords()) is list)

    def test_get_known_ssids_returns_list(self):
        self.assertTrue(type(self.wifipw.get_known_ssids()) is list)

    def test_get_single_password_raises_ValueError_for_unknown_network(self):
        with self.assertRaises(ValueError):
            self.wifipw.get_single_password("unknown ssids")


if __name__ == "__main__":
    unittest.main(verbosity=2)
