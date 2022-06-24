__copyright__ = "Copyright (C) 2019-2021 Joe Campbell"

# This program is free software: you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY
# without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see < https: // www.gnu.org/licenses/>.

import subprocess
import os
import json
import re
from multiprocessing.dummy import Pool as ThreadPool

from . import __version__


class WifiPasswordsWindows:
    def __init__(self) -> None:
        self.data = {}
        self.number_of_profiles = 0
        self.number_visible_networks = 0
        self.number_of_interfaces = 0
        self.net_template = {"auth": "", "psk": "", "metered": False, "macrandom": "Disabled"}

    @staticmethod
    def _command_runner(shell_commands: list) -> str:
        """
        Split subprocess calls into separate runner module for clarity of code.\n
        Takes the command to execute as a subprocess in the form of a list.\n
        Returns the string output as a utf-8 decoded output.\n
        """
        # need to use pipes for all STDIO on windows if running without interactive console.
        # STARTUPINFO is only present on windows, not linux
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return_data = subprocess.run(
            shell_commands,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            startupinfo=si,
        ).stdout.decode("utf-8")
        return return_data

    def _get_password_subthread(self, network):
        # network is a tuple from the networks dictionary
        # values are (ssid, value dictionary)
        profile_info = self._command_runner(
            ["netsh", "wlan", "show", "profile", network[0], "key=clear"]
        ).split("\r\n")

        for row in profile_info:
            if "Key Content" in row:
                network[1]["psk"] = row.split(": ")[1].strip()
            if "Authentication" in row:
                network[1]["auth"] = row.split(": ")[1].strip()
            if "Cost" in row:
                if "Fixed" in row or "Variable" in row:
                    network[1]["metered"] = True
            if "MAC Randomization" in row:
                network[1]["macrandom"] = row.split(": ")[1].strip()
        return network

    def get_passwords(self) -> dict:
        profiles_list = self._command_runner(
            ["netsh", "wlan", "show", "profiles"],
        ).split("\r\n")

        networks = {
            (row.split(": ")[1]): self.net_template.copy()
            for row in profiles_list
            if "Profile     :" in row
        }

        # from testing 6 seems the optimum thread number
        pool = ThreadPool(6)
        results = dict(pool.imap(self._get_password_subthread, networks.items()))
        pool.close()
        pool.join()
        self.number_of_profiles = len(results)
        self.data = results
        return results

    def get_passwords_dummy(self, delay: float = 0.5, quantity: int = 10) -> dict:
        from time import sleep
        from random import randint, choice
        from secrets import token_urlsafe

        sleep(delay)
        data_wpa = {
            f"network {n}": {
                "auth": "WPA2-Personal",
                "psk": f"{token_urlsafe(randint(8,16))}",
                "metered": choice([True, False]),
                "macrandom": choice(["Disabled", "Enabled", "Daily"]),
            }
            for n in range(1, int(quantity / 2), 1)
        }
        data_open = {
            f"open network {n}": {
                "auth": "Open",
                "psk": "",
                "metered": choice([True, False]),
                "macrandom": choice(["Disabled", "Enabled", "Daily"]),
            }
            for n in range(1, int(quantity / 2), 1)
        }
        data = {**data_wpa, **data_open}
        self.number_of_profiles = len(data)
        self.data = data
        return data

    def get_passwords_data(self) -> dict:
        return self.data

    def get_visible_networks(self, as_dictionary=False) -> str:
        current_networks = self._command_runner(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"]
        )
        if "powered down" in current_networks:
            self.number_visible_networks = 0
        else:
            number = int(
                re.findall(r"\d{1,2}(?= network.* currently visible)", current_networks)[
                    0
                ].strip()
            )
            self.number_visible_networks = number

        if as_dictionary:
            if "powered down" not in current_networks:
                networks_split = re.split("(?<!B)SSID ", current_networks)[1:]
                visible_dict = {}
                for i in networks_split:
                    bssid = []
                    radio = []
                    channel = []
                    rates = []
                    ssid = i.split("\r\n")[0].split(":")[1].strip()
                    if ssid == "":
                        ssid = "Hidden " + i.split("\r\n")[0].split(":")[0].strip()
                    for row in i.split("\r\n"):
                        net_type = ""
                        auth = ""
                        encryption = ""
                        signal = ""
                        if "Network type" in row:
                            net_type = row.split(": ")[1].strip()
                        if "Authentication" in row:
                            auth = row.split(": ")[1].strip()
                        if "Encryption" in row:
                            encryption = row.split(": ")[1].strip()
                        if "BSSID" in row:
                            bssid.append(str(row.split(": ")[1]))
                        if "Signal" in row:
                            signal = row.split(": ")[1].strip()
                        if "Radio type" in row:
                            radio.append(str(row.split(": ")[1]))
                        if "Channel" in row:
                            channel.append(str(row.split(": ")[1]))
                        if "Basic rates" in row or "Other rates" in row:
                            rates.append(str(row.split(":")[1]))

                        visible_dict[ssid] = {
                            "type": net_type,
                            "auth": auth,
                            "encryption": encryption,
                            "bssids": bssid,
                            "signal": signal,
                            "radios": radio,
                            "channel": channel,
                            "rates": rates,
                        }
                return visible_dict
            else:
                return {}
        else:
            return current_networks

    def get_dns_config(self, as_dictionary=False) -> str:
        dns_settings = self._command_runner(["netsh", "interface", "ip", "show", "dns"])

        split_dns_config = dns_settings.strip().split("\r\n\r\n")
        self.number_of_interfaces = len(split_dns_config)

        if as_dictionary:
            dns_dict = {}
            for i in split_dns_config:
                interface = i.split('"')[1].strip()
                if "Statically" in i:
                    type = "Static"
                elif "DHCP" in i:
                    type = "DHCP"
                else:
                    type = "None"
                dns = i.split("\r\n")[1].split(": ")[1].strip()
                suffix = i.split("Register with which suffix:")[1].strip()
                dns_dict[interface] = {"type": type, "DNS": dns, "suffix": suffix}
            return dns_dict
        else:
            return dns_settings

    def save_wpa_supplicant(
        self,
        path: str,
        data: dict = None,
        include_open: bool = True,
        locale: str = "GB",
    ) -> None:
        from datetime import datetime
        from platform import uname

        if data is None:
            data = self.data

        with open(os.path.join(path), "w", newline="\n") as fout:
            fout.write(f"# Generated by wifipasswords {__version__}\n")
            fout.write(f"# Created: {datetime.today()}\n")
            fout.write(f"# Device: {uname().system} {uname().version} - {uname().node}\n")
            fout.write(f"# Detected country code: {locale}\n")
            fout.write("\n")
            fout.write("ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n")
            fout.write("update_config=1\n")
            fout.write(f"country={locale}\n")
            fout.write("\n")
            fout.write("# ######## WPA ########\n")
            for key, n in data.items():
                if n["auth"] == "WPA2-Personal":
                    fout.write("network={\n")
                    fout.write('\tssid="{}"\n'.format(key))
                    fout.write('\tpsk="{}"\n'.format(n["psk"]))
                    fout.write("\tkey_mgmt=WPA-PSK\n")
                    fout.write('\tid_str="{}"\n'.format(key))
                    fout.write("}\n")
            fout.write("\n")
            if include_open:
                fout.write("# ######## OPEN ########\n")
                for key, n in data.items():
                    if n["auth"] == "" or n["auth"] == "Open":
                        fout.write("network={\n")
                        fout.write('\tssid="{}"\n'.format(key))
                        fout.write("\tkey_mgmt=NONE\n")
                        fout.write('\tid_str="{}"\n'.format(key))
                        fout.write("\tpriority=-999\n")
                        fout.write("}\n")

    def save_json(self, path: str, data: dict = None) -> None:
        if data is None:
            data = self.data

        with open(os.path.join(path), "w") as fout:
            json.dump(data, fout)

    def get_number_visible_networks(self) -> int:
        self.get_visible_networks()
        return self.number_visible_networks

    def get_number_interfaces(self) -> int:
        self.get_dns_config()
        return self.number_of_interfaces

    def get_number_profiles(self) -> int:
        if self.number_of_profiles == 0:
            self.get_passwords()
        return self.number_of_profiles

    def get_currently_connected_ssids(self) -> list:
        connected_ssids = []
        current_interfaces = self._command_runner(
            ["netsh", "wlan", "show", "interfaces"]
        ).split("\r\n")

        for line in current_interfaces:
            # space before ssid prevents BSSID being captured
            if " SSID" in line:
                # what if ssid contains : ? could it? would need workaround logic if so
                connected_ssids.append(line.split(":")[1].strip())

        return connected_ssids

    def get_currently_connected_passwords(self) -> list:
        connected_passwords = []
        connected_ssids = self.get_currently_connected_ssids()

        for ssid in connected_ssids:
            key_data = self._command_runner(
                ["netsh", "wlan", "show", "profile", ssid, "key=clear"]
            ).split("\r\n")
            psk = ""
            for row in key_data:
                if "Key Content" in row:
                    psk = row.split(": ")[1].strip()
            connected_passwords.append((ssid, psk))

        return connected_passwords

    def get_known_ssids(self) -> list:
        profiles_list = self._command_runner(
            ["netsh", "wlan", "show", "profiles"],
        ).split("\r\n")

        return [(row.split(": ")[1]) for row in profiles_list if "Profile     :" in row]

    def get_single_password(self, ssid) -> str:
        profile_info = self._command_runner(
            ["netsh", "wlan", "show", "profile", ssid, "key=clear"]
        )

        if "not found on the system" in profile_info:
            raise ValueError("SSID not known.")

        for row in profile_info.split("\r\n"):
            if "Key Content" in row:
                psk = row.split(": ")[1].strip()
                return psk
        return ""
