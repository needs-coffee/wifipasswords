# windows specific version of class
# imported as subclass to main WifiPasswords class in __init__
# functions are 1:1 maapping of stub funcitons in WifiPasswords with platform specific code
# documentation for funcitons provided only in main __init__ WifiPasswords class as is the only class designed to be exposed

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

from . import __version__, __copyright__, __licence__


class WifiPasswordsWindows:
    def __init__(self) -> None:
        self.data = {}
        self.number_of_profiles = 0
        self.number_visible_networks = 0
        self.number_of_interfaces = 0
        self.net_template = {'auth': '', 'psk': '',
                             'metered': False, 'macrandom': 'Disabled'}

    def get_passwords(self) -> dict:
        # need to use pipes for all STDIO on windows if running without interactive console.
        # STARTUPINFO is only present on windows, not linux
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        profiles_list = subprocess.run(['netsh', 'wlan', 'show', 'profiles'],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       stdin=subprocess.PIPE,
                                       startupinfo=si).stdout.decode('utf-8').split('\r\n')

        networks = {(row.split(': ')[1]): self.net_template.copy()
                    for row in profiles_list if "User Profile" in row}

        for net, value in networks.items():
            profile_info = subprocess.run(['netsh', 'wlan', 'show', 'profile', net, 'key=clear'],
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          stdin=subprocess.PIPE,
                                          startupinfo=si).stdout.decode('utf-8').split('\r\n')

            for row in profile_info:
                if "Key Content" in row:
                    value['psk'] = row.split(': ')[1].strip()
                if "Authentication" in row:
                    value['auth'] = row.split(': ')[1].strip()
                if "Cost" in row:
                    if "Fixed" in row or "Variable" in row:
                        value['metered'] = True
                if "MAC Randomization" in row:
                    value['macrandom'] = row.split(': ')[1].strip()

        self.number_of_profiles = len(networks)
        self.data = networks
        return networks


    def get_passwords_dummy(self, delay: float = 0.5, quantity: int = 10) -> dict:
        from time import sleep
        from random import randint, choice
        from secrets import token_urlsafe
        sleep(delay)
        data_wpa = {f'network {n}': {'auth': 'WPA2-Personal',
                                     'psk': f'{token_urlsafe(randint(8,16))}',
                                     'metered': choice([True, False]),
                                     'macrandom': choice(['Disabled', 'Enabled', 'Daily'])}
                    for n in range(1, int(quantity/2), 1)}
        data_open = {f'open network {n}': {'auth': 'Open',
                                           'psk': '',
                                           'metered': choice([True, False]),
                                           'macrandom': choice(['Disabled', 'Enabled', 'Daily'])}
                     for n in range(1, int(quantity/2), 1)}
        data = {**data_wpa, **data_open}
        self.number_of_profiles = len(data)
        self.data = data
        return data


    def get_passwords_data(self) -> dict:
        return self.data


    def get_visible_networks(self, as_dictionary=False) -> str:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        current_networks = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'],
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          stdin=subprocess.PIPE,
                                          startupinfo=si).stdout.decode('utf-8')

        if "powered down" in current_networks:
            self.number_visible_networks = 0
        else:
            number = int(re.findall('\d{1,2}(?= network.* currently visible)',
                                    current_networks)[0].strip())
            self.number_visible_networks = number

        if as_dictionary:
            if not "powered down" in current_networks:
                networks_split = re.split('(?<!B)SSID ', current_networks)[1:]
                visible_dict = {}
                for i in networks_split:
                    bssid = []
                    radio = []
                    channel = []
                    rates = []
                    ssid = i.split('\r\n')[0].split(':')[1].strip()
                    if ssid == '':
                        ssid = 'Hidden ' + i.split('\r\n')[0].split(':')[0].strip()
                    for row in i.split('\r\n'):
                        if "Network type" in row:
                            net_type = row.split(': ')[1].strip()
                        else:
                            net_type = ''
                        if "Authentication" in row:
                            auth = row.split(': ')[1].strip()
                        else:
                            auth = ''
                        if "Encryption" in row:
                            encryption = row.split(': ')[1].strip()
                        else:
                            encryption = ''
                        if "BSSID" in row:
                            bssid.append(str(row.split(': ')[1]))
                        if "Signal" in row:
                            signal = row.split(': ')[1].strip()
                        else:
                            signal = ''
                        if "Radio type" in row:
                            radio.append(str(row.split(': ')[1]))
                        if "Channel" in row:
                            channel.append(str(row.split(': ')[1]))
                        if "Basic rates" in row or "Other rates" in row:
                            rates.append(str(row.split(':')[1]))

                        visible_dict[ssid] = {'type': net_type, 'auth': auth, 'encryption': encryption,
                                            'bssids': bssid, 'signal': signal, 'radios': radio, 'channel': channel, 'rates': rates}
                return visible_dict
            else:
                return {}
        else:
            return current_networks


    def get_dns_config(self, as_dictionary=False) -> str:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        dns_settings = subprocess.run(['netsh', 'interface', 'ip', 'show', 'dns'],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      stdin=subprocess.PIPE,
                                      startupinfo=si).stdout.decode('utf-8')

        split_dns_config = dns_settings.strip().split('\r\n\r\n')
        self.number_of_interfaces = len(split_dns_config)

        if as_dictionary:
            dns_dict = {}
            for i in split_dns_config:
                interface = i.split('"')[1].strip()
                if "Statically" in i:
                    type = 'Static'
                elif "DHCP" in i:
                    type = 'DHCP'
                else:
                    type = 'None'
                dns = i.split('\r\n')[1].split(': ')[1].strip()
                suffix = i.split('Register with which suffix:')[1].strip()
                dns_dict[interface] = {'type': type,
                                       'DNS': dns, 'suffix': suffix}
            return dns_dict
        else:
            return dns_settings


    def save_wpa_supplicant(self, path: str, data: dict = None, include_open: bool = True,
                            locale: str = 'GB') -> None:
        from datetime import datetime
        from platform import uname
        if data == None:
            data = self.data

        with open(os.path.join(path), 'w', newline='\n') as fout:
            fout.write(f'# Generated by wifipasswords {__version__}\n')
            fout.write(f'# Created: {datetime.today()}\n')
            fout.write(
                f'# Device: {uname().system} {uname().version} - {uname().node}\n')
            fout.write(f'# Detected country code: {locale}\n')
            fout.write('\n')
            fout.write(
                'ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n')
            fout.write('update_config=1\n')
            fout.write(f'country={locale}\n')
            fout.write('\n')
            fout.write('# ######## WPA ########\n')
            for key, n in data.items():
                if(n['auth'] == 'WPA2-Personal'):
                    fout.write('network={\n')
                    fout.write('\tssid="{}"\n'.format(key))
                    fout.write('\tpsk="{}"\n'.format(n['psk']))
                    fout.write('\tkey_mgmt=WPA-PSK\n')
                    fout.write('\tid_str="{}"\n'.format(key))
                    fout.write('}\n')
            fout.write('\n')
            if include_open:
                fout.write('# ######## OPEN ########\n')
                for key, n in data.items():
                    if(n['auth'] == '' or n['auth'] == 'Open'):
                        fout.write('network={\n')
                        fout.write('\tssid="{}"\n'.format(key))
                        fout.write('\tkey_mgmt=NONE\n')
                        fout.write('\tid_str="{}"\n'.format(key))
                        fout.write('\tpriority=-999\n')
                        fout.write('}\n')


    def save_json(self, path: str, data: dict = None) -> None:
        if data == None:
            data = self.data

        with open(os.path.join(path), 'w') as fout:
            json.dump(data, fout)


    def get_number_visible_networks(self) -> int:
        data = self.get_visible_networks()
        return self.number_visible_networks


    def get_number_interfaces(self) -> int:
        data = self.get_dns_config()
        return self.number_of_interfaces


    def get_number_profiles(self) -> int:
        if self.number_of_profiles == 0:
            self.get_passwords()
        return self.number_of_profiles


    def get_currently_connected_ssids(self) -> list:
        connected_ssids = []

        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        current_interfaces = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      stdin=subprocess.PIPE,
                                      startupinfo=si).stdout.decode('utf-8').split('\r\n')
        for line in current_interfaces:
            # space before ssid prevents BSSID being captured
            if " SSID" in line:
                #what if ssid contains : ? could it? would need workaround logic if so
                connected_ssids.append(line.split(':')[1].strip())
        
        return connected_ssids
