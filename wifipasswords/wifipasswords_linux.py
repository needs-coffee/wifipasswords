# Linux specific version of class
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
import configparser
import io

from . import __version__, __copyright__, __licence__


class WifiPasswordsLinux:
    def __init__(self) -> None:
        self.nm_path = '/etc/NetworkManager/system-connections'
        self.wpa_supplicant_file_path = '/etc/wpa_supplicant/wpa_supplicant.conf'
        self.data = {}
        self.number_of_profiles = 0
        self.number_visible_networks = 0
        self.number_of_interfaces = 0
        self.net_template = {'auth': '', 'pw': '',
                             'metered': False, 'macrandom': 'Disabled'}

    def get_passwords(self) -> dict:
        ## blank network dictionary 
        networks = {}

        ## check network manager first, if configured dont check wpa_supplicant file 
        # if the path doesnt exist then NetworkManager prob isnt installed/configured.
        if os.path.exists(self.nm_path):
            nm_files = [os.path.join(self.nm_path,file) for file in os.listdir(self.nm_path)
                        if file.endswith('.nmconnection')]

            for file in nm_files:
                file_string = subprocess.run(['sudo', 'cat', file],
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE,
                                               stdin=subprocess.PIPE).stdout.decode('utf-8')

                buf = io.StringIO(file_string)
                parser = configparser.ConfigParser()
                parser.read_file(buf)

                if parser['connection']['type'] == 'wifi':
                    ssid = parser['wifi']['ssid']

                    if parser.has_option('wifi-security','psk'):
                        psk = parser['wifi-security']['psk']
                    else:
                        psk = ''

                    if psk == '':
                        auth = 'Open'
                    else:
                        if parser.has_option('wifi-security', 'key-mgmt'):
                            auth = parser['wifi-security']['key-mgmt']
                        else:
                            auth = 'Open'

                    metered = False
                    if parser.has_option('connection','metered'):
                        if parser['connection']['metered'] == 1:
                            metered = True
                    
                    mac_random = 'Disabled'
                    if parser.has_option('wifi','cloned-mac-address'):
                        if parser['wifi']['cloned-mac-address'] == 'random':
                            mac_random = 'Random'
                        elif parser['wifi']['cloned-mac-address'] == 'stable':
                            mac_random = 'Stable Random'
                    
                    networks[ssid] = {'auth':auth, 'psk': psk, 'metered': metered, 'macrandom': mac_random}

        ## check wpa_supplicant file, but only if the file exists and no networks were found from networkmanager 
        # if network manager is being used there shouldn't be an active wpa_supplicant file
        if os.path.isfile(self.wpa_supplicant_file_path) and len(networks) == 0:
            file_string = subprocess.run(['sudo', 'cat', self.wpa_supplicant_file_path],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         stdin=subprocess.PIPE).stdout.decode('utf-8')

            network_blocks = re.findall('(?<=network=)[^}]*(?=})',file_string)
            for network_block in network_blocks:
                block_stripped = network_block.strip().replace('\t','').replace('\n',' ').split(' ')
                for item in block_stripped:
                    if 'ssid' in item:
                        ssid = item.split('ssid=')[1][1:-1]
                    if 'key_mgmt' in item:
                        auth_temp = item.split('key_mgmt=')[1]
                        if auth_temp.upper() == 'NONE':
                            auth = 'Open'
                        else:
                            auth = auth_temp
                    if 'psk' in item:
                        psk = item.split('psk=')[1][1:-1]
                
                metered = False
                mac_random = 'Disabled'
                networks[ssid] = {'auth': auth, 'psk': psk,
                                  'metered': metered, 'macrandom': mac_random}

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


    #to do - get further details from the network info like windows
    # add to dictionary logic - to add further details
    # fix for multiple networks
    # currently just returns a string of current networks or a dictionary with None values 
    def get_visible_networks(self, as_dictionary=False) -> str:
        #first find the wifi interfaces, for now only identifies the first interface
        interfaces_text = subprocess.run(['iwconfig'],
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE,
                                                stdin=subprocess.PIPE).stdout.decode('utf-8').split('\n')
        wifi_interface = interfaces_text[0].split()[0]

        #then check the networks for the interfaces
        current_networks_lines = subprocess.run(['sudo','iwlist',wifi_interface,'scan'],
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          stdin=subprocess.PIPE).stdout.decode('utf-8').split('\n')

        current_networks_list = [] 
        for line in current_networks_lines:
            if 'ESSID' in line:
                if line.split('ESSID:')[1][1:-1] == '':
                    current_networks_list.append('Hidden')
                else:
                    current_networks_list.append(line.split('ESSID:')[1][1:-1])


        if as_dictionary:
            visible_dict = {k:None for k in current_networks_list}
            return visible_dict
        else:
            return '\n'.join(current_networks_list)


    # to do - not yet implemented on linux
    def get_dns_config(self, as_dictionary=False) -> str:
        if as_dictionary:
            dns_dict = {}
            return dns_dict
        else:
            return 'Not yet implemented for linux'


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
                if(n['auth'] == 'WPA2-Personal' or n['auth'].lower() == 'wpa-psk'):
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

    ## not yet implemented on linux
    def get_number_interfaces(self) -> int:
        data = self.get_dns_config()
        return self.number_of_interfaces
 

    def get_number_profiles(self) -> int:
        if self.number_of_profiles == 0:
            self.get_passwords()
        return self.number_of_profiles


    def get_currently_connected_ssids(self) -> list:
        connected_ssids = []
        connected_data = subprocess.run(['iwgetid','-r'],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      stdin=subprocess.PIPE).stdout.decode('utf-8')
                                      
        for item in connected_data.split('\n'):
            if item != '':
                connected_ssids.append(item)

        return connected_ssids
