# Linux specific version of class
# imported as subclass to main WifiPasswords class in __init__
# exposed functions are 1:1 maapping of stub funcitons in WifiPasswords with platform specific code
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
from multiprocessing.dummy import Pool as ThreadPool, Value

from . import __version__, __copyright__, __licence__


class WifiPasswordsLinux:
    def __init__(self) -> None:
        self.nm_path = '/etc/NetworkManager/system-connections'
        self.wpa_supplicant_file_path = '/etc/wpa_supplicant/wpa_supplicant.conf'
        self.data = {}
        self.number_of_profiles = 0
        self.number_visible_networks = 0
        self.number_of_interfaces = 0
        self.net_template = {'auth': '', 'psk': '',
                             'metered': False, 'macrandom': 'Disabled'}


    @staticmethod
    def _command_runner(shell_commands: list) -> str:
        """
        Split subprocess calls into separate runner module for clarity of code.\n
        Takes the command to execute as a subprocess in the form of a list.\n
        Returns the string output as a utf-8 decoded output.\n
        """
        return_data = subprocess.run(shell_commands,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     stdin=subprocess.PIPE).stdout.decode('utf-8')
        return return_data


    def _get_password_subthread(self, network):
        # network is a tuple from the networks dictionary
        # values are (ssid, value dictionary)
        profile_info = self._command_runner(
            ['nmcli', '-t', '-f', '802-11-wireless-security.key-mgmt,802-11-wireless-security.psk,connection.metered,802-11-wireless.cloned-mac-address',
                'c', 's', network[0], '--show-secrets']).split('\n')
        
        network[1]['auth'] = 'Open'
        network[1]['psk'] = ''
        network[1]['metered'] = False
        network[1]['macrandom'] = 'Disabled'

        for row in profile_info:
            if "802-11-wireless-security.key-mgmt" in row:
                network[1]['auth'] = row.split(':')[1]
            if "802-11-wireless-security.psk" in row:
                network[1]['psk'] = row.split(':')[1]
            if "connection.metered" in row:
                if "yes" in row.split(':')[1]:
                    network[1]['metered'] = True
            if "802-11-wireless.cloned-mac-address" in row:
                if row.split(':')[1] != '':
                    network[1]['macrandom'] = row.split(':')[1]
        return network


    def get_passwords(self) -> dict:
        ## check network manager first, if configured dont check wpa_supplicant file
        # if the path doesnt exist then NetworkManager prob isnt installed/configured.
        if os.path.exists(self.nm_path):
            profiles_list = self._command_runner(['nmcli','-t','-f','NAME,TYPE','c']).split('\n')
            networks = {re.split(r"(?<!\\):",network)[0]:self.net_template.copy() 
                                for network in profiles_list if '802-11-wireless' in network}
            pool = ThreadPool(6)
            results = dict(pool.imap(self._get_password_subthread,networks.items()))
            pool.close()
            pool.join()

        ## check wpa_supplicant file, but only if the file exists and no networks were found from networkmanager
        # if network manager is being used there shouldn't be an active wpa_supplicant file
        elif os.path.isfile(self.wpa_supplicant_file_path):
            results = {}
            file_string = self._command_runner(['sudo','cat',self.wpa_supplicant_file_path])
            network_blocks = re.findall('(?<=network={)[^}]*(?=})', file_string)
            for network_block in network_blocks:
                block_stripped = network_block.strip().replace('\t', '').split('\n')
                ssid = ' '
                auth = ' '
                psk = ' '
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
                results[ssid] = {'auth': auth, 'psk': psk,
                                  'metered': metered, 'macrandom': mac_random}
        else:
            results = {}

        self.number_of_profiles = len(results)
        self.data = results
        return results                     


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
        ## check nmcli first, if doesnt exist return not implemented string
        ## 
        if os.path.exists(self.nm_path):
            network_dict = {}
            network_list = []
            
            visible_list = self._command_runner(['nmcli','-t','-f','SSID,CHAN,RATE,SIGNAL,SECURITY','dev','wifi']).split('\n')
            for row in visible_list:
                try:
                    row_split = row.split(':')
                    if row_split[0] == '':
                        row_split[0] = 'Hidden'
                    if as_dictionary:
                        network_dict[row_split[0]] = {'auth':row_split[4], 
                                                        'channel':row_split[1],
                                                        'signal':row_split[3],
                                                        'rates':row_split[2]} 
                    else:
                        network_list.append(f"{row_split[0]} \n Channel: {row_split[1]} \n Rate: {row_split[2]} \n Signal: {row_split[3]}% \n Security: {row_split[4]} \n")
                except:
                    pass
            if as_dictionary:
                self.number_visible_networks = len(network_dict)
                return network_dict
            else:
                self.number_visible_networks = len(network_list)
                visible_networks = f'There are {len(network_list)} networks visible.' + '\n ----- \n' + '\n'.join(network_list)
                return visible_networks
        else:
            if as_dictionary:
                return {}
            else:
                return 'Requires NetworkManager.'


    def get_dns_config(self, as_dictionary=False) -> str:
        dns_dict = {}
        ## uses nmcli - if doesnt exist return error message
        if os.path.exists(self.nm_path):
            interfaces = self._command_runner(['nmcli','-t','-f','DEVICE,CONNECTION','dev']).split('\n')
            for interface in interfaces:
                # try:
                if len(interface.split(':')) == 2:
                    suffix = ''
                    type = 'None'
                    DNS = []
                    interface_data = self._command_runner(['nmcli','-t','-f','IP4.DNS,IP4.DOMAIN','device','show',interface.split(':')[0]]).split('\n')
                    profile_data = self._command_runner(['nmcli','-t','-f','ipv4.dns,ipv4.ignore-auto-dns','c','s',interface.split(':')[1]]).split('\n')
                    for row in interface_data:
                        if 'IP4.DOMAIN' in row:
                            suffix = row.split(':')[1]
                        if 'IP4.DNS' in row:
                            DNS = row.split(':')[1].split(',')
                    for row in profile_data:
                        if 'ipv4.ignore-auto-dns' in row:
                            if row.split(':')[1] == 'yes':
                                type = 'Static'
                            elif row.split(':')[1] == 'no' and len(DNS) != 0:
                                type = 'DHCP'
                    dns_dict[interface.split(':')[0]] = {'type':type, 'DNS': DNS, 'suffix': suffix}

            if as_dictionary:
                return dns_dict
            else:
                dns_string = ''
                for k,v in dns_dict.items():
                    dns_string = dns_string + f"Interface: {k} \n type: {v['type']} \n DNS: {v['DNS']} \n domain: {v['suffix']}" + '\n' + '\n'
                return dns_string
        
        else:
            if as_dictionary:
                return {}
            else:
                return "Requires NetworkManager"


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


    def get_number_interfaces(self) -> int:
        data = self.get_dns_config()
        return self.number_of_interfaces
 

    def get_number_profiles(self) -> int:
        if self.number_of_profiles == 0:
            self.get_passwords()
        return self.number_of_profiles


    def get_currently_connected_ssids(self) -> list:
        connected_ssids = []

        #check if network manager is installed by checking config path, else use iwgetid
        if os.path.exists(self.nm_path):
            connected_data = self._command_runner(['nmcli', '-t', 'd']).split('\n')
            for row in connected_data:
                try:
                    if row.split(':')[1] == 'wifi' and row.split(':')[2] == 'connected':
                        connected_ssids.append(row.split(':')[3])
                except:
                    pass

        #if there is no nmcli, use iwgetid -r
        else:
            connected_data = self._command_runner(['iwgetid', '-r']).split('\n')
            for row in connected_data:
                try:
                    if row != '':
                        connected_ssids.append(row)
                except:
                    pass

        return connected_ssids


    def get_currently_connected_passwords(self) -> list:
        """
        Returns a tuple of (ssid, psk) for each currently connected network.
        """
        connected_passwords = []
        connected_ssids = self.get_currently_connected_ssids()

        if os.path.exists(self.nm_path):
            for ssid in connected_ssids:
                psk = ''
                key_content = self._command_runner(
                    ['nmcli', '-t', '-f', '802-11-wireless-security.psk', 'c', 's', ssid, '--show-secrets'])
                if key_content != '':
                    for row in key_content.split('\n'):
                        if '802-11-wireless-security.psk' in row:
                            psk = row.split(':')[1]
                    connected_passwords.append((ssid, psk))

        elif os.path.isfile(self.wpa_supplicant_file_path):
            file_string = self._command_runner(
                ['sudo', 'cat', self.wpa_supplicant_file_path])
            network_blocks = re.findall('(?<=network=)[^}]*(?=})', file_string)

            #if matching a connected ssid
            matched_blocks = [net for net in network_blocks if any(
                xs in net for xs in connected_ssids)]

            for network_block in matched_blocks:
                block_stripped = network_block.strip().replace(
                    '\t', '').replace('\n', ' ').split(' ')
                ssid = ''
                psk = ''
                for row in block_stripped:
                    if 'ssid' in row:
                        ssid = row.split('ssid=')[1][1:-1]
                    if 'psk' in row:
                        psk = row.split('psk=')[1][1:-1]
                connected_passwords.append((ssid, psk))

        return connected_passwords


    def get_known_ssids(self) -> list:
        ssids = []
        ## check network manager first, if configured dont check wpa_supplicant file
        # if the path doesnt exist then NetworkManager prob isnt installed/configured.
        if os.path.exists(self.nm_path):
            profiles_list = self._command_runner(['nmcli', '-t', '-f', 'NAME,TYPE', 'c']).split('\n')
            ssids = [re.split(r"(?<!\\):", ssid)[0] for ssid in profiles_list if '802-11-wireless' in ssid]

        ## check wpa_supplicant file, but only if the file exists and no networks were found from networkmanager
        # if network manager is being used there shouldn't be an active wpa_supplicant file
        elif os.path.isfile(self.wpa_supplicant_file_path):
            file_string = self._command_runner(['sudo', 'cat', self.wpa_supplicant_file_path])
            network_blocks = re.findall('(?<=network={)[^}]*(?=})', file_string)
            for network_block in network_blocks:
                block_stripped = network_block.strip().replace('\t', '').split('\n')
                ssid = ' '
                for item in block_stripped:
                    if 'ssid' in item:
                        ssid = item.split('ssid=')[1][1:-1]
                ssids.append(ssid)
        else:
            ssids = []

        self.number_of_profiles = len(ssids)
        return ssids


    def get_single_password(self, ssid) -> str:
        psk = ''
        found = False
        if os.path.exists(self.nm_path):
            key_content = self._command_runner(['nmcli', '-t', '-f',
                             '802-11-wireless-security.psk,connection.id', 'c', 's', ssid, '--show-secrets'])
            if key_content == '':
                raise ValueError('SSID not known.')
            else:
                found = True
            
            for row in key_content.split('\n'):
                if '802-11-wireless-security.psk' in row:
                    psk = row.split(':')[1]

        elif os.path.isfile(self.wpa_supplicant_file_path):
            file_string = self._command_runner(['sudo', 'cat', self.wpa_supplicant_file_path])
            network_blocks = re.findall('(?<=network=)[^}]*(?=})', file_string)

            for network_block in network_blocks:
                if ssid in network_block:
                    found = True
                    stripped_block = network_block.strip().replace(
                        '\t', '').replace('\n', ' ').split(' ')
                    for row in stripped_block:
                        if 'psk' in row:
                            psk = row.split('psk=')[1][1:-1]
        if found:
            return psk
        else:
            raise ValueError('SSID not known.')