# macos specific version of class
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
from multiprocessing.dummy import Pool as ThreadPool

from . import __version__, __copyright__, __licence__

class WifiPasswordsMacos:
    def __init__(self) -> None:
        self.airport = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
        self.data = {}
        self.number_of_profiles = 0
        self.number_visible_networks = 0
        self.number_of_interfaces = 0
        self.net_template = {'auth': '', 'psk': '',
                             'metered': False, 'macrandom': 'Disabled'}


    @staticmethod
    def _command_runner(shell_commands:list) -> str:
        """
        Split subprocess calls into separate runner module for clarity of code.\n
        Takes the command to execute as a subprocess in the form of a list.\n
        Returns the string output as a utf-8 decoded output.\n
        """
        return_data = subprocess.run(shell_commands,
                                     stdout=subprocess.PIPE).stdout.decode('utf-8')
        return return_data


    #DONE -> not fully tested 
    # ?threading ?mac randomisation ?metered
    # prompts for escalation for every password
    def get_passwords(self) -> dict:
        # dump the keychain (without secrets) to get lists of keychain entries, split as items by atrributes
        # then filter the keychain items to find those with "desc"<blob>="AirPort network password"
        keychain_ssids = []
        results = {}

        keychain_dump = self._command_runner(['security','dump-keychain'])
        keychain_items = [keychain_item.split('\n') for keychain_item in keychain_dump.split('attributes:')
                             if 'AirPort network password' in keychain_item]
       
        for item in keychain_items:
            for row in item:
                if '"acct"<blob>=' in row:
                    # blob = row.split('"acct"<blob>')[1:-1]
                    blob = row.split('"acct"<blob>=')[1]
                    if blob.startswith('0x'):
                        #hex encoded due to unprintable chars - take as bytes and decode
                        stripped_blob = blob.split('  ')[0]
                        ssid = bytes.fromhex(stripped_blob[2:]).decode('utf-8')
                    else:
                        #string encoded, just remove 2 quotes.
                        ssid = blob[1:-1]
                    keychain_ssids.append(ssid)    

        # need to find way of getting metered and macrandomisation - is this defined per network on mac?
        for ssid in keychain_ssids:
            psk = self._command_runner(['security', 'find-generic-password', '-a', ssid,'-w']).strip()
            results[ssid] = {'auth': '', 'psk': psk, 'metered': False, 'macrandom': 'Disabled'}

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
        network_dict = {}
        network_list = []
        current_networks = self._command_runner(['airport','-s']).split('\n')
        #remove blank/whitespace entries
        current_networks[:] = [network for network in current_networks if network.strip()]
        #discard header row
        for network in current_networks[1:]:
            ssid = re.search(r'.*(?=\s[a-z0-9]{2}:[a-z0-9]{2})', network)[0].strip()
            bssids = re.search(r'([a-z0-9]{2}:){5}([a-z0-9]{2})',network)[0]
            rssi = re.search(r'(?<=([a-z0-9]{2}:){5}([a-z0-9]{2})\s)-\d{2}', network)[0]
            channel = re.search(r'(?<=-\d{2})\s{1,2}[0-9,+]{1,6}', network)[0].strip()
            encryption = re.search(r'\S*$', network.strip())[0]
            
            if as_dictionary:
                network_dict[ssid] = {'bssids':bssids, 'channel':channel, 'signal':rssi,
                                        'encryption':encryption}
            else:
                network_list.append(f"{ssid}\n BSSID: {bssids}\n Channel: {channel}\n Signal (RSSI): {rssi}\n Security: {encryption}\n")

        if as_dictionary:
            self.number_visible_networks = len(network_dict)
            return network_dict
        else:
            self.number_visible_networks = len(network_list)
            return f'Number of visible networks: {len(network_list)}' + '\n' + '\n'.join(network_list)
            
    
    def get_dns_config(self, as_dictionary=False) -> str:
        dns_settings = self._command_runner(['scutil','--dns'])
        interfaces_data = self._command_runner(['ifconfig']).strip().split('\n')
           
        dns_dict = {}

        #for macos, look at scoped DNS queries as most on scutil relate to mdns
        split_dns_config = dns_settings.strip().split('\n\n')
        scoped_dns_index = split_dns_config.index('DNS configuration (for scoped queries)')
        scoped_dns = split_dns_config[scoped_dns_index + 1:]
        
        interfaces = [item.split(':')[0] for item in interfaces_data if not item.startswith('\t')]
        self.number_of_interfaces = len(interfaces)

        # add entries for each interface without a scoped query 
        for interface in interfaces:
            dns_dict[interface] = {'type':'None', 'DNS': '', 'suffix':''}

        for item in scoped_dns:
            interface = ''
            type = 'None'
            dns = ''
            suffix = ''
            rows = item.split('\n')
            for row in rows:
                if 'search domain' in row:
                    suffix = row.split(':')[1].strip()
                if 'if_index' in row:
                    interface = re.search(r'\(.*\)',row)[0][1:-1]
                if 'nameserver' in row:
                    dns = row.split(':')[1].strip()
        
            dns_dict[interface] = {'type':type, 'DNS':dns, 'suffix': suffix}
    
        if as_dictionary:
            return dns_dict
        else:
            dns_string = f'Number of interfaces: {self.number_of_interfaces}' + '\n'
            other_interfaces = []
            for item,v in dns_dict.items():
                if v['DNS'] == '':
                    other_interfaces.append(item)
                else:
                    dns_string = dns_string + \
                        f"Interface: {item} \n type: {v['type']} \n DNS: {v['DNS']} \n domain: {v['suffix']}" + '\n' + '\n'
            dns_string = dns_string + '\n' + 'Other interfaces:' + '\n'
            for item in other_interfaces:
                dns_string = dns_string + ' ' + item + '\n'
            return dns_string
    
    
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
        current_interfaces = self._command_runner([self.airport,'-I']).split('\n')

        for line in current_interfaces:
            if " SSID" in line:
                connected_ssids.append(line.split(':')[1].strip())
        
        return connected_ssids


    def get_currently_connected_passwords(self) -> list:
        connected_passwords = []
        connected_ssids = self.get_currently_connected_ssids()
        
        for ssid in connected_ssids:
            psk = self._command_runner(['security', 'find-generic-password', '-a', ssid,'-w']).strip()
            connected_passwords.append((ssid,psk))

        return connected_passwords


    def get_known_ssids(self) -> list:
        keychain_ssids = []
        keychain_dump = self._command_runner(['security', 'dump-keychain'])
        keychain_items = [keychain_item.split('\n') for keychain_item in keychain_dump.split('attributes:')
                          if 'AirPort network password' in keychain_item]

        for item in keychain_items:
            for row in item:
                if '"acct"<blob>=' in row:
                    blob = row.split('"acct"<blob>=')[1]
                    if blob.startswith('0x'):
                        #hex encoded due to unprintable chars - take as bytes and decode
                        stripped_blob = blob.split('  ')[0]
                        ssid = bytes.fromhex(stripped_blob[2:]).decode('utf-8')
                    else:
                        #string encoded, just remove 2 quotes.
                        ssid = blob[1:-1]
                    keychain_ssids.append(ssid)   
        return keychain_ssids


    def get_single_password(self, ssid) -> str:
        return_data = subprocess.run(['security', 'find-generic-password', '-a', ssid, '-w'],
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        err = return_data.stderr.decode('utf-8').strip()
        if 'The specified item could not be found in the keychain.' in err:
            raise ValueError('SSID not known.')
        psk = return_data.stdout.decode('utf-8').strip()

        return psk        
