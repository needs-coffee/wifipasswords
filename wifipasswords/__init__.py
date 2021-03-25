#!/usr/bin/env python3
""" wifipasswords.py
    Retreive and save all wifi networks and passwords on the device.
    On Windows uses netsh module.
    On Linux reads NetworkManager files or wpa_supplicant files. Partially implemented.
    MacOS to be implemented.
    Uses the netsh windows module. Pass --JSON argument to export as JSON.
    Pass --wpasupplicant to create a wpa_supplicant.conf file for linux
    Creation date: 10-02-2019
    Modified date: 25-03-2021
    Dependencies: colorama
"""
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

__version__ = "0.3.3-beta"
__licence__ = "GPLv3"  # GNU General Public Licence v3

import platform

class WifiPasswords:
    """
    For retrieving wifi network information.\n
    Uses platform specific code to retrieve information.\n
    """

    def __init__(self) -> None:
        self.platform = platform.system()

        if self.platform == 'Windows':
            from .wifipasswords_windows import WifiPasswordsWindows as _PlatformClass
            self._WifiPasswordsSubclass = _PlatformClass()
        elif self.platform == 'Linux':
            from .wifipasswords_linux import WifiPasswordsLinux as _PlatformClass
            self._WifiPasswordsSubclass = _PlatformClass()
        elif self.platform == 'Darwin':
            raise NotImplementedError
        elif self.platform == 'Java':
            raise NotImplementedError
        else:
            raise NotImplementedError

    @property
    def data(self) -> dict:
        """
        Returns the stored data value as a dictionary. \n
        """
        return self._WifiPasswordsSubclass.data
    

    @property
    def number_of_profiles(self) -> int:
        """
        Returns the number of saved profiles as an int. \n
        """
        return self._WifiPasswordsSubclass.number_of_profiles
    

    @property
    def number_of_visible_networks(self) -> int:
        """
        Returns the stored data value as a dictionary. \n
        """
        return self._WifiPasswordsSubclass.number_visible_networks
    
    
    @property
    def number_of_interfaces(self) -> int:
        """
        Returns the number of network interfaces. \n
        """
        return self._WifiPasswordsSubclass.number_visible_networks
    

    def get_passwords(self) -> dict:
        """
        Returns a nested dictionary of saved network profiles.\n
        includes network keys\n
        data is also maintained in the instance under data variable.\n
        can take several seconds to return.
        """
        return self._WifiPasswordsSubclass.get_passwords()


    def get_passwords_dummy(self, delay: float = 0.5, quantity: int = 10) -> dict:
        """
        Returns a dictionary of dummy networks for testing.\n
        Arguments:\n
        - delay: seconds of delay before returning. emulating netsh.\n
        - quantity: how many networks, half open, half wpa\n
        """
        return self._WifiPasswordsSubclass.get_passwords_dummy(delay,quantity)


    def get_passwords_data(self) -> dict:
        """
        returns stored data as dictionary.\n
        needs to be run after get_passwords or will return empty dict.
        """
        return self._WifiPasswordsSubclass.data


    def get_visible_networks(self, as_dictionary=False) -> str:
        """
        returns currently visible WiFi networks.\n
        returns a formatted string or dictionary.\n
        on linux only returns wifi SSID.\n
        Arguments:\n
        - as_dictionary: if true, returns nested dictionary of dns config, false returns str.\n
        """
        return self._WifiPasswordsSubclass.get_visible_networks(as_dictionary)


    def get_dns_config(self, as_dictionary=False) -> str:
        """
        returns current dns config.\n
        returns as formatted string as per netsh output.\n
        if split is specified returns nested dictionary.\n
        {interface: {type:static/dhcp, DNS: ip, whichsuffix: suffix}}\n
        not yet implemented on linux.\n
        Arguments:\n
        - as_dictionary: if true, returns nested dictionary of dns config, false returns str.\n
        """
        return self._WifiPasswordsSubclass.get_dns_config(as_dictionary)


    def save_wpa_supplicant(self, path: str, data: dict = None, include_open: bool = True,
                            locale: str = 'GB') -> None:
        """
        Saves formatted wpa_supplicant.conf file\n
        For use on linux systems to configure wifi\n
        arguments:\n
        - path - must be specified. Full path with filename.\n
        - data - dictionary or defaults to self.data\n
        - include open - select whether open networks in dictionary will be output.\n
        - locale - ISO country code to add to wpa_supplicant. Should be country of use.
        """
        self._WifiPasswordsSubclass.save_wpa_supplicant(path,data,include_open,locale)


    def save_json(self, path: str, data: dict = None) -> None:
        """
        Saves network data as JSON.\n
        arguments:\n
        - path - must be specified. Full path including filename.
        - data - dictionary, defaults to self.data
        """
        self._WifiPasswordsSubclass.save_json(path,data)


    def get_number_visible_networks(self) -> int:
        """
        number of networks visible currently.\n
        also calls get_visible_networks.\n
        """
        return self._WifiPasswordsSubclass.get_number_visible_networks()


    def get_number_interfaces(self) -> int:
        """
        returns number of interfaces, calculated from number of DNS configs.\n
        """
        return self._WifiPasswordsSubclass.get_number_interfaces()


    def get_number_profiles(self) -> int:
        """
        returns number of saved profiles.\n
        calls get_passwords if number of profiles is 0.\n
        """
        return self._WifiPasswordsSubclass.get_number_profiles()


    def get_currently_connected_ssids(self) -> list:
        """
        Returns all currently connected SSIDs as a list. \n
        Empty list if none connected. \n
        checks all active interfaces on the system. \n
        """
        return self._WifiPasswordsSubclass.get_currently_connected_ssids()

    
    def get_currently_connected_passwords(self) -> list:
        """
        Returns a tuple of (ssid, psk) for each currently connected network as a list.
        """
        return self._WifiPasswordsSubclass.get_currently_connected_passwords()
