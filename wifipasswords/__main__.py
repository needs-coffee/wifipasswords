#!/usr/bin/env python3

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

import os
import platform
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from colorama import init, Fore, Back

from . import WifiPasswords, __version__, __licence__


def get_commandline_arguments() -> dict:
    """
    Get Command line arguments passed to script.\n
    Returns - args as dictionary.
    """
    helpstring = """
    Show all wifi passwords stored on windows and linux. MacOS to be added.
    For all commands below PATH is optional for saving files.
    If no path is specified, will default the current working directory.

    wifipasswords version {} 
    This program comes with ABSOLUTELY NO WARRANTY. 
    This is free software, and you are welcome to redistribute it 
    under certain conditions, see the GPLv3 Licence file attached.
    {} - Licence: {} """.format(__version__,__copyright__, __licence__)

    parser = ArgumentParser(description=helpstring,
                            formatter_class=RawTextHelpFormatter)
    parser.add_argument('-a', '--all', help="Show DNS, current visible networks, and save as JSON and wpa_supplicant.conf in given path",
                        nargs="?", const=".", metavar='PATH')
    parser.add_argument('-c', '--current', help="show currently visible networks",
                        nargs="?", const='.', metavar='')
    parser.add_argument('-d', '--dns', help='Show DNS configurations',
                        nargs="?", const='.', metavar='')
    parser.add_argument("-j", "--json", help="output JSON of networks in given directory",
                        nargs="?", const='.', metavar='PATH')
    parser.add_argument('-v','-V', '--version',
                        action='version', version=__version__)
    parser.add_argument('-w', '--wpasupplicant',
                        help="create a wpa_supplicant.conf for all networks.", nargs="?", const=".", metavar='PATH')
    args = vars(parser.parse_args())

    return args


def print_output_heading() -> None:
    """
    Prints the static header for the command line output.\n
    """
    print(Fore.BLACK + Back.WHITE +
            "{:^92}".format("WIFI PASSWORDS " + __version__))
    print("{:^92}".format("Lists known wifi networks and passwords."))
    print("{:^92}".format("'>' before SSID denotes the currently connected network."))
    print("{:^92}".format(
        "(M) denotes metered connection. --help to show more options."))
    print("*" * 92)
    print(Back.WHITE + Fore.BLACK +
            "{:^33} | {:^13} | {:^40}".format("NETWORK", "AUTH", "PASSWORD"))


def print_network_data(networks,connected_ssids) -> None:
    """
    Print data from the network dictionary.
    """
    for key, n in networks.items():
        if key in connected_ssids:
            connected = '>'
        else:
            connected = ' '
        if n['metered']:
            metered = Fore.LIGHTBLACK_EX + "(M)"
        else:
            metered = ''
        print("{:<1} {:<31} | {:<13} | {:<36} {}".format(
            connected, key, n['auth'], n['psk'], metered))


def print_output_footer() -> None:
    """
    Print static footer.
    """
    print("\r\n" + "*" * 92)
    print("{:>92}".format("JC 2019-2021"))


def print_visible_networks(current_networks) -> None:
    """
    Output for visible networks.
    """
    print(Fore.BLACK + Back.WHITE +
            "{:^92}".format("Currently Visible Networks"))
    print(current_networks)
    print("*"*92)


def print_current_dns_config(dns_config) -> None:
    """
    output for passed DNS config.
    """
    print(Fore.BLACK + Back.WHITE +
            "{:^92}".format("Currently DNS Configuration"))
    print(dns_config)
    print("*"*92)

def cli():

    init(autoreset=True)
    pw = WifiPasswords()
    args = get_commandline_arguments()
    print_output_heading()
    data = pw.get_passwords()
    active_ssids = pw.get_currently_connected_ssids()
    print_network_data(data,active_ssids)
    print_output_footer()
    if not args['current'] == None or not args['all'] == None:
        print_visible_networks(pw.get_visible_networks())
    if not args['dns'] == None or not args['all'] == None:
        print_current_dns_config(pw.get_dns_config())

    if not args['wpasupplicant'] == None or not args['all'] == None:
        if args['wpasupplicant'] == None:
            args['wpasupplicant'] = args['all']
        print()
        pw.save_wpa_supplicant(os.path.join(
            args['wpasupplicant'], 'wpa_supplicant.conf'), data, True, 'GB')
        print(
            f"wpa_supplicant.conf written to {os.path.join(args['wpasupplicant'],'wpa_supplicant.conf')}")

    if not args['json'] == None or not args['all'] == None:
        if args['json'] == None:
            args['json'] = args['all']
        print()
        pw.save_json(os.path.join(args['json'], 'networks_data.json'),data)
        print("JSON saved >> {}".format(
            os.path.join(args['json'], 'networks_data.json')))
    print()


if __name__ == '__main__':
    sys.exit(cli())
