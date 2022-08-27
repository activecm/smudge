
#!/usr/bin/python
"""Passer learns, by watching network traffic, about the servers and clients on your network."""
#Copyright 2008-2018, William Stearns <william.l.stearns@gmail.com>
#Passer is a PASsive SERvice sniffer.
#Home site http://www.stearns.org/passer/
#Github repository https://github.com/organizations/activecm/passer/
#Dedicated to Mae Anne Laroche.

#Released under the GPL version 3:
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.

#======== Imports ========
import argparse
import scapy.all as scapy
from smudge.utils import Signature

def tcp_sig_plus(packet):
    """TCP SIG Plus Exception Handling"""
    if not tcp_sig_plus.pn:
        tcp_sig_plus.pn = 0
    tcp_sig_plus.pn += 1
    sig = Signature(packet)
    print("Packet: " + str(tcp_sig_plus.pn))
    print(packet)
    print("Signature for Packet: " + str(tcp_sig_plus.pn))
    print(sig)
    print("******************************************")
    #pn += 1



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Signature Generator')
    parser.add_argument('-i', '--interface',
        help='Interface(s) from which to read packets (default is all interfaces)',
        required=False, default=[], nargs='*')

    parser.add_argument('-r', '--read',
        help='Pcap file(s) from which to read packets',
        required=False, default=[], nargs='*')

    parser.add_argument('-l', '--log',
        help='File to which to write output csv lines',
        required=False, default=None)

    parser.add_argument('-b', '--bpf',
        help='BPF to restrict which packets are processed',
        required=False, default='')

    (parsed, unparsed) = parser.parse_known_args()
    cl_args = vars(parsed)
    InterfaceName = cl_args['interface']

    if InterfaceName:
        # Unused
        # scapy.sniff(store=0, iface=InterfaceName, filter=cl_args['bpf'],
        #     stopperTimeout=5, stopper=scapy.exit_now, prn=tcp_sig_plus)

        # Old scapy "stop_filter" feature to exit if needed; doesn't work yet, disabled.
        # scapy.sniff(store=0, iface=InterfaceName, filter=cl_args['bpf'],
        #     stop_filter=scapy.exit_now_packet_param, prn=tcp_sig_plus)

        # No attempt to exit sniff loop for the moment.
        scapy.sniff(store=0, iface=InterfaceName, filter=cl_args['bpf'],
            prn=tcp_sig_plus)

    if not InterfaceName and cl_args['read'] == []:
        # Unused
        # scapy.sniff(store=0, filter=cl_args['bpf'],
        # stopperTimeout=5, stopper=scapy.exit_now, prn=tcp_sig_plus)

        # Old scapy "stop_filter" feature to exit if needed; doesn't work yet, disabled.
        # scapy.sniff(store=0, filter=cl_args['bpf'],
        #     stop_filter=scapy.exit_now_packet_param, prn=tcp_sig_plus)

        #No attempt to exit sniff loop for the moment.
        scapy.sniff(store=0, filter=cl_args['bpf'], prn=tcp_sig_plus)
