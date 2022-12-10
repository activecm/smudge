"""
Main Module
"""

#======== Imports ========#
import argparse
import sys
import os
from signal import signal, SIGINT
from scapy.all import sniff
from smudge.command_line import CommandLineUtility



def handler(signal_received, frame):
    '''Handler for SIGINT'''
    print('\nSIGINT or CTRL-C detected. Exiting gracefully')
    sys.exit(0)


#======== Main ========#
def main():
    '''Main'''
    signal(SIGINT, handler)
    # Argparse Arguments
    description = 'SMUDGE passive OS detection based on SYN packets without Transmitting any Data.'
    parser = argparse.ArgumentParser(prog='smudge', description=description)
    parser.add_argument(
        '-c', '--colored-text',
        help='Disable colored text output.',
        action='store_true',
        required=False)
    parser.add_argument(
        '-d', '--database',
        help='Disable local SQlite db creation.',
        action='store_true',
        required=False)
    parser.add_argument(
        '-i','--interface',
        type=str,
        help='Interface that traffic will be sniffed on.',
        required=False)
    parser.add_argument(
        '-l', '--list',
        help='Lists available interfaces.',
        action='store_true',
        required=False)
    parser.add_argument(
        '-p', '--pause',
        type= str,
        help='Decimal value of the pause inbetween signature matches.',
        action='store',
        required=False)
    parser.add_argument(
        '-r','--read',
        action='store',
        type=str,
        help='PCAP file that will be read by SMUDGE.',
        required=False)
    args = vars(parser.parse_args())

    # List Interfaces Argument
    CommandLineUtility.list_interfaces(args['list'])

    # If not disabled via flag, create sqlite database and import signatures.
    CommandLineUtility.import_signatures(args['database'])

    # Verify that Signatures Exist
    if not CommandLineUtility.verify_signatures():
        sys.exit("""No signature.db file exists.
        Please run SMUDGE without the -d flag to generate one.""")

    # Read PCAP if flag supplied
    if args['read']:
        if os.path.exists(args['read']):
            CommandLineUtility.read_pcap(args)
        else:
            sys.exit('PCAP File does not exist.')

    # Sniff
    if not args['read']:
        pause = CommandLineUtility.verify_pause(args['pause'])
        interface = CommandLineUtility.verify_interface(args['interface'])
        print("--- SMUDGE an Open Source Project by Active Countermeasures ---")
        print("\n[+] Reading Packets from interface: " + str(interface))
        print("[+] Pause between signature matches: " + str(pause))
        print("[+] Entering main event loop.\n")
        try:
            sniff(
                prn=CommandLineUtility.handle_packet,
                filter='tcp[tcpflags] == tcp-syn',
                iface=interface)
        except PermissionError:
            sys.exit("Sniffing on specified interfaces requires additional privilege.")
    return True



#======== Smudge has entered the chat. ========#
if __name__ == '__main__':
    main()
