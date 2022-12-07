#!/usr/bin/env python


#======== Imports ========#
import argparse
import sys
import os
from signal import signal, SIGINT
from smudge.utils import PassiveData, Signature, PullData, TcpSig, Matching, QueryObject
from scapy.all import sniff
from scapy.all import rdpcap
from scapy.interfaces import get_if_list
from colorama import Fore
from colorama import Style
import time

text = True


def colored_text():
    '''Enables crossplatform colored output.'''
    from colorama import Fore
    from colorama import Style
    return True


def cprint(bool, out):
    '''If enabled, prints main colored output.'''
    if bool:
        print(Fore.CYAN + out)
        print(Style.RESET_ALL)
    else:
        print(out)
    return True

def mprint(bool, out):
    '''If enabled, prints secondary colored output.'''
    if bool:
        print(Fore.MAGENTA + out)
        print(Style.RESET_ALL)
    else:
        print(out)
    return True

def calculate_dist(TTL):
    '''Takes a value of TTL and calculates hop distance.'''
    try:
        if TTL > 128:
            dist = 255 - TTL
        elif TTL > 64 and TTL < 129:
            dist = 128 - TTL
        elif TTL > 32 and TTL < 65:
            dist = 64 - TTL
        elif TTL > 0 and TTL < 33:
            dist = 32 -TTL
        else:
            dist = -1
    except:
        dist = -1
    return dist


def verify_pause(flo):
    '''Verify pause argument is between 0 and 1.''' 
    try:
        flo = float(flo)
    except ValueError:
        print("Pause argument must be a decimal value between 0 and 1.")
        print("Ignoring flag and applying default of 0.")
        flo = 0
    except TypeError:
        flo = 0.1
    except:
        sys.exit("Pause argument must be a decimal value between 0 and 1.")
    return flo


def verify_interface(interface):
    '''Verify interface argument is valid.'''
    interfaces = get_if_list()
    if interface in interfaces:
        interface = interface
    else:
        interface = ''
    return interface


def handler(signal_received, frame):
    '''Handler for SIGINT'''
    print('\nSIGINT or CTRL-C detected. Exiting gracefully')
    sys.exit(0)


def list_interfaces(bool):
    '''List all available Network Interfaces.'''
    if bool:
        interfaces = get_if_list()
        print("Available Interfaces: ")
        for i in interfaces:
            print("\t" + i)
        sys.exit(0)
    else:    
        return True


def import_signatures(bool):
    '''Import Signatures from Github'''
    # Get Signatures from Github
    if not bool:
        if PassiveData.test_github_con():
            signature_list = PullData.import_data()
        # Create Sqlite DB for Smudge Signatures
        PassiveData.setup_db()
	    # Create DB  Connection
        conn = PassiveData.create_con()
	    # Iterate over JSON Objects
        for i in signature_list['signature_list']:
            try:
                smud = TcpSig(i)
                PassiveData.signature_insert(conn, smud)
            except Exception as e:
                print(e)
        return True

def verify_signatures():
    '''Verifies that signature db file exists.'''
    exists = os.path.exists('signature.db')
    return exists

def read_pcap(args):
    '''Read packet capture from file and SMUDGE.'''
    # Verify Pause
    pause = verify_pause(args['pause'])
    if args['colored_text']:
        text = False
    else:
        text = True
    print("--- SMUDGE an Open Source Project by Active Countermeasures ---")
    print("\n[+] Reading Packets from PCAP file: " + str(args['read']))
    print("[+] Pause between signature matches: " + str(pause))
    print("[+] Entering main event loop.\n")
    packets = sniff(offline=args['read'], filter='tcp[tcpflags] == tcp-syn')
    for packet in packets:
        time.sleep(pause)
        try:
            packet_signature = Signature(packet)
            mo = Matching.match(packet_signature)
            dev_out = "Signature Identified for: {IP} --> {signature}".format(IP=packet['IP'].src, signature=str(packet_signature))
            try:
                os = mo[1][0][2]
                certainty = mo[0]
            except:
                os = "No signature match on file."
                certainty = ""
            segway = str(packet['IP'].src) + "/"  + str(packet['IP'].sport) + " -> " + str(packet['IP'].dst) + "/" + str(packet['IP'].dport)
            cprint(text, "\n\n.-[ " +  segway + " ]-")
            mprint(text, "|")
            mprint(text, "| client = " + str(packet['IP'].src) + "/"  + str(packet['IP'].sport))
            mprint(text, "| os = " + os)
            mprint(text, "| certainty = " + certainty)
            mprint(text, "| dist = " + str(calculate_dist(packet['IP'].ttl)))
            mprint(text, "| raw_sig = " + str(packet_signature))
            mprint(text, "|")
            mprint(text, "`----")
        except:
            pass
    return True


def handle_packet(packet):
    '''Read packet capture from file and SMUDGE.'''
    global text
    out = ""
    if packet.haslayer("TCP"):
        if 'S' in str(packet['TCP'].flags):
            try:
                packet_signature = Signature(packet)
                mo = Matching.match(packet_signature)
                dev_out = "Signature Identified for: {IP} --> {signature}".format(IP=packet['IP'].src, signature=str(packet_signature))
                try:
                    os = mo[1][0][2]
                    certainty = mo[0]
                except:
                    os = "No signature match on file."
                    certainty = ""
                segway = str(packet['IP'].src) + "/"  + str(packet['IP'].sport) + " -> " + str(packet['IP'].dst) + "/" + str(packet['IP'].dport)
                cprint(text, "\n\n.-[ " +  segway + " ]-")
                mprint(text, "|")
                mprint(text, "| client = " + str(packet['IP'].src) + "/"  + str(packet['IP'].sport))
                mprint(text, "| os = " + os)
                mprint(text, "| certainty = " + certainty)
                mprint(text, "| dist = " + str(calculate_dist(packet['IP'].ttl)))
                mprint(text, "| raw_sig = " + str(packet_signature))
                mprint(text, "|")
                mprint(text, "`----")
            except:
                cprint(text, "No signature match on file.")
                print("raw_sig = " + str(packet_signature))
    return None


#======== Main ========#
def main():
    '''Main'''
    global text
    signal(SIGINT, handler)
    # Argparse Arguments
    parser = argparse.ArgumentParser(prog='smudge', description='SMUDGE passive OS detection based on SYN packets without Transmitting any Data.')
    parser.add_argument('-c', '--colored-text', help='Disable colored text output.', action='store_true', required=False)
    parser.add_argument('-d', '--database', help='Disable local SQlite db creation.', action='store_true', required=False)
    parser.add_argument('-i','--interface', type=str, help='Interface that traffic will be sniffed on.', required=False)
    parser.add_argument('-l', '--list', help='Lists available interfaces.', action='store_true', required=False)
    parser.add_argument('-p', '--pause', type= str, help='Decimal value of the pause inbetween signature matches.', action='store', required=False)
    parser.add_argument('-r','--read', action='store', type=str, help='PCAP file that will be read by SMUDGE.', required=False)
    args = vars(parser.parse_args())
    
    # List Interfaces Argument
    list_interfaces(args['list'])
    
    # If not disabled via flag, create sqlite database and import signatures.  
    import_signatures(args['database'])

    # Verify that Signatures Exist
    if not verify_signatures():
        sys.exit("No signature.db file exists. Please run SMUDGE without the -d flag to generate one.")

    # Verify Colored Text
    if args['colored_text']:
        text = False
    else:
        colored_text()
        text = True
        

    # Read PCAP if flag supplied
    if args['read']:
        if os.path.exists(args['read']):
            read_pcap(args)
        else:
            sys.exit('PCAP File does not exist.')

    # Sniff
    if not args['read']:
        pause = verify_pause(args['pause'])
        interface = verify_interface(args['interface'])  
        print("--- SMUDGE an Open Source Project by Active Countermeasures ---")
        print("\n[+] Reading Packets from interface: " + str(interface))
        print("[+] Pause between signature matches: " + str(pause))
        print("[+] Entering main event loop.\n")
        try:
            sniff(prn=handle_packet, filter='tcp[tcpflags] == tcp-syn', iface=interface)
        except PermissionError:
            sys.exit("Sniffing on specified interfaces requires additional privilege.")
    return True



#======== Smudge has entered the chat. ========#
if __name__ == '__main__':
    main()
