"""
Command Line Utils
"""
import sys
import os
import time
import netifaces
from scapy.all import sniff
from smudge.utils import PassiveData
from smudge.utils import Signature
from smudge.utils import PullData
from smudge.utils import TcpSig
from smudge.utils import Matching

try:
    from colorama import Fore
    from colorama import Style
except ImportError:
    print("Color text is not available on this platform.")


class CommandLineUtility():
    """
    The utility methods needed for the command line tool reside here.
    """

    @staticmethod
    def cprint(out):
        '''If enabled, prints main colored output.'''
        if "colorama" in sys.modules:
            print(Fore.CYAN + out)
            print(Style.RESET_ALL)
        else:
            print(out)
        return True

    @staticmethod
    def mprint(out):
        '''If enabled, prints secondary colored output.'''
        if "colorama" in sys.modules:
            print(Fore.MAGENTA + out)
            print(Style.RESET_ALL)
        else:
            print(out)
        return True

    @staticmethod
    def calculate_dist(time_to_live):
        '''Takes a value of TTL and calculates hop distance.'''
        try:
            if time_to_live > 128:
                dist = 255 - time_to_live
            elif 64 < time_to_live < 129:
                dist = 128 - time_to_live
            elif 32 < time_to_live < 65:
                dist = 64 - time_to_live
            elif 0 < time_to_live < 33:
                dist = 32 - time_to_live
            else:
                dist = -1
        except TypeError:
            dist = -1
        except ValueError:
            dist = -1
        return dist

    @staticmethod
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
        return flo

    @staticmethod
    def verify_interface(interface):
        '''Verify interface argument is valid.'''
        interfaces = netifaces.interfaces()
        if interface not in interfaces:
            interface = ''
        return interface

    @staticmethod
    def list_interfaces(argument):
        '''List all available Network Interfaces.'''
        if argument:
            interfaces = netifaces.interfaces()
            print("Available Interfaces: ")
            for i in interfaces:
                print("\t" + i)
            sys.exit(0)
        else:
            return True

    @staticmethod
    def import_signatures(argument):
        '''Import Signatures from Github'''
        # Get Signatures from Github
        if not argument:
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
                except TypeError as except_value:
                    print(except_value)
                except ValueError as except_value:
                    print(except_value)
        return True

    @staticmethod
    def verify_signatures():
        '''Verifies that signature db file exists.'''
        exists = os.path.exists('signature.db')
        return exists

    @staticmethod
    def read_pcap(args):
        '''Read packet capture from file and SMUDGE.'''
        # Verify Pause
        pause = CommandLineUtility.verify_pause(args['pause'])
        print("--- SMUDGE an Open Source Project by Active Countermeasures ---")
        print("\n[+] Reading Packets from PCAP file: " + str(args['read']))
        print("[+] Pause between signature matches: " + str(pause))
        print("[+] Entering main event loop.\n")
        packets = sniff(offline=args['read'], filter='tcp[tcpflags] == tcp-syn')
        for packet in packets:
            time.sleep(pause)
            try:
                packet_signature = Signature(packet)
                match_object = Matching.match(packet_signature)
                try:
                    operating_system = match_object[1][0][2]
                    certainty = match_object[0]
                except TypeError:
                    operating_system = "No signature match on file."
                    certainty = ""
                except ValueError:
                    operating_system = "No signature match on file."
                    certainty = ""
                seg_1 = str(packet['IP'].src)
                seg_2 = str(packet['IP'].sport)
                seg_3 = str(packet['IP'].dst)
                seg_4 = str(packet['IP'].dport)
                seg_5 = str(CommandLineUtility.calculate_dist(packet['IP'].ttl))
                segway =  seg_1 + "/"  + seg_2 + " -> " + seg_3 + "/" + seg_4
                CommandLineUtility.cprint("\n\n.-[ " +  segway + " ]-")
                CommandLineUtility.mprint("|")
                CommandLineUtility.mprint("| client = " + seg_1 + "/"  + seg_2)
                CommandLineUtility.mprint("| os = " + operating_system)
                CommandLineUtility.mprint("| certainty = " + certainty)
                CommandLineUtility.mprint("| dist = " + seg_5)
                CommandLineUtility.mprint("| raw_sig = " + str(packet_signature))
                CommandLineUtility.mprint("|")
                CommandLineUtility.mprint("`----")
            except ValueError:
                pass
            except TypeError:
                pass
        return True

    @staticmethod
    def handle_packet(packet):
        '''Read packet capture from file and SMUDGE.'''
        if packet.haslayer("TCP"):
            if 'S' in str(packet['TCP'].flags):
                try:
                    packet_signature = Signature(packet)
                    match_object = Matching.match(packet_signature)
                    try:
                        operating_system = match_object[1][0][2]
                        certainty = match_object[0]
                    except ValueError:
                        operating_system = "No signature match on file."
                        certainty = ""
                    except TypeError:
                        operating_system = "No signature match on file."
                        certainty = ""
                    seg_1 = str(packet['IP'].src)
                    seg_2 = str(packet['IP'].sport)
                    seg_3 = str(packet['IP'].dst)
                    seg_4 = str(packet['IP'].dport)
                    seg_5 = str(CommandLineUtility.calculate_dist(packet['IP'].ttl))
                    segway = seg_1 + "/"  + seg_2 + " -> " + seg_3 + "/" + seg_4
                    CommandLineUtility.cprint("\n\n.-[ " +  segway + " ]-")
                    CommandLineUtility.mprint("|")
                    CommandLineUtility.mprint("| client = " + seg_1 + "/"  + seg_2)
                    CommandLineUtility.mprint("| os = " + operating_system)
                    CommandLineUtility.mprint("| certainty = " + certainty)
                    CommandLineUtility.mprint("| dist = " + seg_5)
                    CommandLineUtility.mprint("| raw_sig = " + str(packet_signature))
                    CommandLineUtility.mprint("|")
                    CommandLineUtility.mprint("`----")
                except ValueError:
                    CommandLineUtility.cprint("No signature match on file.")
                    print("raw_sig = " + str(packet_signature))
                except TypeError:
                    CommandLineUtility.cprint("No signature match on file.")
                    print("raw_sig = " + str(packet_signature))
