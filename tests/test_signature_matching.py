"""Smudge Test module for Signature class"""
from scapy.all import sniff
from smudge import Signature


def test_signature_1():
    '''Signature.'''
    packet_1 = sniff(offline="passer.pcap")[0]
    signature_1 = Signature(packet_1)
    assert signature_1.version == str(4)
