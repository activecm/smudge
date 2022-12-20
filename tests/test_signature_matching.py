"""Smudge Test module for Signature class"""
import pytest
from scapy.all import sniff
from smudge import Signature

pcap_file = "test.pcap"

def test_signature_1():
    '''Signature.'''
    packet_1 = sniff(offline=pcap_file)[0]
    signature_1 = Signature(packet_1)
    assert signature_1.version == str(4)

def test_process_options():
    '''Pytest for Process Options static method.'''
    packet_1 = sniff(offline=pcap_file)[0]
    signature_1 = Signature.process_options(packet_1)
    assert signature_1 == '?n'

def test_version():
    '''Pytest for Version property.'''
    packet_1 = sniff(offline=pcap_file)[0]
    signature_1 = Signature(packet_1).version
    assert signature_1 == '4'