""" SMUDGE """

import unittest
from scapy.all import sniff

from smudge import Signature

class SignatureMatchingTestcase(unittest.TestCase):
    """Testing Signatures."""
    def test_signature_1(self):
        '''Signature.'''
        packet_1 = sniff(offline="smudge/tests/test.pcap")[0]
        signature_1 = Signature(packet_1)
        self.assertTrue(signature_1.version == str(4))
