"""
Signature Matching
"""

import sqlite3
from os.path import exists
import urllib.request
import json

class Quirk:
    """
    Creates quirks - comma-delimited properties and quirks observed in IP or TCP headers.
        If a signature scoped to both IPv4 and IPv6 contains quirks valid
            for just one of these protocols, such quirks will be ignored for
            on packets using the other protocol. For example, any combination
            of 'df', 'id+', and 'id-' is always matched by any IPv6 packet.
    """

    def __init__(self, packet):
        '''Takes a packet as an argument.'''
        self.packet = packet

    def __str__(self):
        return self.qstring

    @property
    def df_flag(self):
        '''Sets df attribute based on flag -
            "don't fragment" set (probably PMTUD);
            ignored for IPv6.
        '''
        version = self.packet.version
        if version == 6:
            df_flag = False
        else:
            if 'DF' in self.packet['IP'].flags.names:
                df_flag = 'df'
        return df_flag

    @property
    def id_plus(self):
        '''Sets id+ attribute based on flag and IPID -
           DF set but IPID non-zero;
           ignored for IPv6.
        '''
        version = self.packet.version
        if version == 6:
            id_plus = False
        else:
            id_plus = False
            if self.packet['IP'].flags =='DF' and self.packet['IP'].id != 0:
                id_plus = 'id+'
        return id_plus

    @property
    def id_minus(self):
        '''
        Sets id- attribute based on flag and IPID -
        DF not set but IPID is zero; ignored for IPv6.
        '''
        version = self.packet.version
        if version == 6:
            id_minus = False
        else:
            id_minus = False
            if self.packet['IP'].flags =='DF' and self.packet['IP'].id == 0:
                id_minus = 'id-'
        return id_minus

    @property
    def ecn(self):
        '''Sets ecn attribute - explicit congestion notification support.'''
        ecn = False
        if 'E' in self.packet['TCP'].flags:
            ecn = 'ecn'
        return ecn

    @property
    def zero_plus(self):
        '''Sets 0+ Attribute -  "must be zero" field not zero; ignored for IPv6.'''
        version = self.packet.version
        if version == 6:
            zero_plus = False
        else:
            zero_plus = False
            if self.packet.reserved != 0:
                zero_plus = '0+'
        return zero_plus

    @property
    def flow(self):
        '''Sets flow Attribute - non-zero IPv6 flow ID; ignored for IPv4.'''
        #TODO IPv6 support
        flow = False
        return flow

    @property
    def seq_minus(self):
        '''Sets seq- attribute - sequence number is zero.'''
        seq_minus = False
        if self.packet['TCP'].seq == 0:
            seq_minus = 'seq-'
        return seq_minus

    @property
    def ack_plus(self):
        '''Sets ack+ - ACK number is non-zero, but ACK flag not set.'''
        ack_plus = False
        if self.packet['TCP'].ack != 0:
            ack_plus = 'ack+'
        return ack_plus

    @property
    def ack_minus(self):
        '''Sets ack- - ACK number is zero, but ACK flag set.'''
        ack_minus = False
        if self.packet['TCP'].ack == 0:
            ack_minus = 'ack-'
        return ack_minus

    @property
    def uptr_plus(self):
        '''Sets uptr+ attribute - URG pointer is non-zero, but URG flag not set.'''
        uptr_plus = 'uptr+'
        return uptr_plus

    @property
    def urgf_plus(self):
        '''Sets urgf+ attribute - URG flag used.'''
        urgf_plus = False
        if 'URG' in self.packet['IP'].flags:
            urgf_plus = 'urgf+'
        return urgf_plus

    @property
    def pushf_plus(self):
        '''Sets pushf+ attribute - PUSH flag used.'''
        pushf_plus = False
        if 'PUSH' in self.packet['IP'].flags:
            pushf_plus = 'pushf+'
        return pushf_plus

    @property
    def ts1_minus(self):
        '''Sets ts1- attribute - own timestamp specified as zero.'''
        ts1_minus = False
        try:
            ts1 = dict(self.packet['TCP'].options)
            if ts1['Timestamp'][0] == 0:
                ts1_minus = 'T0'
        except TypeError:
            pass
        return ts1_minus

    @property
    def ts2_plus(self):
        '''Sets ts2+ attribute - non-zero peer timestamp on initial SYN.'''
        ts2_plus = False
        try:
            ts2 = dict(self.packet['TCP'].options)
            if ts2['Timestamp'][1] != 0:
                ts2_plus = 'T'
        except TypeError:
            pass
        return ts2_plus

    #TODO
    @property
    def opt_plus(self):
        '''Sets opt+ attribute - trailing non-zero data in options segment.'''
        opt_plus = False
        return opt_plus

    @property
    def exws(self):
        '''Sets exws attribute - excessive window scaling factor (> 14).'''
        try:
            exws = dict(self.packet['TCP'].options)
        except TypeError:
            exws = False
        if exws is not False:
            try:
                exws = exws['WScale'] >= 14
            except TypeError:
                exws = False
        return exws

    #TODO
    @property
    def bad(self):
        '''Sets bad attribute - malformed TCP options.'''
        bad = isinstance(self.packet['TCP'].options, list)
        bad = False
        return bad

    @property
    def qstring(self):
        '''Looks at all attributes and makes quirks.'''
        items = [
                self.df_flag, self.id_plus, self.id_minus,
                self.ecn, self.zero_plus, self.flow,
                self.seq_minus, self.ack_plus, self.ack_minus,
                self.uptr_plus, self.pushf_plus, self.ts1_minus,
                self.ts2_plus, self.opt_plus, self.exws,
                self.bad
                ]
        quirks = [item for item in items if item is not False]
        quirks = ",".join(quirks)
        return quirks


class Signature:
    """
    Data mapping class that takes a TCP Signature object and inserts it into the sqlite database.
    """
    def __init__(self, packet):
        self.packet = packet

    @staticmethod
    def process_options(option: list) -> str:
        '''Static method for processing options.'''
        option_zero = option[0]
        option_one = option[1]
        if option_zero == 'MSS' and (option_one == 0 or option_one == ''):
            options_output = 'M*'
        elif option_zero == 'MSS' and option_one > 1:
            options_output = 'M' + str(option_one)
        elif option_zero == 'NOP':
            options_output = 'N'
        elif option_zero == 'WScale':
            options_output= 'W' + str(option_one)
        elif option_zero == 'SAckOK':
            options_output = 'S'
        elif option_zero == 'EOL':
            options_output = 'E'
        else:
            # TODO
            # The p0f docs state:
            #  ?n     - unknown option ID n
            # What does that even mean?
            # Then to make things even more vague
            # some random documentation on cert.org states:
            #  ?n       - unrecognized option number n.
            # Soooooo, unrecognized != unknown
            # I came up with the following and the output does not look correct. \
            # We went with literally returning '?n'
            # return '?' + str(option[1])
            options_output = '?n'
        return options_output

    @property
    def version(self):
        '''Signature for IPv4 ('4'), IPv6 ('6'), or both ('*').'''
        version = self.packet.version
        return str(version)

    @property
    def ittl(self):
        '''
        Initial TTL used by the OS. Almost all operating systems use
        64, 128, or 255; ancient versions of Windows sometimes used
        32, and several obscure systems sometimes resort to odd values
        such as 60.

        NEW SIGNATURES: P0f will usually suggest something, using the
        format of 'observed_ttl+distance' (e.g. 54+10). Consider using
        traceroute to check that the distance is accurate, then sum up
        the values. If initial TTL can't be guessed, p0f will output
        'nnn+?', and you need to use traceroute to estimate the '?'.

        A handful of userspace tools will generate random TTLs. In these
        cases, determine maximum initial TTL and then add a - suffix to
        the value to avoid confusion.
        '''
        if self.version == '4':
            ittl = self.p['IP'].ttl
        elif self.version == '6':
            ittl = self.p['IPv6'].ttl
        else:
            ittl = ''
        return ittl

    @property
    def olen(self):
        '''
        Length of IPv4 options or IPv6 extension headers. Usually zero
        for normal IPv4 traffic; always zero for IPv6 due to the
        limitations of libpcap.
        '''
        if self.version == '4':
            olen = len(self.p['IP'].options)
        elif self.version == '6':
            olen = len(self.p['IPv6'].options)
        else:
            olen = ''
        return str(olen)

    @property
    def mss(self):
        '''
        maximum segment size, if specified in TCP options. Special value
        of '*' can be used to denote that MSS varies depending on the
        parameters of sender's network link, and should not be a part of
        the signature. In this case, MSS will be used to guess the
        type of network hookup according to the [mtu] rules.

        NEW SIGNATURES: Use '*' for any commodity OSes where MSS is
        around 1300 - 1500, unless you know for sure that it's fixed.
        If the value is outside that range, you can probably copy it
        literally.
        '''
        mss = dict(self.packet['TCP'].options)
        try:
            return str(mss['MSS'])
        except KeyError:
            return '*'

    @property
    def window_size(self):
        '''
        Window size. Can be expressed as a fixed value, but many
        operating systems set it to a multiple of MSS or MTU, or a
        multiple of some random integer. P0f automatically detects these
        cases, and allows notation such as 'mss*4', 'mtu*4', or '%8192'
        to be used. Wilcard ('*') is possible too.
        '''
        window_size = self.packet['TCP'].window
        if self.mss != '*':
            if (self.packet['TCP'].window / int(self.mss)).is_integer():
                window_size = "mss*" + str(int(self.packet['TCP'].window / int(self.mss)))
        return str(window_size)

    @property
    def scale(self):
        '''
        Window scaling factor, if specified in TCP options. Fixed value
        or '*'.
        NEW SIGNATURES: Copy literally, unless the value varies randomly.
        Many systems alter between 2 or 3 scaling factors, in which case,
        it's better to have several 'sig' lines, rather than a wildcard.
        '''
        options = dict(self.packet['TCP'].options)
        try:
            scale = options['WScale']
        except TypeError:
            scale = '*'
        return scale

    @property
    def olayout(self):
        '''
        comma-delimited layout and ordering of TCP options, if any. This
        is one of the most valuable TCP fingerprinting signals. Supported
        values.
        '''
        if len(self.packet['TCP'].options) == 0:
            olayout = '*'
        else:
            loo = []
            for i in self.packet['TCP'].options:
                loo.append(Signature.process_options(i))
            olayout = ','.join(map(str, loo))
        return olayout

    @property
    def quirk(self):
        '''
        Comma-delimited properties and quirks observed in IP or TCP
        headers.
        '''
        Quirks = Quirk(self.packet)
        return str(Quirks)

    @property
    def pclass(self):
        '''
        Payload size classification: '0' for zero, '+' for non-zero,
        '*' for any. The packets we fingerprint right now normally have
        no payloads, but some corner cases exist.
        '''
        pclass = len(self.packet['TCP'].payload)
        if pclass != 0:
            pclass = '+'
        return str(pclass)

    @property
    def qstring(self):
        '''Create Query String'''
        qstring = f"{self.version}:"\
        + f"{self.ittl}:{self.olen}:{self.mss}:"\
        + f"{self.window_size}:{self.scale}:"\
        + f"{self.olayout}:{self.quirk}:{self.pclass}"
        return qstring

    def __str__(self):
        return self.qstring



class Matching():
    """This class be matching."""

    @staticmethod
    def create_con():
        '''Create Database Connection'''
        return sqlite3.connect('signature.db')

    @staticmethod
    def sig_match_one(conn, sig_obj):
        '''Select 100%'''
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM signatures WHERE version=? AND ittl=?\
            AND olen=? AND mss=? AND wsize=? AND scale=?\
            AND olayout=? AND quirks=? AND pclass=?",
            [sig_obj.version, sig_obj.ittl, sig_obj.olen, sig_obj.mss,\
            sig_obj.window_size,sig_obj.scale, sig_obj.olayout,\
            sig_obj.quirk, sig_obj.pclass]
            )
        signature_matches = cur.fetchall()
        if len(signature_matches) == 0:
            signature_matches = None
        return signature_matches

    @staticmethod
    def sig_match_eighty(conn, so):
        '''Select 80%'''
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM signatures WHERE version=?\
            AND ittl=? AND olen=? AND mss=? AND wsize=?\
            AND scale=? AND olayout=? AND pclass=?",
            [so.version, so.ittl, so.olen, so.mss, so.window_size, so.scale, so.olayout, so.pclass]
            )
        signature_matches = cur.fetchall()
        if len(signature_matches) == 0:
            signature_matches = None
        return signature_matches

    @staticmethod
    def sig_match_sixty(conn, so):
        '''Select 60%'''
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM signatures WHERE version=?\
            AND ittl=? AND olen=? AND wsize=?\
            AND scale=? AND olayout=?",
            [so.version, so.ittl, so.olen, so.window_size, so.scale, so.olayout]
            )
        signature_matches = cur.fetchall()
        if len(signature_matches) == 0:
            signature_matches = None
        return signature_matches

    @staticmethod
    def sig_match_fourty(conn, so):
        '''Select 40%'''
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM signatures WHERE version=? AND ittl=? AND olen=? AND olayout=?",
            [so.version, so.ittl, so.olen, so.olayout]
            )
        signature_matches = cur.fetchall()
        if len(signature_matches) == 0:
            signature_matches = None
        return signature_matches

    @staticmethod
    def sig_match_twenty(conn, so):
        '''Select 20%'''
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM signatures WHERE version=? AND ittl=? AND olen=?",
            [so.version, so.ittl, so.olen]
            )
        signature_matches = cur.fetchall()
        if len(signature_matches) == 0:
            signature_matches = None
        return signature_matches


    @staticmethod
    def match(signature_obj):
        '''Match.'''
        conn = Matching.create_con()
        results = ''
        one_hundred = Matching.sig_match_one(conn, signature_obj)
        if one_hundred:
            results = ('100%', one_hundred)
        if results == '':
            eighty = Matching.sig_match_eighty(conn, signature_obj)
            if eighty:
                results = ('80%', eighty)
        if results == '':
            sixty = Matching.sig_match_sixty(conn, signature_obj)
            if sixty:
                results = ('60%', sixty)
        if results == '':
            fourty = Matching.sig_match_fourty(conn, signature_obj)
            if fourty:
                results = ('40%', fourty)
        if results == '':
            twenty = Matching.sig_match_twenty(conn, signature_obj)
            if twenty:
                results = ('20%', twenty)
        if results == '':
            results = ('0%', signature_obj)
        conn.close()
        return results



class QueryObject():
    """
    Data mapping class that takes a TCP Signature object and inserts it into the sqlite database.
    """

    def __init__(self,
                    acid, platform, tcp_flag, comments, version, ittl,
                     olen, mss, wsize, scale, olayout, quirks, pclass
                ):
        self.sig_acid = acid
        self.platform = platform
        self.sig_tcp_flag = tcp_flag
        self.sig_comments = comments
        self.version = version
        self.ittl = ittl
        self.olen = olen
        self.mss = mss
        self.wsize = wsize
        self.scale = scale
        self.olayout = olayout
        self.quirks = quirks
        self.pclass = pclass

    @property
    def qstring(self):
        '''Query String.'''
        qstring = f"{self.version}:{self.ittl}:{self.olen}\
        :{self.mss}:{self.wsize}:{self.scale}\
        :{self.olayout}:{self.quirks}:{self.pclass}"
        return qstring

    def __str__(self):
        return self.qstring


class PassiveData:
    """
    A class filled with static methods that interacts with the sqlite database.
    """

    @staticmethod
    def test_github_con():
        '''Tests Internet Connection to Github.com'''
        test_result = urllib.request.urlopen("https://www.github.com").getcode()
        return bool(test_result == 200)


    @staticmethod
    def create_con():
        '''Create Database Connection'''
        return sqlite3.connect('signature.db')


    @staticmethod
    def setup_db():
        '''Create Sqlite3 DB with all required tables'''
        if exists('signature.db'):
            pass
        else:
            with open('signature.db', 'x') as f_p:
                pass
            conn = sqlite3.connect('signature.db')
            # Create Signatures Table
            conn.execute('''CREATE TABLE "signatures" (
	        "id"	INTEGER NOT NULL UNIQUE,
	        "acid"	INTEGER UNIQUE,
	        "platform"  TEXT,
            "tcp_flag"	TEXT,
	        "version"	TEXT NOT NULL,
	        "ittl"	TEXT,
	        "olen"	TEXT,
	        "mss"	TEXT,
	        "wsize"	TEXT,
	        "scale"	TEXT,
	        "olayout"	TEXT,
	        "quirks"	TEXT,
	        "pclass"	TEXT,
	        "comments"	TEXT,
	        PRIMARY KEY("id" AUTOINCREMENT)
            );''')
            conn.close()
        return True

    @staticmethod
    def signature_insert(conn, sig_obj):
        '''Insert Statement for the Signature Table.'''
        entry = conn.execute('SELECT id FROM signatures WHERE (acid=?)', (sig_obj.sig_acid,))
        entry = entry.fetchone()
        if entry is None:
            conn.execute("insert into signatures\
            (acid, platform, tcp_flag, version,\
            ittl, olen, mss, wsize,\
            scale, olayout, quirks, pclass,\
            comments) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (sig_obj.sig_acid, sig_obj.platform, sig_obj.sig_tcp_flag, sig_obj.version,\
            sig_obj.ittl, sig_obj.olen, sig_obj.mss, sig_obj.wsize, sig_obj.scale,\
            sig_obj.olayout, sig_obj.quirks, sig_obj.pclass, sig_obj.sig_comments))
            conn.commit()
        return True



class PullData:
    """
    A class that contains a method that:
        * Loads a json file from github into memory.
        * Dumps the json into the sqlite database.

    The use of class methods is used so that class variables can be overrided for testing.
    ...

    Class Variables
    ----------
    url : str
        URL of raw json file that contains TCP Signatures.
    """


    url = "https://raw.githubusercontent.com/activecm/tcp-sig-json/testing-data/tcp-sig.json"

    @classmethod
    def import_data(cls):
        """Imports TCP Signatures from raw JSON file hosted on Github."""
        with urllib.request.urlopen(cls.url) as f_p:
            data = json.load(f_p)
            return data

    @classmethod
    def import_local_data(cls, json_file):
        """Imports TCP Signatures from local raw JSON file."""
        with open(json_file) as f_p:
            data = json.load(f_p)
            return data

class TcpSig:
    """
    Data mapping class that takes a TCP Signature object and inserts it into the sqlite database.
    """

    def __init__(self, tcp_sig_obj):
        self.sig_acid = tcp_sig_obj['acid']
        self.platform = tcp_sig_obj['platform']
        self.sig_tcp_flag = tcp_sig_obj['tcp_flag']
        self.sig_comments = tcp_sig_obj['comments']
        self.signature = dict(
            zip(
                ['version', 'ittl', 'olen', 'mss', 'wsize', 'scale', 'olayout', 'quirks', 'pclass'],
                tcp_sig_obj['tcp_sig'].split(':')
                )
            )
        self.version = self.signature['version']
        self.ittl = self.signature['ittl']
        self.olen = self.signature['olen']
        self.mss = self.signature['mss']
        self.wsize = self.signature['wsize']
        self.scale = self.signature['scale']
        self.olayout = self.signature['olayout']
        self.quirks = self.signature['quirks']
        self.pclass = self.signature['pclass']

    @property
    def qstring(self):
        """QString."""
        qstring = f"{self.version}:\
            {self.ittl}:{self.olen}:{self.mss}:\
            {self.wsize}:{self.scale}:{self.olayout}:\
            {self.quirks}:{self.pclass}"
        return qstring

    def __str__(self):
        return self.qstring
