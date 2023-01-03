Color text is not available on this platform.
Color text is not available on this platform.
---
description: |
    API documentation for modules: __init__, __main__, __version__, command_line, utils, test_passive, test_signature_matching.

lang: en

classoption: oneside
geometry: margin=1in
papersize: a4

linkcolor: blue
links-as-notes: true
...


    
# Module `__init__` {#id}

Smudge init file.







    
# Module `__main__` {#id}









    
# Module `__version__` {#id}

SMUDGE module listing versions.







    
# Module `command_line` {#id}

Command Line Utils





    
## Classes


    
### Class `CommandLineUtility` {#id}




>     class CommandLineUtility


The utility methods needed for the command line tool reside here.






    
#### Static methods


    
##### `Method calculate_dist` {#id}




>     def calculate_dist(
>         time_to_live
>     )


Takes a value of TTL and calculates hop distance.

    
##### `Method cprint` {#id}




>     def cprint(
>         out
>     )


If enabled, prints main colored output.

    
##### `Method handle_packet` {#id}




>     def handle_packet(
>         packet
>     )


Read packet capture from file and SMUDGE.

    
##### `Method import_signatures` {#id}




>     def import_signatures(
>         argument
>     )


Import Signatures from Github

    
##### `Method list_interfaces` {#id}




>     def list_interfaces(
>         argument
>     )


List all available Network Interfaces.

    
##### `Method mprint` {#id}




>     def mprint(
>         out
>     )


If enabled, prints secondary colored output.

    
##### `Method read_pcap` {#id}




>     def read_pcap(
>         args
>     )


Read packet capture from file and SMUDGE.

    
##### `Method verify_interface` {#id}




>     def verify_interface(
>         interface
>     )


Verify interface argument is valid.

    
##### `Method verify_pause` {#id}




>     def verify_pause(
>         flo
>     )


Verify pause argument is between 0 and 1.

    
##### `Method verify_signatures` {#id}




>     def verify_signatures()


Verifies that signature db file exists.




    
# Module `utils` {#id}

Signature Matching





    
## Classes


    
### Class `Matching` {#id}




>     class Matching


This class be matching.






    
#### Static methods


    
##### `Method create_con` {#id}




>     def create_con()


Create Database Connection

    
##### `Method match` {#id}




>     def match(
>         signature_obj
>     )


Match.

    
##### `Method sig_match_eighty` {#id}




>     def sig_match_eighty(
>         conn,
>         signature_options
>     )


Select 80%

    
##### `Method sig_match_fourty` {#id}




>     def sig_match_fourty(
>         conn,
>         signature_options
>     )


Select 40%

    
##### `Method sig_match_one` {#id}




>     def sig_match_one(
>         conn,
>         sig_obj
>     )


Select 100%

    
##### `Method sig_match_sixty` {#id}




>     def sig_match_sixty(
>         conn,
>         signature_options
>     )


Select 60%

    
##### `Method sig_match_twenty` {#id}




>     def sig_match_twenty(
>         conn,
>         signature_options
>     )


Select 20%


    
### Class `PassiveData` {#id}




>     class PassiveData


A class filled with static methods that interacts with the sqlite database.






    
#### Static methods


    
##### `Method create_con` {#id}




>     def create_con()


Create Database Connection

    
##### `Method setup_db` {#id}




>     def setup_db()


Create Sqlite3 DB with all required tables

    
##### `Method signature_insert` {#id}




>     def signature_insert(
>         conn,
>         sig_obj
>     )


Insert Statement for the Signature Table.

    
##### `Method test_github_con` {#id}




>     def test_github_con()


Tests Internet Connection to Github.com


    
### Class `PullData` {#id}




>     class PullData


A class that contains a method that:
    * Loads a json file from github into memory.
    * Dumps the json into the sqlite database.

The use of class methods is used so that class variables can be overrided for testing.
...

#### Class Variables

url : str
    URL of raw json file that contains TCP Signatures.




    
#### Class variables


    
##### Variable `url` {#id}








    
#### Static methods


    
##### `Method import_data` {#id}




>     def import_data()


Imports TCP Signatures from raw JSON file hosted on Github.

    
##### `Method import_local_data` {#id}




>     def import_local_data(
>         json_file
>     )


Imports TCP Signatures from local raw JSON file.


    
### Class `QueryObject` {#id}




>     class QueryObject(
>         acid,
>         platform,
>         tcp_flag,
>         comments,
>         version,
>         ittl,
>         olen,
>         mss,
>         wsize,
>         scale,
>         olayout,
>         quirks,
>         pclass
>     )


Data mapping class that takes a TCP Signature object and inserts it into the sqlite database.





    
#### Instance variables


    
##### Variable `qstring` {#id}




Query String.



    
### Class `Quirk` {#id}




>     class Quirk(
>         packet
>     )


Creates quirks - comma-delimited properties and quirks observed in IP or TCP headers.
    If a signature scoped to both IPv4 and IPv6 contains quirks valid
        for just one of these protocols, such quirks will be ignored for
        on packets using the other protocol. For example, any combination
        of 'df', 'id+', and 'id-' is always matched by any IPv6 packet.

Takes a packet as an argument.





    
#### Instance variables


    
##### Variable `ack_minus` {#id}




Sets ack- - ACK number is zero, but ACK flag set.

    
##### Variable `ack_plus` {#id}




Sets ack+ - ACK number is non-zero, but ACK flag not set.

    
##### Variable `bad` {#id}




Sets bad attribute - malformed TCP options.

    
##### Variable `df_flag` {#id}




Sets df attribute based on flag -
"don't fragment" set (probably PMTUD);
ignored for IPv6.

    
##### Variable `ecn` {#id}




Sets ecn attribute - explicit congestion notification support.

    
##### Variable `exws` {#id}




Sets exws attribute - excessive window scaling factor (> 14).

    
##### Variable `flow` {#id}




Sets flow Attribute - non-zero IPv6 flow ID; ignored for IPv4.

    
##### Variable `id_minus` {#id}




Sets id- attribute based on flag and IPID -
DF not set but IPID is zero; ignored for IPv6.

    
##### Variable `id_plus` {#id}




Sets id+ attribute based on flag and IPID -
DF set but IPID non-zero;
ignored for IPv6.

    
##### Variable `opt_plus` {#id}




Sets opt+ attribute - trailing non-zero data in options segment.

    
##### Variable `pushf_plus` {#id}




Sets pushf+ attribute - PUSH flag used.

    
##### Variable `qstring` {#id}




Looks at all attributes and makes quirks.

    
##### Variable `seq_minus` {#id}




Sets seq- attribute - sequence number is zero.

    
##### Variable `ts1_minus` {#id}




Sets ts1- attribute - own timestamp specified as zero.

    
##### Variable `ts2_plus` {#id}




Sets ts2+ attribute - non-zero peer timestamp on initial SYN.

    
##### Variable `uptr_plus` {#id}




Sets uptr+ attribute - URG pointer is non-zero, but URG flag not set.

    
##### Variable `urgf_plus` {#id}




Sets urgf+ attribute - URG flag used.

    
##### Variable `zero_plus` {#id}




Sets 0+ Attribute -  "must be zero" field not zero; ignored for IPv6.



    
### Class `Signature` {#id}




>     class Signature(
>         packet
>     )


Data mapping class that takes a TCP Signature object and inserts it into the sqlite database.





    
#### Instance variables


    
##### Variable `ittl` {#id}




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

    
##### Variable `mss` {#id}




maximum segment size, if specified in TCP options. Special value
of '*' can be used to denote that MSS varies depending on the
parameters of sender's network link, and should not be a part of
the signature. In this case, MSS will be used to guess the
type of network hookup according to the [mtu] rules.

NEW SIGNATURES: Use '*' for any commodity OSes where MSS is
around 1300 - 1500, unless you know for sure that it's fixed.
If the value is outside that range, you can probably copy it
literally.

    
##### Variable `olayout` {#id}




comma-delimited layout and ordering of TCP options, if any. This
is one of the most valuable TCP fingerprinting signals. Supported
values.

    
##### Variable `olen` {#id}




Length of IPv4 options or IPv6 extension headers. Usually zero
for normal IPv4 traffic; always zero for IPv6 due to the
limitations of libpcap.

    
##### Variable `pclass` {#id}




Payload size classification: '0' for zero, '+' for non-zero,
'*' for any. The packets we fingerprint right now normally have
no payloads, but some corner cases exist.

    
##### Variable `qstring` {#id}




Create Query String

    
##### Variable `quirk` {#id}




Comma-delimited properties and quirks observed in IP or TCP
headers.

    
##### Variable `scale` {#id}




Window scaling factor, if specified in TCP options. Fixed value
or '*'.
NEW SIGNATURES: Copy literally, unless the value varies randomly.
Many systems alter between 2 or 3 scaling factors, in which case,
it's better to have several 'sig' lines, rather than a wildcard.

    
##### Variable `version` {#id}




Signature for IPv4 ('4'), IPv6 ('6'), or both ('*').

    
##### Variable `window_size` {#id}




Window size. Can be expressed as a fixed value, but many
operating systems set it to a multiple of MSS or MTU, or a
multiple of some random integer. P0f automatically detects these
cases, and allows notation such as 'mss*4', 'mtu*4', or '%8192'
to be used. Wilcard ('*') is possible too.


    
#### Static methods


    
##### `Method process_options` {#id}




>     def process_options(
>         option: list
>     ) ‑> str


Static method for processing options.


    
### Class `TcpSig` {#id}




>     class TcpSig(
>         tcp_sig_obj
>     )


Data mapping class that takes a TCP Signature object and inserts it into the sqlite database.





    
#### Instance variables


    
##### Variable `qstring` {#id}




QString.





    
# Module `test_passive` {#id}

Pytest Module for Passive Data




    
## Functions


    
### Function `test_setup_db_1` {#id}




>     def test_setup_db_1()


UT to ensure DB file gets created.

    
### Function `test_setup_db_5` {#id}




>     def test_setup_db_5()


UT to ensure signatures table was created.

    
### Function `test_test_github_con_1` {#id}




>     def test_test_github_con_1()


UT to ensure Github connection test is successful.




    
# Module `test_signature_matching` {#id}

Smudge Test module for Signature class




    
## Functions


    
### Function `test_process_options` {#id}




>     def test_process_options()


Pytest for Process Options static method.

    
### Function `test_signature_1` {#id}




>     def test_signature_1()


Signature.

    
### Function `test_version` {#id}




>     def test_version()


Pytest for Version property.



-----
Generated by *pdoc* 0.10.0 (<https://pdoc3.github.io>).
