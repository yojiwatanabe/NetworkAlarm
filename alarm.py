#!/usr/bin/python

"""
Yoji Watanabe
Spring 2018


Source code for alarm.py, a program that listens on network interfaces or investigates pcap files in order to check
against possible cyber attacks. Protects against nmap stealthy scans, Nikto scans, Shellshock attacks, credentials sent
in-the-clear, and credit card numbers sent in-the-clear.
"""

import pcapy
import argparse
from re import findall
from scapy.all import *
from base64 import b64decode
from datetime import datetime

# Static Global Vars
NULL_FLAG = 0b00000000
FIN_FLAG = 0b00000001
XMAS_FLAG = 0b00101001
HTTP_AUTH_KEYWD = "Authorization: Basic"
NIKTO_KEYWORDS = ["Nikto", "nikto", "NIKTO"]
SHOCK_KEYWORDS = ["() { :; };", "(){:;};", "() { :;};", "() { : ; } ;", "() {:; };"]
USER_KEYWORDS = ["mac", "log", "login", "wpname", "ahd_username", "unickname", "nickname", "user", "user_name", "alias",
                 "pseudo", "email", "username", "_username", "userid", "form_loginname", "loginname", "login_id",
                 "loginid", "session_key", "sessionkey", "pop_login", " uid", " id", "user_id", "screenname", "uname",
                 "ulogin", "acctname", "account", "member", "mailaddress", "membername", "login_username",
                 "login_email", "loginusername", "loginemail", "uin", "sign-in"]
PASS_KEYWORDS = ["pass", "ahd_password", "pass password", "_password passwd", "session_password", "sessionpassword",
                 "login_password", "loginpassword", "form_pw", "pw", "userpassword", "pwd", "upassword",
                 "login_password", "passwort", "passwrd", "wppassword", "upasswd"]
PROTOCOLS = ["HOPOPT", "ICMP", "IGMP", "GGP", "IPv4", "ST", "TCP", "CBT", "EGP", "IGP", "BBN-RCC-MON", "NVP-II", "PUP",
             "ARGUS", "EMCON", "XNET", "CHAOS", ]
LOG = 'logs/{{{}}}.log'

# Dynamic Global Vars
ALERT_COUNTER = 1
tempUserPass = ''


# Packet class
#
# Holds information from the packet so the instance of a Scapy Packet does not need to be passed around.
class Packet:
    srcIP = ''
    protocol = ''
    rawData = ''
    flags = 0x00

    def __init__(self, in_packet):
        self.srcIP = str(in_packet[IP].src)
        self.protocol = int(in_packet.proto)
        self.rawData = str(in_packet)
        self.flags = in_packet[TCP].flags


# print_alert()
#
# Prints an alert pertinent to what was picked up on the alarm.
def print_alert(scan_type, src, proto, payload):
    global ALERT_COUNTER

    ALERT_COUNTER += 1
    if payload == "":
        print("ALERT #%d: %s is detected from %s (%s)%s!" % (ALERT_COUNTER, scan_type, src, PROTOCOLS[proto], payload))
        logging.info("ALERT #%d: %s is detected from %s (%s)%s!" % (ALERT_COUNTER, scan_type, src, PROTOCOLS[proto],
                                                                    payload))
    else:
        print("ALERT #%d: %s from %s (%s) (%s)!" % (ALERT_COUNTER, scan_type, src, PROTOCOLS[proto], payload))
        logging.info("ALERT #%d: %s from %s (%s) (%s)!" % (ALERT_COUNTER, scan_type, src, PROTOCOLS[proto], payload))


# scan_check()
#
# Checks given Packet object for traces of a NULL, FIN, or XMAS nmap stealthy scan. Does this by checking what flags are
# set in the TCP layer, which will allow for the detection of a stealthy scan. Calls on print_alert() if packet seems to
# be from an nmap stealth scan.
def scan_check(in_packet):
    global ALERT_COUNTER

    if in_packet.flags == NULL_FLAG:  # NULL SCAN
        print_alert("NULL scan", in_packet.srcIP, in_packet.protocol, "")
    elif in_packet.flags == FIN_FLAG:  # FIN SCAN
        print_alert("FIN scan", in_packet.srcIP, in_packet.protocol, "")
    elif in_packet.flags == XMAS_FLAG:  # XMAS SCAN
        print_alert("XMAS scan", in_packet.srcIP, in_packet.protocol, "")


# nikto_check()
#
# Checks given Packet object for traces of a Nikto scan. Does this by checking for references to keywords associated
# with the Nikto program (NIKTO_KEYWORDS) to identify a Nikto scan.
def nikto_check(in_packet):
    global ALERT_COUNTER

    for keyword in NIKTO_KEYWORDS:
        if keyword in in_packet.rawData:
            print_alert("Nikto scan", in_packet.srcIP, in_packet.protocol, "")


# get_shock_script()
#
# Helper function to obtain the command that was attempted to be run in a Shellshock attack. Used by shellshock_check().
def get_shock_script(packet_data):
    shellshock_line = ""  # Return empty string if not found

    data = packet_data.splitlines()
    for line in data:
        for keyword in SHOCK_KEYWORDS:
            if keyword in line:
                shellshock_line = line
                break

    return shellshock_line


# shellshock_check()
#
# Checks a packet for traces of a Shellshock attack. Does this by looking for shellshock entry queries.
def shellshock_check(in_packet):
    global ALERT_COUNTER

    for keyword in SHOCK_KEYWORDS:
        if keyword in in_packet.rawData:
            print_alert("Shellshock attack", in_packet.srcIP, in_packet.protocol,
                        get_shock_script(in_packet.rawData))


# get_username()
#
# Returns the username that was found in the raw data of a network packet. Helper function to find_user_pass().
def get_username(raw_data):
    words = str(raw_data).split()

    for i in range(len(words)):
        for keyword in USER_KEYWORDS:
            if keyword in words[i].lower():
                return words[i + 1]


# getPassword()
#
# Returns the password that was found in the raw data of a network packet. Helper function to find_user_pass().
def get_password(raw_data):
    words = str(raw_data).split()

    for i in range(len(words)):
        for keyword in PASS_KEYWORDS:
            if keyword in words[i].lower():
                return words[i + 1]


# find_user_pass()
#
# Helper function to user_pass_check, where after it is determined that a username and password was sent in the clear,
# it will call on this function in order to find the username and password combination (even if split between packets)
# and calls on the print_alert() function.
def find_user_pass(raw_packet, parsed_packet):
    global ALERT_COUNTER, tempUserPass
    raw_data = parsed_packet.getlayer(Raw)  # Get only the Raw layer of the raw_packet

    for keyword in USER_KEYWORDS:
        if keyword in str(raw_data).lower():
            username = get_username(raw_data)
            tempUserPass = username

    for keyword in PASS_KEYWORDS:
        if keyword in str(raw_data).lower():
            password = get_password(raw_data)
            user_pass = tempUserPass + ":" + password

            if not check_if_printable(user_pass):
                continue

            tempUserPass = ""
            print_alert("Username and password sent in the clear", raw_packet.srcIP, raw_packet.protocol, user_pass)
            tempUserPass = ""


# check_if_printable()
#
# In order to try and decrease false positives for credentials sent in-the-clear, check if the username and password are
# ASCII characters and non-control characters
def check_if_printable(username_password):
    try:
        for character in username_password:
            # Check that credentials only use extended-ASCII and non-control characters
            if ord(character) > 255 or ord(character) < 32:
                return False
    # Unable to get char value
    except TypeError:
        return False

    return True


# user_pass_check()
#
# Checks whether or not credentials have been sent in-the-clear. If it believes
# there are credentials in the packet, sends to find_user_pass() to find and
# report them.
def user_pass_check(raw_packet, parsed_packet):
    global ALERT_COUNTER, tempUserPass

    data = raw_packet.rawData.splitlines()
    for line in data:
        if HTTP_AUTH_KEYWD in line:
            words = line.split()
            user_pass = words[2]
            if ((len(user_pass) % 4) == 0) and (user_pass[-1] == '='):
                if not check_if_printable(user_pass):
                    pass
                print_alert("Username and password sent in-the-clear", raw_packet.srcIP, raw_packet.protocol,
                            b64decode(user_pass))

    raw_data = str(parsed_packet.getlayer(Raw))
    for keyword in USER_KEYWORDS:
        if keyword in raw_data.lower() or (len(tempUserPass) > 1):
            find_user_pass(raw_packet, parsed_packet)


# credit_card_check()
#
# Checks whether or not credit card numbers have been sent in-the-clear. If it believes
# there are credentials in the packet,
def credit_card_check(in_packet):
    visa_num = findall('4[0-9]{12}(?:[0-9]{3})?', raw)
    mastercard_num = findall('(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}', raw)
    diners_club_num = findall('3(?:0[0-5]|[68][0-9])[0-9]{11}', raw)
    discover_num = findall('6(?:011|5[0-9]{2})[0-9]{12}', raw)
    jcb_num = findall('(?:2131|1800|35\d{3})\d{11}', raw)
    american_express_num = findall('3[47][0-9]{13}', raw)
    bcglobal_num = findall('^(6541|6556)[0-9]{12}', raw)
    korean_local_num = findall('^9[0-9]{15}', raw)
    laser_card_num = findall('^(6304|6706|6709|6771)[0-9]{12,15}', raw)
    maestro_num = findall('^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}', raw)
    union_pay_num = findall('^(62[0-9]{14,17})', raw)

    if visa_num:
        print_alert("Visa CC # sent in-the-clear", in_packet.srcIP, in_packet.protocol, visa_num)
    if mastercard_num:
        print_alert("MasterCard CC # sent in-the-clear", in_packet.srcIP, in_packet.protocol, mastercard_num)
    if diners_club_num:
        print_alert("Diners Club CC # sent in-the-clear", in_packet.srcIP, in_packet.protocol, diners_club_num)
    if discover_num:
        print_alert("Discover CC # sent in-the-clear", in_packet.srcIP, in_packet.protocol, discover_num)
    if jcb_num:
        print_alert("JCB CC # sent in-the-clear", in_packet.srcIP, in_packet.protocol, jcb_num)
    if american_express_num:
        print_alert("American Express CC # sent in-the-clear", in_packet.srcIP, in_packet.protocol,
                    american_express_num)
    if bcglobal_num:
        print_alert("BCGlobal CC # sent in-the-clear", in_packet.srcIP, in_packet.protocol, bcglobal_num)
    if korean_local_num:
        print_alert("KoreanLocalCard CC # sent in-the-clear", in_packet.srcIP, in_packet.protocol, korean_local_num)
    if laser_card_num:
        print_alert("JCB CC # sent in-the-clear", in_packet.srcIP, in_packet.protocol, laser_card_num)
    if maestro_num:
        print_alert("Maestro CC # sent in-the-clear", in_packet.srcIP, in_packet.protocol, maestro_num)
    if union_pay_num:
        print_alert("Union Pay CC # sent in-the-clear", in_packet.srcIP, in_packet.protocol, union_pay_num)


# sniff_packet()
#
# Sniffs a given packet. Will call on four functions to protect against: nmap 
# stealthy scans, Nikto scans, Shellshock attacks, and credentials sent
# in-the-clear.
def sniff_packet(in_packet):
    temp_packet = Packet(in_packet)

    scan_check(temp_packet)
    nikto_check(temp_packet)
    shellshock_check(temp_packet)
    user_pass_check(temp_packet, in_packet)
    credit_card_check(temp_packet)


def packet_callback(in_packet):
    try:
        sniff_packet(in_packet)
    except IndexError:
        pass
    except StandardError:
        pass


parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()

log_name = LOG.replace('{{{}}}', '{date:%Y-%m-%d_%H:%M:%S}'.format(date=datetime.now()))
logging.basicConfig(filename=log_name, format='%(asctime)s %(levelname)-5s - - - %(message)s', level=logging.INFO)
logging.info('Started Execution')

if args.pcapfile:
    try:
        print("Reading PCAP file %(filename)s..." % {"filename": args.pcapfile})
        sniff(offline=args.pcapfile, prn=packet_callback)
    except IOError:
        print("Sorry, something went wrong with the PCAP file %(filename)s IO!" % {"filename": args.pcapfile})
    except StandardError:
        print("Sorry, something went wrong with reading the PCAP file %(filename)s!" % {"filename": args.pcapfile})

else:
    print("Sniffing on %(interface)s... " % {"interface": args.interface})
    try:
        sniff(iface=args.interface, prn=packet_callback)
    except pcapy.PcapError:
        print "Sorry, error opening network interface %(interface)s. It does not exist." % {"interface": args.interface}
    except Exception as e:
        print type(e)
        print "Sorry, can\'t read network traffic. Are you root?"

logging.info('Finished Execution')
