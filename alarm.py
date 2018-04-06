#!/usr/bin/python

'''
Yoji Watanabe
Computer System Security
Spring 2018
Lab 5 - Python and Scapy
alarm.py

Source code for alarm.py, a program that listens on network interfaces or
investigates pcap files in order to check against possible cyber attacks.
Protects against nmap stealthy scans, Nikto scans, Shellshock attacks, and 
credentials sent in-the-clear.

'''


from base64 	import b64decode
from scapy.all 	import *
import pcapy
import argparse


# Static Global Vars
NULL_FLAG 		= 0
FIN_FLAG  		= 1
XMAS_FLAG 		= 41
HTTP_AUTH_KEYWD = "Authorization: Basic"
NIKTO_KEYWORDS 	= ["Nikto", "nikto", "NIKTO"]
SHOCK_KEYWORDS 	= ["() { :; };", "(){:;};", "() { :;};", "() { : ; } ;", 
				   "() {:; };"]
USER_KEYWORDS   = ["mac", "log", "login", "wpname", "ahd_username", "unickname",
				   "nickname", "user", "user_name", "alias" "pseudo", "email", 
				   "username", "_username", "userid", "form_loginname", 
				   "loginname", "login_id", "loginid", "session_key", 
				   "sessionkey", "pop_login", " uid"," id", "user_id", 
				   "screenname", "uname", "ulogin", "acctname", "account", 
				   "member", "mailaddress", "membername", "login_username", 
				   "login_email", "loginusername", "loginemail", "uin", 
				   "sign-in"]
PASS_KEYWORDS 	= ["pass", "ahd_password", "pass password", "_password passwd", 
				   "session_password", "sessionpassword", "login_password", 
				   "loginpassword", "form_pw", "pw", "userpassword", "pwd", 
				   "upassword", "login_password", "passwort", "passwrd", 
				   "wppassword", "upasswd"]
PROTOCOLS 		= ["HOPOPT", "ICMP", "IGMP", "GGP", "IPv4", "ST", "TCP", "CBT", 
				   "EGP", "IGP", "BBN-RCC-MON", "NVP-II", "PUP", "ARGUS", 
				   "EMCON", "XNET", "CHAOS", ] 


# Dynamic Global Vars
alertCounter 	= 1
tempUserPass 	= ''


# Packet class
#
# Holds information from the packet so the instance of a Scapy Packet does not
# need to be passed around.
class Packet():
	srcIP 		= ''
	protocol 	= ''
	rawData 	= ''
	flags 		= 0x00

	def __init__(self, inPacket):
		self.srcIP 		= str(inPacket[IP].src)
		self.protocol 	= int(inPacket.proto)
		self.rawData 	= str(inPacket)
		self.flags 		= inPacket[TCP].flags


# printAlert()
#
# Prints an alert pertinent to what was picked up on the alarm.
def printAlert(scanType, src, proto, payload):
	global alertCounter

	if (payload == ""):
		print("ALERT #%d: %s is detected from %s (%s)%s!" % (alertCounter, \
			scanType, src, PROTOCOLS[proto], payload))
	else:
		print("ALERT #%d: %s from %s (%s) (%s)!" % (alertCounter, scanType, \
			src, PROTOCOLS[proto], payload))


# scanCheck()
#
# Checks given Packet object for traces of a NULL, FIN, or XMAS nmap stealthy
# scan. Does this by checking what flags are set in the TCP layer, which will
# allow for the detection of a stealthy scan. Calls on printAlert() if packet 
# seems to be from an nmap stealth scan.
def scanCheck(packet):
	global alertCounter
	
	if packet.flags == NULL_FLAG:		# NULL SCAN
		printAlert("NULL scan", packet.srcIP, packet.protocol, "")
		alertCounter += 1
	elif packet.flags == FIN_FLAG:		# FIN SCAN
		printAlert("FIN scan", packet.srcIP, packet.protocol, "")
		alertCounter += 1
	elif packet.flags == XMAS_FLAG:		# XMAS SCAN
		printAlert("XMAS scan", packet.srcIP, packet.protocol, "")


# niktoCheck()
#
# Checks given Packet object for traces of a Nikto scan. Does this by checking 
# for references to keywords associated with the Nikto program (NIKTO_KEYWORDS)
# to identify a Nikto scan.
def niktoCheck(packet):
	global alertCounter

	for keyword in NIKTO_KEYWORDS:
		if keyword in packet.rawData:
			printAlert("Nikto scan", packet.srcIP, packet.protocol, "")
			alertCounter += 1


# getShockScript()
#
# Helper function to obtain the command that was attempted to be run in a
# Shellshock attack. Used by shellshockCheck().
def getShockScript(packetData):
	shellshockLine = "" # Return empty string if not found

	data = packetData.splitlines()
	for line in data:
		for keyword in SHOCK_KEYWORDS:
			if keyword in line:
				shellshockLine = line;
				break;

	return shellshockLine


# shellshockCheck()
#
# Checks a packet for traces of a Shellshock attack. Does this by 
def shellshockCheck(packet):
	global alertCounter

	for keyword in SHOCK_KEYWORDS:
		if keyword in packet.rawData:
			printAlert("Shellshock attack", packet.srcIP, packet.protocol, \
				getShockScript(packet.rawData))
			alertCounter += 1


# getUsername()
#
# Returns the username that was found in the raw data of a network packet. 
# Helper function to findUserPass().
def getUsername(rawData):
	words 	 = str(rawData).split()

	for i in range(len(words)):
		for keyword in USER_KEYWORDS:
			if keyword in words[i].lower():
				return words[i + 1]


# getPassword()
#
# Returns the password that was found in the raw data of a network packet. 
# Helper function to findUserPass().
def getPassword(rawData):
	words 	 = str(rawData).split()

	for i in range(len(words)):
		for keyword in PASS_KEYWORDS:
			if keyword in words[i].lower():
				return words[i + 1]


# findUserPass()
#
# Helper function to userPassCheck, where after it is determined that a username
# and password was sent in the clear, it will call on this function in order to
# find the username and password combination (even if split between packets) and
# calls on the printAlert() function.
def findUserPass(packet, inPacket):
	global alertCounter, tempUserPass
	username = ""
	password = ""
	rawData  = inPacket.getlayer(Raw) # Get only the Raw layer of the packet

	for keyword in USER_KEYWORDS:
		if keyword in str(rawData).lower():
			username = getUsername(rawData)
			tempUserPass = username

	for keyword in PASS_KEYWORDS:
		if keyword in str(rawData).lower():
			password = getPassword(rawData)
			userPass = tempUserPass + ":" + password
			tempUserPass = ""
			printAlert("Username and password sent in the clear", packet.srcIP,\
			packet.protocol, userPass)
			tempUserPass = ""
			alertCounter += 1

# userPassCheck()
#
# Checks whether or not credentials have been sent in-the-clear. If it believes
# there are credentials in the packet, sends to findUserPass() to find and 
# report them.
def userPassCheck(packet, inPacket):
	global alertCounter, tempUserPass

	data = packet.rawData.splitlines()
	for line in data:
		if HTTP_AUTH_KEYWD in line:
			words 	 = line.split()
			userPass = words[2]
			if ((len(userPass) % 4) == 0) and (userPass[-1] == '='):
				printAlert("Username and password sent in the clear", \
					packet.srcIP, packet.protocol, b64decode(userPass))
				alertCounter += 1

	rawData = str(inPacket.getlayer(Raw))
	for keyword in USER_KEYWORDS:
		if keyword in rawData.lower() or (len(tempUserPass) > 1):
			findUserPass(packet, inPacket)			

# sniffPacket()
#
# Sniffs a given packet. Will call on four functions to protect against: nmap 
# stealthy scans, Nikto scans, Shellshock attacks, and credentials sent
# in-the-clear.
def sniffPacket(inPacket):
	tempPacket = Packet(inPacket)

	scanCheck(tempPacket)
	niktoCheck(tempPacket)
	shellshockCheck(tempPacket)
	userPassCheck(tempPacket, inPacket)

def packetcallback(packet):
	try:
		sniffPacket(packet)
	except:
		pass


parser = argparse.ArgumentParser(description='A network sniffer that \
		identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff \
		on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()

if args.pcapfile:
	try:
		print("Reading PCAP file %(filename)s..." %{"filename" : args.pcapfile})
		sniff(offline=args.pcapfile, prn=packetcallback)
	except:
		print("Sorry, something went wrong reading PCAP file %(filename)s!" % 
			 {"filename" : args.pcapfile})
else:
	print("Sniffing on %(interface)s... " % {"interface" : args.interface})
	try:
		sniff(iface=args.interface, prn=packetcallback)
	except pcapy.PcapError:
		print "Sorry, error opening network interface %(interface)s. It does \
			not exist." % {"interface" : args.interface}
	except:
		print "Sorry, can\'t read network traffic. Are you root?"