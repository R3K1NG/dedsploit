'''
mainLib - main library of dedsploit.
          All global variables and methods are here.
'''

########## Dependencies + Modules ##########

import os, sys, threading, signal, socket, smtplib, logging, random, platform, subprocess
import nmap

logging. getLogger("scapy.runtime").setLevel(logging.ERROR) # STDOUT from Scapy - please stfu

from time import sleep
from getpass import getpass
#from terminaltables import AsciiTable
from subprocess import call
from scapy.all import *
from scapy.error import Scapy_Exception


########## Colors to make program and output text much more appealing ##########

W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
LR = '\033[1;31m' # light red
LG = '\033[1;32m' # light green
LO = '\033[1;33m' # light orange
LB = '\033[1;34m' # light blue
LP = '\033[1;35m' # light purple
LC = '\033[1;36m' # light cyan

########## WARNINGS! ##########

if not os.geteuid() == 0:
    sys.exit(R + "[!] You are not root! [!]" + W )
if platform.system() != "Linux":
    print R + "[!] You are not using Linux! dedsploit may be unstable! [!]" + W


########## Network Information in the form of variables ##########

lan_ip = os.popen("ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'").read()
public_ip = os.popen("wget http://ipinfo.io/ip -qO -").read()
if platform.system() == "Darwin":
	mac_address = os.popen("ifconfig en1 | awk '/ether/{print $2}'").read()
	gateway_ip = os.popen("netstat -nr | grep default | grep -oE '\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b'").read()
else:
	mac_address = os.popen("cat /sys/class/net/eth0/address").read()
	gateway_ip = os.popen("/sbin/ip route | awk '/default/ { printf $3 }'").read()

########## Visually appealing text in the form of variables ##########

# Modules and attack vectors available!
m, v = 5, 7

# Constants for text
WARNING = R + "Not recognized" + W
LISTMSG =  LC + "Type 'list' to show all of available attack vectors" + W

header = C + """

    .___         .___             .__         .__  __
  __| _/____   __| _/____________ |  |   ____ |__|/  |_
 / __ |/ __ \ / __ |/  ___/\____ \|  |  /  _ \|  \   __|
/ /_/ \  ___// /_/ |\___ \ |  |_> >  |_(  <_> )  ||  |
\____ |\___  >____ /____  >|   __/|____/\____/|__||__|
     \/    \/     \/    \/ |__|                         \n""" + W

site = "http://dedsploit.tech"

# Print authors, versions and available modules/attack vectors
version = LG + """\n
         [   Written By: the dedsploit team     ]
         [   Version: 2.0.0                     ]
         [   Modules: %s                         ]
         [   Attack Vectors: %s                  ]\n""" % (m, v) + W

# Output info based on network
netinfo = """
		> Local IP Address: %s
		> MAC Address: %s
		> Gateway IP: %s\n
		""" % (str(lan_ip), str(mac_address), str(gateway_ip))

# Help and modules
help_options = LR + """
	[System Commands Available:]\n""" + G + """
	help			|	Display available commands and modules
	modules			|	Show modules that can be used
	clear			|	Move the screen up to clear it
	clearcache		|	Delete dedsploit cache
	update			|	Update dedsploit through git
	exit			|	Exit the program or current module\n""" + W

modules = LR + """
	[There are currently """ + LP + str(m) + LR + " modules available:]\n" + G + """
	ssh
	recon
	smtp
	http
	misc\n""" + W


ssh_menu = LR + """
    [Secure SHell Module - Available Attack Vectors:]""" + G + """

    ---
    bruteforce         | Bruteforce an SSH server with paramiko
    ---
    list               | Show this list again
    exit               | Go back to the main menu\n   """ + W

# SSH Bruteforce Menu
sshbrute_menu = LR + """
    [Secure SHell Bruteforce Vector:]""" + G + """

    target <server>    | Set the target SSH server
    port <number>      | Set SSH port (default 22)
    username <name>    | Set username
    wordlist </path>   | Path to wordlist
    start bruteforce   | Start the attack once everything is set
    ---
    exit bruteforce    | Exit bruteforce module\n    """ + W


smtp_menu = LR + """
    [Simple Mail Transfer Protocol - Available Attack Vectors:]""" + G + """

    ---
    bruteforce         | Bruteforce a SMTP-based account (email)
    smsbomb            | Spam a specified SMS number with SMTP-crafted messages
    ---
    list               | Show this list again
    exit               | Go back to the main menu\n   """ + W


smtpbrute_menu =  LR + """
    [Simple Mail Tranfer Protocol Bruteforce Vector:]""" + G + """

    target <server>    | Set the target SMTP server. For e.g, 'smtp.gmail.com'
    port <number>      | Set SMTP port (default 587)
    username <name>    | Set username (without @email account identifier)
    wordlist </path>   | Path to wordlist
    start bruteforce   | Start the attack once everything is set"
    ---
    exit bruteforce    | Exit bruteforce module\n       """ + W

sms_menu = LR + """
    [SMS Bomb Attack Vector:]""" + G + """

    target <phone>     | Set the target's phone number
    carrier <carrier>  | Set the target's phone carrier (use list carriers to show)
    email <email>      | Set disposable email WITHOUT @email identifier
    start smsbomb      | Start the attack
    ---
    list carriers      | List available carriers
    exit smsbomb       | Exit smsbomb module\n    """ + W

http_menu = LR + """
    [HyperText Transfer Protocol - Available Attack Vectors:]""" + G + """

    ---
    arpspoof           | ARP Spoof/Poison attack to capture packets on the network
    slowloris          | Slowloris DoS attack on vulnerable web servers
    ---
    list               | Show this list again
    exit               | Go back to the main menu\n   """ + W

arpspoof_menu = LR + """
    [ARPspoof Attack Vector:]""" + G + """

    target <ip>        | Set the target's IP address
    packet <count>     | Set number of packets to send
    start arpspoof     | Start the arpspoof attack
    ---
    exit arpspoof      | Exit ARPspoof module\n     """ + W

slowloris_menu = LR + """
    [Slowloris Attack Vector:]""" + G + """

    target <ip>            | Set the target's IP address"
    connections <number>   | Set the number of connections to send"
    start slowloris        | Start the Slowloris DoS attack"
    length <time>          | Time to keep attack alive"
    ---
    exit slowloris         | Exit slowloris module\n     """ + W

recon_menu = LR + """
    [Reconaissance - Available Attack Vectors:]""" + G + """

    ---
    pscan              | Perform a Nmap Port Scan
    hosts              | Discover active hosts on the network
    ---
    list               | Show this list again
    exit               | Go back to the main menu\n   """ + W

pscan_menu = LR + """
    [Port Scan:]""" + G + """

    scan <ip>     | Portscan on IP address  "
    ---
    exit pscan    | Exit portscan module\n           """ + W
