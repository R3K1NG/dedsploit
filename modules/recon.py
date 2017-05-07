'''

Recon Module for dedsploit. Attack vectors include:

'''

# Incorporate mainLib for module-wide variables (i.e, colors)
from core.mainLib import *


def pscan(ip):
        #############################
        # Actual Nmap Scanning! First throw try/except in case of KeyboardInterrupt. Then output results
        #############################
        try:
            print O + "[*] Performing a Nmap scan on the network. Please hold... Use CTRL+C to stop. [*]" + W
            nm = nmap.PortScanner()
            nm.scan(str(ip), '22-443')
        except KeyboardInterrupt:
            print R + "\n[!] Interrupted! Stopping... [!]" + W
        # Output!
        for host in nm.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, nm[host].hostname()))
            print('State : %s' % nm[host].state())
            for proto in nm[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
            lport = nm[host][proto].keys()
            lport.sort()
            for port in lport:
                print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                pscan(ip)

def hosts():
    while True:
        print O + "[*] Performing a Nmap scan on the network. Please hold... Use CTRL+C to stop. [*]" + W
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=gateway_ip + "/24", arguments='-n -sn -PE')
            print('+-------------------------------+')
            for host in nm.all_hosts():
                print('| Host | %s (%s) | %s |' % (host, nm[host].hostname(), nm[host].state()))
                print('+------------------------------+')
        except KeyboardInterrupt:
            print R + "\n[!] Interrupted! Stopping... [!]" + W
            break

def recon():
    print LISTMSG
    print recon_menu
    while True:
        try:
            recon_options = raw_input(LP + "[recon] >> " + W )
            if recon_options == "list":
                print recon_menu
            elif recon_options == "clear":
                os.system("clear")
            elif recon_options == "exit":
                break
            elif recon_options == "pscan":
                print pscan_menu
                while True:
                    pre, pscanopts = raw_input(LP + "[recon] pscan >> " + W ).split()
                    if pre == "scan":
                        ip = pscanopts
                        print "IP => ", ip
                        pscan(ip)
                    elif pre == "exit":
                        break
            elif recon_options == "hosts":
                hosts()
        except ValueError:
            print WARNING
            continue
        except KeyboardInterrupt: # Ctrl + C to go back to main menu
            break
