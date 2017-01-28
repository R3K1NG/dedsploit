import sys

from mainLib import *

sys.path.append("modules/")
from HTTP import *
from ssh import *
from smtp import *
from recon import *
from misc import *

print header, site, version, netinfo


def main():
    print LC + "Type in a command. For system commands, type 'help'."
    print "For available modules, type 'modules'. Exit with Ctrl + C or 'exit'.\n"
    while True:
        options = raw_input(LP + "[>>] " + W )

        ########################
        # System Commands
        ########################
        if options == "help":   # DONE
            print help_options
            continue
        elif options == "modules": # DONE
            print modules
            continue
        elif options == "clear": # DONE
            os.system("clear")
            continue
        elif options == "clearcache": # NOT YET
            print "Done"
        elif options == "update": # NOT YET
            update()
        elif options == "exit":
            raise EOFError

        ########################
        # Modules and Respective Attack Vectors
        ########################
        elif options == "ssh":
            ssh()
        elif options == "smtp":
            smtp()
        elif options == "http":
            http()
        elif options == "misc":
            misc()
        elif options == "recon":
            recon()
        else:
            print WARNING
            continue

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print LR + "\n[!] Goodbye! Remember to Hack the Gibson!" + W
        exit()
