import sys

from query_ioc import get_recent_iocs
from get_ioc_byID import search_ioc_by_id
from search_ioc_keyword import search_ioc_by_keyword
from search_ioc_hash import search_by_file_hash
from get_malware_list import get_malware_list
from iocs_malware_fam import search_ioc_by_malware
from share_IOC import submit_ioc


def print_main_menu():
    """
    This is the menu to print on screen when a user accesses the
    applicaton
    """
    print("\n ** Welcome to ThreatFox Command line interface **")
    print(" ** This application is designed to give users info on Indicators of Compromise(IOCs) as well as submit IOCs **")
    print(" ** The app is available for purposes of incident response🛡, detection🔭, and threat hunting⚔ **\n")
    print("=====================================================")
    print("================Main Menu=====================")
    print("1. Get recent IOCs")
    print("2. Search IOCs by ID")
    print("3. Lookup IOC by a keyword(3.g domain name or ip addresss)")
    print("4. Filter IOCs related by a certain file hash")
    print("5. List malware families supported by Threatfox")
    print("6. Search IOCs by malware family")
    print("7. Submit a new IOC(s) discovered to Threatfox")
    print("0. Exit Threatfox CLI")

def main():
    while True:
        print_main_menu()
        choice = input("Please choose an option(0-7) to use Threatfox CLI features: ").strip()

        if choice == "1":
            get_recent_iocs()
        elif choice == "2":
            search_ioc_by_id()
        elif choice == "3":
            search_ioc_by_keyword()
        elif choice == "4":
            search_by_file_hash()
        elif choice == "5":
            get_malware_list()
        elif choice == "6":
            search_ioc_by_malware()
        elif choice == "7":
            submit_ioc()
        elif choice == "0":
            print("\nExiting ThreatFox CLI. Bye!👋\n")
            sys.exit(0)
        else:
            print("ERROR❗❗: Invalid choice. Please enter a number between 0 and 7.")
    
    print()

if __name__ == "__main__":
    main()
