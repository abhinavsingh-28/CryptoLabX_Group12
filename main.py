from utils.banner import display_banner
from utils.menu import display_menu
from utils.input_handler import get_choice


def encrypt():
    print("\n========== Encrypt ==========")
    print("Coming Soon...")
    input("\nPress Enter to continue...")


def decrypt():
    print("\n========== Decrypt ==========")
    print("Coming Soon...")
    input("\nPress Enter to continue...")


def attack():
    print("\n========== Attack ==========")
    print("Coming Soon...")
    input("\nPress Enter to continue...")


def analyze():
    print("\n========== Analyze ==========")
    print("Coming Soon...")
    input("\nPress Enter to continue...")


def main():

    while True:

        display_banner()

        display_menu()

        choice = get_choice()

        if choice == 1:
            encrypt()

        elif choice == 2:
            decrypt()

        elif choice == 3:
            attack()

        elif choice == 4:
            analyze()

        elif choice == 5:
            print("\nThank you for using CryptoLabX.")
            print("Goodbye!\n")
            break


if __name__ == "__main__":
    main()