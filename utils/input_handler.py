def get_choice():
    while True:
        try:
            choice = int(input("\nEnter your choice (1-5): "))

            if 1 <= choice <= 5:
                return choice

            print("Please enter a number between 1 and 5.")

        except ValueError:
            print("Invalid input. Please enter a valid number.")