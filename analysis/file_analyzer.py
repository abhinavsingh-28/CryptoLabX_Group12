from collections import Counter
import os


def read_file(filename):
    filepath = os.path.join("datasets", filename)

    print(f"Opening file: {filepath}")

    try:
        with open(filepath, "r") as file:
            text = file.read()

            print(f"Length of text = {len(text)}")
            print(repr(text))  # Shows hidden characters too

            return text

    except FileNotFoundError:
        print("File not found!")
        return None


def count_characters(text):
    return len(text)


def count_words(text):
    return len(text.split())


def count_lines(text):
    return len(text.splitlines())


def count_unique_characters(text):
    return len(set(text))


def letter_frequency(text):

    letters = []

    for ch in text.lower():

        if ch.isalpha():
            letters.append(ch)

    return Counter(letters)


def analyze_file():

    filename = input("\nEnter filename (example: sample1.txt): ")

    text = read_file(filename)

    if text is None:
        return

    print("\n" + "=" * 50)
    print("             FILE ANALYSIS REPORT")
    print("=" * 50)

    print(f"Characters          : {count_characters(text)}")
    print(f"Words               : {count_words(text)}")
    print(f"Lines               : {count_lines(text)}")
    print(f"Unique Characters   : {count_unique_characters(text)}")

    print("\nLetter Frequency")
    print("-" * 20)

    frequency = letter_frequency(text)

    for letter in sorted(frequency):
        print(f"{letter} : {frequency[letter]}")

    print("=" * 50)

    input("\nPress Enter to continue...")