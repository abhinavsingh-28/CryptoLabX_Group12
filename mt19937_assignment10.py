"""
Assignment 10: Complete Lab Demonstration Runner (Steps 16-19)
Executes Part A and Part B end-to-end and saves output to outputs/assignment10_output.txt.
"""

import io
import os
import sys
from contextlib import redirect_stdout

from modern.mt19937_cipher import run_part_a_demo
from attacks.mt19937_token_attack import run_part_b_demo


def main() -> None:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        print("*" * 72)
        print("CRYPTOGRAPHY LAB - ASSIGNMENT 10 DEMONSTRATION")
        print("MT19937 Stream Cipher and Predictable Token Attack")
        print("*" * 72 + "\n")
        run_part_a_demo()
        print("\n")
        run_part_b_demo()
        print("\n" + "*" * 72)

    output_text = buffer.getvalue()
    sys.stdout.write(output_text)

    os.makedirs("outputs", exist_ok=True)
    output_path = os.path.join("outputs", "assignment10_output.txt")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(output_text)

    print(f"\n[+] Saved complete demonstration log to: {output_path}")


if __name__ == "__main__":
    main()