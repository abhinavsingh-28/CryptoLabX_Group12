"""
Assignment 9 - Task 1: Operating-System & Cryptographic RNG Data Generator
Generates >= 1 MB (1,048,576 bytes) of random data from three mechanisms:
  1. Linux /dev/urandom (native file, WSL, or MSYS2 device emulation)
  2. OpenSSL `rand` utility (`openssl rand` CLI or OpenSSL libssl/libcrypto)
  3. Windows CNG (`BCryptGenRandom` via bcrypt.dll or .NET RandomNumberGenerator)
"""

import os
import sys

# Guard against local 'math/' directory shadowing Python's stdlib 'math'
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SHADOWED = [p for p in sys.path if os.path.abspath(p or ".") == _PROJECT_ROOT]
for _p in _SHADOWED:
    sys.path.remove(_p)

import ctypes
import math  # noqa: F401
import shutil
import ssl
import subprocess
from typing import Dict, Tuple

sys.path.extend(_SHADOWED)

ONE_MB = 1024 * 1024  # 1,048,576 bytes
DEFAULT_OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "datasets", "rng_samples")


def generate_linux_urandom(num_bytes: int = ONE_MB) -> Tuple[bytes, str]:
    """
    Task 1a: Read random bytes from Linux /dev/urandom.
    Supports native /dev/urandom (Linux/macOS), WSL on Windows, or MSYS2 head/dd.
    """
    # 1. Native POSIX /dev/urandom
    if os.path.exists("/dev/urandom"):
        with open("/dev/urandom", "rb") as f:
            data = f.read(num_bytes)
        if len(data) == num_bytes:
            return data, "Native POSIX /dev/urandom"

    # 2. MSYS2 head.exe reading emulated /dev/urandom on Windows
    msys_head = r"C:\msys64\usr\bin\head.exe"
    if os.path.exists(msys_head):
        proc = subprocess.run(
            [msys_head, "-c", str(num_bytes), "/dev/urandom"],
            capture_output=True,
            check=False,
        )
        if proc.returncode == 0 and len(proc.stdout) == num_bytes:
            return proc.stdout, "MSYS2 /dev/urandom (via C:\\msys64\\usr\\bin\\head.exe)"

    # 3. Windows Subsystem for Linux (WSL) /dev/urandom
    if shutil.which("wsl"):
        proc = subprocess.run(
            ["wsl", "head", "-c", str(num_bytes), "/dev/urandom"],
            capture_output=True,
            check=False,
        )
        if proc.returncode == 0 and len(proc.stdout) == num_bytes:
            return proc.stdout, "WSL Linux /dev/urandom"

    # 4. Fallback to Python's os.urandom() OS kernel entropy interface
    return os.urandom(num_bytes), "OS Kernel Entropy Interface (os.urandom fallback)"


def generate_openssl_rand(num_bytes: int = ONE_MB) -> Tuple[bytes, str]:
    """
    Task 1b: Generate random bytes using OpenSSL's `rand` utility.
    Checks PATH and MSYS2 for `openssl.exe`, with a direct fallback to
    Python's linked OpenSSL C library (`ssl.RAND_bytes`).
    """
    openssl_candidates = [
        shutil.which("openssl"),
        r"C:\msys64\ucrt64\bin\openssl.exe",
        r"C:\msys64\usr\bin\openssl.exe",
        r"C:\Program Files\Git\usr\bin\openssl.exe",
    ]
    for cmd_path in openssl_candidates:
        if cmd_path and os.path.exists(cmd_path):
            proc = subprocess.run(
                [cmd_path, "rand", str(num_bytes)],
                capture_output=True,
                check=False,
            )
            if proc.returncode == 0 and len(proc.stdout) == num_bytes:
                return proc.stdout, f"OpenSSL CLI (`{os.path.basename(cmd_path)} rand {num_bytes}`)"

    # Direct call to OpenSSL's libcrypto CSPRNG linked in Python's ssl module
    return ssl.RAND_bytes(num_bytes), f"OpenSSL libcrypto (`ssl.RAND_bytes`, {ssl.OPENSSL_VERSION})"


def generate_windows_cng(num_bytes: int = ONE_MB) -> Tuple[bytes, str]:
    """
    Task 1c: Generate random bytes using the Windows CNG API (`BCryptGenRandom`
    in bcrypt.dll with BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002) or .NET
    System.Security.Cryptography.RandomNumberGenerator.
    """
    if sys.platform == "win32":
        try:
            bcrypt = ctypes.WinDLL("bcrypt")
            BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
            buffer = ctypes.create_string_buffer(num_bytes)
            status = bcrypt.BCryptGenRandom(
                None,
                buffer,
                ctypes.c_ulong(num_bytes),
                ctypes.c_ulong(BCRYPT_USE_SYSTEM_PREFERRED_RNG),
            )
            if status == 0:  # STATUS_SUCCESS (0x00000000)
                return buffer.raw, "Windows CNG API (bcrypt.dll -> BCryptGenRandom)"
        except Exception:
            pass

        # Fallback to .NET RandomNumberGenerator via PowerShell if ctypes is restricted
        ps_cmd = (
            f"$b = New-Object byte[] {num_bytes}; "
            "[System.Security.Cryptography.RandomNumberGenerator]::Fill($b); "
            "[Console]::OpenStandardOutput().Write($b, 0, $b.Length)"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            check=False,
        )
        if proc.returncode == 0 and len(proc.stdout) == num_bytes:
            return proc.stdout, ".NET Cryptographic RNG (System.Security.Cryptography.RandomNumberGenerator)"

    # Cross-platform fallback when executed on Linux lab machines
    return os.urandom(num_bytes), "OS CSPRNG (Windows CNG cross-platform fallback)"


def generate_all_samples(
    num_bytes: int = ONE_MB, output_dir: str = DEFAULT_OUTPUT_DIR
) -> Dict[str, Dict[str, object]]:
    """
    Generates 1 MB binary files for all three sources and saves them under
    datasets/rng_samples/.
    """
    os.makedirs(output_dir, exist_ok=True)
    generators = {
        "linux_urandom": ("urandom_1mb.bin", generate_linux_urandom),
        "openssl_rand": ("openssl_1mb.bin", generate_openssl_rand),
        "windows_cng": ("windows_cng_1mb.bin", generate_windows_cng),
    }

    results: Dict[str, Dict[str, object]] = {}
    for key, (filename, gen_func) in generators.items():
        data, method_desc = gen_func(num_bytes)
        file_path = os.path.join(output_dir, filename)
        with open(file_path, "wb") as f:
            f.write(data)
        results[key] = {
            "name": key,
            "method": method_desc,
            "file_path": file_path,
            "size_bytes": len(data),
            "first_16_hex": data[:16].hex(),
            "data": data,
        }
    return results


def run_task1_demo() -> None:
    print("=" * 76)
    print("TASK 1: GENERATING 1 MB (1,048,576 BYTES) OF RANDOM DATA PER MECHANISM")
    print("=" * 76)
    samples = generate_all_samples(ONE_MB)
    for key, info in samples.items():
        print(f"\n[{key.upper()}]")
        print(f"  Mechanism Used : {info['method']}")
        print(f"  Saved File     : {os.path.relpath(str(info['file_path']), _PROJECT_ROOT)}")
        print(f"  Size Generated : {info['size_bytes']:,} bytes ({info['size_bytes'] / ONE_MB:.2f} MB)")
        print(f"  First 16 Bytes : {info['first_16_hex']}")


if __name__ == "__main__":
    run_task1_demo()