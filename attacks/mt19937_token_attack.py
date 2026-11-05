"""
Assignment 10 - Part B: Predictable Password Reset Token Generation & Attack
Uses the exact same MT19937 byte-extraction procedure from Part A.
"""

import os
import sys
import time
from typing import Dict, List, Optional, Tuple

# Append project root to the END of sys.path so stdlib 'math' is never shadowed by local 'math/'
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from modern.mt19937_cipher import mt19937_keystream


def generate_token_from_timestamp(timestamp: int, token_length: int = 16) -> bytes:
    """
    Step 7: Seed MT19937 with timestamp T; generate 16 consecutive 8-bit outputs
    and combine them into a 16-byte token.
    """
    return bytes(mt19937_keystream(timestamp, token_length))


def simulate_password_reset_token(custom_timestamp: Optional[int] = None) -> Tuple[int, bytes, str]:
    """
    Steps 6, 7 & 8: Record Unix timestamp T (integer seconds), generate the 16-byte
    reset token using MT19937(T), and format it in hexadecimal.
    """
    timestamp_t = int(time.time()) if custom_timestamp is None else int(custom_timestamp)
    token_bytes = generate_token_from_timestamp(timestamp_t, token_length=16)
    token_hex = token_bytes.hex()
    return timestamp_t, token_bytes, token_hex


def predict_reset_token_timestamp(
    observed_token_hex: str,
    reference_time: int,
    window_seconds: int = 300,
) -> Dict[str, object]:
    """
    Steps 9, 10 & 11: Treat the token as observed by an attacker who knows generation
    occurred within [T - 300, T + 300] seconds. Test every timestamp in the interval,
    count candidates tested, and regenerate the token to verify the match.
    """
    observed_bytes = bytes.fromhex(observed_token_hex)
    start_ts = reference_time - window_seconds
    end_ts = reference_time + window_seconds

    timestamps_tested = 0
    first_match_attempt: Optional[int] = None
    matching_timestamps: List[int] = []

    for candidate_ts in range(start_ts, end_ts + 1):
        timestamps_tested += 1
        candidate_token = generate_token_from_timestamp(candidate_ts, token_length=16)
        if candidate_token == observed_bytes:
            matching_timestamps.append(candidate_ts)
            if first_match_attempt is None:
                first_match_attempt = timestamps_tested

    recovered_ts = matching_timestamps[0] if matching_timestamps else None
    regenerated_hex = (
        generate_token_from_timestamp(recovered_ts, token_length=16).hex()
        if recovered_ts is not None
        else ""
    )
    verified = regenerated_hex == observed_token_hex

    return {
        "search_interval": (start_ts, end_ts),
        "timestamps_tested": timestamps_tested,
        "first_match_attempt": first_match_attempt,
        "matching_timestamps": matching_timestamps,
        "recovered_timestamp": recovered_ts,
        "regenerated_token_hex": regenerated_hex,
        "verified": verified,
    }


def run_part_b_demo() -> None:
    print("=" * 72)
    print("PART B: PREDICTABLE PASSWORD RESET TOKEN GENERATION & PREDICTION")
    print("=" * 72)

    # Steps 6-8: Token Generation
    timestamp_t, _, token_hex = simulate_password_reset_token()
    print("\n[Steps 6, 7 & 8] Simulated Application Reset Token Generation:")
    print(f"  Recorded Timestamp (T) : {timestamp_t} (Unix seconds)")
    print(f"  Generated 16B Token    : {token_hex}")

    # Steps 9-11: Token Prediction across [T - 300, T + 300]
    attack_res = predict_reset_token_timestamp(
        observed_token_hex=token_hex,
        reference_time=timestamp_t,
        window_seconds=300,
    )
    start_ts, end_ts = attack_res["search_interval"]
    print("\n[Steps 9, 10 & 11] Attacker Timestamp Brute-Force & Token Verification:")
    print(f"  Observed Token (hex)   : {token_hex}")
    print(f"  Search Interval        : [{start_ts}, {end_ts}] (T-300 to T+300 s)")
    print(f"  Timestamps Tested      : {attack_res['timestamps_tested']} (Match at attempt #{attack_res['first_match_attempt']})")
    print(f"  Matching Timestamp(s)  : {attack_res['matching_timestamps']}")
    print(f"  Recovered Timestamp    : {attack_res['recovered_timestamp']}")
    print(f"  Regenerated Token (hex): {attack_res['regenerated_token_hex']}")
    print(f"  Token Match Verified   : {'SUCCESS' if attack_res['verified'] else 'FAILED'}")


if __name__ == "__main__":
    run_part_b_demo()