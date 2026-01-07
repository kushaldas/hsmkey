#!/usr/bin/env python3
"""Example: HMAC Operations with HSM-backed Keys.

This example demonstrates how to perform HMAC (Hash-based Message Authentication
Code) operations using secret keys stored in an HSM. The key material never
leaves the HSM - all HMAC operations are performed on the hardware.

Prerequisites:
    - SoftHSM2 installed and configured
    - Test keys imported (run: just setup)

Run with: uv run python examples/hmac_operations.py
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes

from hsmkey import SessionPool, PKCS11HMACKey


def main():
    # Configuration
    module_path = os.environ.get(
        "HSM_MODULE", "/usr/lib/softhsm/libsofthsm2.so"
    )
    token_label = os.environ.get("HSM_TOKEN", "hsmkey-test")
    pin = os.environ.get("HSM_PIN", "12345678")

    print("=" * 60)
    print("HMAC Operations Example - HSM-backed Secret Keys")
    print("=" * 60)

    # Create a session pool
    pool = SessionPool(
        module_path=module_path,
        token_label=token_label,
        user_pin=pin,
    )

    # Example 1: HMAC-SHA1
    print("\n1. HMAC-SHA1")
    print("-" * 40)

    with pool.session() as session:
        key = PKCS11HMACKey(session, key_label="hmac-sha1")
        data = b"Hello, World! This is a test message."

        # Compute HMAC
        mac = key.sign(data, hashes.SHA1())
        print(f"Data: {data.decode()}")
        print(f"HMAC-SHA1: {mac.hex()}")
        print(f"MAC length: {len(mac)} bytes ({len(mac) * 8} bits)")

        # Verify HMAC
        try:
            key.verify(data, mac, hashes.SHA1())
            print("Verification: SUCCESS")
        except Exception as e:
            print(f"Verification: FAILED - {e}")

    # Example 2: HMAC-SHA256
    print("\n2. HMAC-SHA256")
    print("-" * 40)

    with pool.session() as session:
        key = PKCS11HMACKey(session, key_label="hmac-sha256")
        data = b"Hello, World! This is a test message."

        # Compute HMAC
        mac = key.sign(data, hashes.SHA256())
        print(f"Data: {data.decode()}")
        print(f"HMAC-SHA256: {mac.hex()}")
        print(f"MAC length: {len(mac)} bytes ({len(mac) * 8} bits)")

        # Verify HMAC
        try:
            key.verify(data, mac, hashes.SHA256())
            print("Verification: SUCCESS")
        except Exception as e:
            print(f"Verification: FAILED - {e}")

    # Example 3: HMAC-SHA384
    print("\n3. HMAC-SHA384")
    print("-" * 40)

    with pool.session() as session:
        key = PKCS11HMACKey(session, key_label="hmac-sha384")
        data = b"Another message for HMAC-SHA384 testing."

        mac = key.sign(data, hashes.SHA384())
        print(f"Data: {data.decode()}")
        print(f"HMAC-SHA384: {mac.hex()}")
        print(f"MAC length: {len(mac)} bytes ({len(mac) * 8} bits)")

        key.verify(data, mac, hashes.SHA384())
        print("Verification: SUCCESS")

    # Example 4: HMAC-SHA512
    print("\n4. HMAC-SHA512")
    print("-" * 40)

    with pool.session() as session:
        key = PKCS11HMACKey(session, key_label="hmac-sha512")
        data = b"Final message for HMAC-SHA512 demonstration."

        mac = key.sign(data, hashes.SHA512())
        print(f"Data: {data.decode()}")
        print(f"HMAC-SHA512: {mac.hex()}")
        print(f"MAC length: {len(mac)} bytes ({len(mac) * 8} bits)")

        key.verify(data, mac, hashes.SHA512())
        print("Verification: SUCCESS")

    # Example 5: Verification Failure Detection
    print("\n5. Verification Failure Detection")
    print("-" * 40)

    with pool.session() as session:
        key = PKCS11HMACKey(session, key_label="hmac-sha256")
        data = b"Original message"
        tampered_data = b"Tampered message"

        mac = key.sign(data, hashes.SHA256())
        print(f"Original data: {data.decode()}")
        print(f"Tampered data: {tampered_data.decode()}")
        print(f"MAC computed for original: {mac.hex()[:32]}...")

        try:
            key.verify(tampered_data, mac, hashes.SHA256())
            print("Verification: UNEXPECTED SUCCESS")
        except Exception as e:
            print(f"Verification correctly failed: {type(e).__name__}")

    # Example 6: Multiple MACs with Same Key
    print("\n6. Multiple MACs with Same Key")
    print("-" * 40)

    with pool.session() as session:
        key = PKCS11HMACKey(session, key_label="hmac-sha256")

        messages = [
            b"First message",
            b"Second message",
            b"Third message",
        ]

        print("Computing MACs for multiple messages:")
        for i, msg in enumerate(messages, 1):
            mac = key.sign(msg, hashes.SHA256())
            key.verify(msg, mac, hashes.SHA256())
            print(f"  Message {i}: {msg.decode()}")
            print(f"  MAC: {mac.hex()[:32]}...")

    # Example 7: Using Key by ID
    print("\n7. Using Key by ID")
    print("-" * 40)

    with pool.session() as session:
        # Key ID 0x21 is hmac-sha256
        key = PKCS11HMACKey(session, key_id=bytes([0x21]))
        data = b"Message authenticated by key ID"

        mac = key.sign(data, hashes.SHA256())
        key.verify(data, mac, hashes.SHA256())
        print(f"Successfully used key by ID (0x21)")
        print(f"MAC: {mac.hex()[:32]}...")

    print("\n" + "=" * 60)
    print("HMAC examples completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
