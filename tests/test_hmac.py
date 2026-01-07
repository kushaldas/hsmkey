"""Tests for HMAC key implementations."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives import hashes

from hsmkey import (
    PKCS11HMACKey,
    HSMKeyNotFoundError,
    HSMOperationError,
)


# HMAC key ID fixtures
@pytest.fixture
def hmac_sha1_key_id() -> bytes:
    """HMAC-SHA1 key ID."""
    return bytes([0x20])


@pytest.fixture
def hmac_sha256_key_id() -> bytes:
    """HMAC-SHA256 key ID."""
    return bytes([0x21])


@pytest.fixture
def hmac_sha384_key_id() -> bytes:
    """HMAC-SHA384 key ID."""
    return bytes([0x22])


@pytest.fixture
def hmac_sha512_key_id() -> bytes:
    """HMAC-SHA512 key ID."""
    return bytes([0x23])


class TestPKCS11HMACKeySHA1:
    """Tests for PKCS11HMACKey with SHA-1."""

    def test_sign_sha1(self, hsm_session, hmac_sha1_key_id):
        """Test HMAC-SHA1 signing."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha1_key_id)
        data = b"test data for HMAC-SHA1"

        mac = key.sign(data, hashes.SHA1())

        assert len(mac) == 20  # SHA-1 produces 160-bit output
        assert isinstance(mac, bytes)

    def test_sign_verify_sha1(self, hsm_session, hmac_sha1_key_id):
        """Test HMAC-SHA1 sign and verify roundtrip."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha1_key_id)
        data = b"test data for HMAC-SHA1 verification"

        mac = key.sign(data, hashes.SHA1())
        # Should not raise
        key.verify(data, mac, hashes.SHA1())

    def test_verify_sha1_failure(self, hsm_session, hmac_sha1_key_id):
        """Test HMAC-SHA1 verification failure with wrong data."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha1_key_id)
        data = b"original data"
        wrong_data = b"tampered data"

        mac = key.sign(data, hashes.SHA1())

        with pytest.raises(HSMOperationError):
            key.verify(wrong_data, mac, hashes.SHA1())

    def test_verify_sha1_wrong_mac(self, hsm_session, hmac_sha1_key_id):
        """Test HMAC-SHA1 verification failure with wrong MAC."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha1_key_id)
        data = b"test data"
        wrong_mac = b"\x00" * 20

        with pytest.raises(HSMOperationError):
            key.verify(data, wrong_mac, hashes.SHA1())

    def test_sign_by_label(self, hsm_session):
        """Test loading HMAC key by label."""
        key = PKCS11HMACKey(hsm_session, key_label="hmac-sha1")
        data = b"test data"

        mac = key.sign(data, hashes.SHA1())
        assert len(mac) == 20


class TestPKCS11HMACKeySHA256:
    """Tests for PKCS11HMACKey with SHA-256."""

    def test_sign_sha256(self, hsm_session, hmac_sha256_key_id):
        """Test HMAC-SHA256 signing."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        data = b"test data for HMAC-SHA256"

        mac = key.sign(data, hashes.SHA256())

        assert len(mac) == 32  # SHA-256 produces 256-bit output
        assert isinstance(mac, bytes)

    def test_sign_verify_sha256(self, hsm_session, hmac_sha256_key_id):
        """Test HMAC-SHA256 sign and verify roundtrip."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        data = b"test data for HMAC-SHA256 verification"

        mac = key.sign(data, hashes.SHA256())
        # Should not raise
        key.verify(data, mac, hashes.SHA256())

    def test_verify_sha256_failure(self, hsm_session, hmac_sha256_key_id):
        """Test HMAC-SHA256 verification failure with wrong data."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        data = b"original data"
        wrong_data = b"tampered data"

        mac = key.sign(data, hashes.SHA256())

        with pytest.raises(HSMOperationError):
            key.verify(wrong_data, mac, hashes.SHA256())

    def test_verify_sha256_wrong_mac(self, hsm_session, hmac_sha256_key_id):
        """Test HMAC-SHA256 verification failure with wrong MAC."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        data = b"test data"
        wrong_mac = b"\x00" * 32

        with pytest.raises(HSMOperationError):
            key.verify(data, wrong_mac, hashes.SHA256())

    def test_sign_by_label(self, hsm_session):
        """Test loading HMAC key by label."""
        key = PKCS11HMACKey(hsm_session, key_label="hmac-sha256")
        data = b"test data"

        mac = key.sign(data, hashes.SHA256())
        assert len(mac) == 32

    def test_deterministic_output(self, hsm_session, hmac_sha256_key_id):
        """Test that HMAC produces deterministic output for same input."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        data = b"test data for determinism"

        mac1 = key.sign(data, hashes.SHA256())
        mac2 = key.sign(data, hashes.SHA256())

        assert mac1 == mac2


class TestPKCS11HMACKeySHA384:
    """Tests for PKCS11HMACKey with SHA-384."""

    def test_sign_sha384(self, hsm_session, hmac_sha384_key_id):
        """Test HMAC-SHA384 signing."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha384_key_id)
        data = b"test data for HMAC-SHA384"

        mac = key.sign(data, hashes.SHA384())

        assert len(mac) == 48  # SHA-384 produces 384-bit output
        assert isinstance(mac, bytes)

    def test_sign_verify_sha384(self, hsm_session, hmac_sha384_key_id):
        """Test HMAC-SHA384 sign and verify roundtrip."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha384_key_id)
        data = b"test data for HMAC-SHA384 verification"

        mac = key.sign(data, hashes.SHA384())
        key.verify(data, mac, hashes.SHA384())


class TestPKCS11HMACKeySHA512:
    """Tests for PKCS11HMACKey with SHA-512."""

    def test_sign_sha512(self, hsm_session, hmac_sha512_key_id):
        """Test HMAC-SHA512 signing."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha512_key_id)
        data = b"test data for HMAC-SHA512"

        mac = key.sign(data, hashes.SHA512())

        assert len(mac) == 64  # SHA-512 produces 512-bit output
        assert isinstance(mac, bytes)

    def test_sign_verify_sha512(self, hsm_session, hmac_sha512_key_id):
        """Test HMAC-SHA512 sign and verify roundtrip."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha512_key_id)
        data = b"test data for HMAC-SHA512 verification"

        mac = key.sign(data, hashes.SHA512())
        key.verify(data, mac, hashes.SHA512())


class TestPKCS11HMACKeyGeneral:
    """General tests for PKCS11HMACKey."""

    def test_key_not_found(self, hsm_session):
        """Test that HSMKeyNotFoundError is raised for non-existent key."""
        key = PKCS11HMACKey(hsm_session, key_label="nonexistent-hmac-key")
        with pytest.raises(HSMKeyNotFoundError):
            key.sign(b"data", hashes.SHA256())

    def test_unsupported_algorithm(self, hsm_session, hmac_sha256_key_id):
        """Test that ValueError is raised for unsupported hash algorithm."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        # MD5 is not supported
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            key.sign(b"data", hashes.MD5())

    def test_key_equality(self, hsm_session, hmac_sha256_key_id):
        """Test key equality."""
        key1 = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        key2 = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        key3 = PKCS11HMACKey(hsm_session, key_label="hmac-sha256")

        assert key1 == key2
        assert key1 != key3  # Different identifiers
        assert key1 != "not a key"

    def test_key_hash(self, hsm_session, hmac_sha256_key_id):
        """Test key hashing."""
        key1 = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        key2 = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)

        assert hash(key1) == hash(key2)

    def test_key_copy(self, hsm_session, hmac_sha256_key_id):
        """Test key copying."""
        key1 = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        key2 = copy.copy(key1)

        assert key1 == key2
        assert key1 is not key2

    def test_key_repr(self, hsm_session, hmac_sha256_key_id):
        """Test key repr."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        repr_str = repr(key)

        assert "PKCS11HMACKey" in repr_str

    def test_empty_data(self, hsm_session, hmac_sha256_key_id):
        """Test HMAC with empty data."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        data = b""

        mac = key.sign(data, hashes.SHA256())
        assert len(mac) == 32
        key.verify(data, mac, hashes.SHA256())

    def test_large_data(self, hsm_session, hmac_sha256_key_id):
        """Test HMAC with large data."""
        key = PKCS11HMACKey(hsm_session, key_id=hmac_sha256_key_id)
        data = b"x" * 10000  # 10KB

        mac = key.sign(data, hashes.SHA256())
        assert len(mac) == 32
        key.verify(data, mac, hashes.SHA256())
