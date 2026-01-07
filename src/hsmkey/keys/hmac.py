"""HMAC key implementation for HSM-backed operations."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from pkcs11 import KeyType, ObjectClass, SecretKey

from ..algorithms import HMAC_MECHANISMS, HASH_DIGEST_SIZES
from ..exceptions import HSMKeyNotFoundError, HSMOperationError

if TYPE_CHECKING:
    from pkcs11 import Session


class PKCS11HMACKey:
    """HMAC key backed by HSM via PKCS#11.

    This class provides HMAC operations using a secret key stored in an HSM.
    The key material never leaves the HSM - all HMAC operations are performed
    on the hardware.

    Example:
        >>> from hsmkey import SessionPool, PKCS11HMACKey
        >>> from cryptography.hazmat.primitives import hashes
        >>>
        >>> pool = SessionPool(...)
        >>> with pool.session() as session:
        ...     key = PKCS11HMACKey(session, key_label="my-hmac-key")
        ...     mac = key.sign(b"data to authenticate", hashes.SHA256())
        ...     key.verify(b"data to authenticate", mac, hashes.SHA256())
    """

    def __init__(
        self,
        session: Session,
        key_id: bytes | None = None,
        key_label: str | None = None,
    ) -> None:
        """Initialize HMAC key from HSM.

        Args:
            session: PKCS#11 session
            key_id: Key ID (CKA_ID) to look up the key
            key_label: Key label (CKA_LABEL) to look up the key

        Raises:
            HSMKeyNotFoundError: If no key matches the given id/label
        """
        self._session = session
        self._key_id = key_id
        self._key_label = key_label
        self._pkcs11_key: SecretKey | None = None

    @property
    def pkcs11_key(self) -> SecretKey:
        """Get PKCS#11 secret key object (lazy-loaded)."""
        if self._pkcs11_key is None:
            try:
                self._pkcs11_key = self._session.get_key(
                    key_type=KeyType.GENERIC_SECRET,
                    object_class=ObjectClass.SECRET_KEY,
                    id=self._key_id,
                    label=self._key_label,
                )
            except Exception as e:
                raise HSMKeyNotFoundError(
                    f"HMAC key not found: id={self._key_id}, label={self._key_label}"
                ) from e
        return self._pkcs11_key

    def sign(
        self,
        data: bytes,
        algorithm: hashes.HashAlgorithm,
    ) -> bytes:
        """Compute HMAC for the given data.

        Args:
            data: Data to authenticate
            algorithm: Hash algorithm (e.g., hashes.SHA256())

        Returns:
            HMAC value

        Raises:
            ValueError: If unsupported hash algorithm
            HSMOperationError: If HMAC operation fails
        """
        alg_type = type(algorithm)
        if alg_type not in HMAC_MECHANISMS:
            raise ValueError(f"Unsupported hash algorithm for HMAC: {algorithm.name}")

        mechanism = HMAC_MECHANISMS[alg_type]

        try:
            return self.pkcs11_key.sign(data, mechanism=mechanism)
        except HSMKeyNotFoundError:
            raise
        except Exception as e:
            raise HSMOperationError(f"HMAC sign failed: {e}") from e

    def verify(
        self,
        data: bytes,
        signature: bytes,
        algorithm: hashes.HashAlgorithm,
    ) -> None:
        """Verify HMAC for the given data.

        Args:
            data: Data that was authenticated
            signature: HMAC value to verify
            algorithm: Hash algorithm (e.g., hashes.SHA256())

        Raises:
            ValueError: If unsupported hash algorithm
            HSMOperationError: If verification fails (invalid HMAC)
        """
        alg_type = type(algorithm)
        if alg_type not in HMAC_MECHANISMS:
            raise ValueError(f"Unsupported hash algorithm for HMAC: {algorithm.name}")

        mechanism = HMAC_MECHANISMS[alg_type]

        try:
            result = self.pkcs11_key.verify(data, signature, mechanism=mechanism)
            if not result:
                raise HSMOperationError("HMAC verification failed: signature mismatch")
        except HSMOperationError:
            raise
        except Exception as e:
            raise HSMOperationError(f"HMAC verification failed: {e}") from e

    @property
    def key_size(self) -> int:
        """Get key size in bits."""
        # CKA_VALUE_LEN gives size in bytes
        value_len = self.pkcs11_key[ObjectClass.SECRET_KEY]
        if hasattr(self.pkcs11_key, "key_length"):
            return self.pkcs11_key.key_length * 8
        # Fallback: try to get from attributes
        return 256  # Default assumption

    def __copy__(self) -> "PKCS11HMACKey":
        """Create a shallow copy of the key."""
        new_key = PKCS11HMACKey.__new__(PKCS11HMACKey)
        new_key._session = self._session
        new_key._key_id = self._key_id
        new_key._key_label = self._key_label
        new_key._pkcs11_key = None
        return new_key

    def __deepcopy__(self, memo: dict) -> "PKCS11HMACKey":
        """Create a deep copy (same as shallow for HSM keys)."""
        return self.__copy__()

    def __eq__(self, other: object) -> bool:
        """Check equality based on key identifiers."""
        if not isinstance(other, PKCS11HMACKey):
            return False
        return self._key_id == other._key_id and self._key_label == other._key_label

    def __hash__(self) -> int:
        """Hash based on key identifiers."""
        return hash(("HMAC", self._key_id, self._key_label))

    def __repr__(self) -> str:
        """String representation."""
        return f"PKCS11HMACKey(key_id={self._key_id!r}, key_label={self._key_label!r})"
