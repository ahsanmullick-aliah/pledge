"""Symmetric layer: AES-256-GCM data encryption, key wrapping, KDF and the
patient/auditor public-key wrap (X25519 ECIES with HKDF-SHA256 + AES-256-GCM)."""
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .pairing import gt_bytes


def kdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def kwk_from_gt(M, tau: str, version: int) -> bytes:
    """Key-wrapping key KWK = KDF(M, tau, v)."""
    return kdf(gt_bytes(M), b"PLEDGE|KWK|" + tau.encode() + b"|" + str(version).encode())


def aead_encrypt(key: bytes, pt: bytes, ad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, pt, ad)


def aead_decrypt(key: bytes, ct: bytes, ad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(ct[:12], ct[12:], ad)


def new_dek() -> bytes:
    return AESGCM.generate_key(bit_length=256)


@dataclass
class BoxKeyPair:
    """X25519 key pair used for the patient wrap W_p and the audit payloads."""
    sk: X25519PrivateKey

    @classmethod
    def generate(cls):
        return cls(X25519PrivateKey.generate())

    @property
    def pk(self) -> bytes:
        return self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def seal(pk: bytes, pt: bytes, ad: bytes = b"") -> bytes:
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(pk))
    epk = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = kdf(shared, b"PLEDGE|seal|" + epk + pk)
    return epk + aead_encrypt(key, pt, ad)


def open_sealed(kp: BoxKeyPair, ct: bytes, ad: bytes = b"") -> bytes:
    epk, body = ct[:32], ct[32:]
    shared = kp.sk.exchange(X25519PublicKey.from_public_bytes(epk))
    key = kdf(shared, b"PLEDGE|seal|" + epk + kp.pk)
    return aead_decrypt(key, body, ad)
