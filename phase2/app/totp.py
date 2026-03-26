"""
Manual TOTP (RFC 6238) / HOTP (RFC 4226) implementation.
NO third-party TOTP libraries are used.
Only Python built-ins: hashlib, struct, time, os, base64.
"""

import hashlib
import hmac as _hmac  # Python standard-library hmac — NOT a TOTP library
import struct
import time
import os
import base64


# ---------------------------------------------------------------------------
# Low-level: HMAC-SHA1
# ---------------------------------------------------------------------------

def hmac_sha1(key: bytes, msg: bytes) -> bytes:
    """
    Compute HMAC-SHA1 manually following RFC 2104.

    HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
    Where:
        K' = K padded / hashed to block size (64 bytes for SHA-1)
        ipad = 0x36 repeated 64 times
        opad = 0x5C repeated 64 times
    """
    BLOCK_SIZE = 64  # SHA-1 block size in bytes

    # If key is longer than block size, hash it first
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha1(key).digest()

    # Pad key to block size with zeros
    key = key + b'\x00' * (BLOCK_SIZE - len(key))

    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)

    inner = hashlib.sha1(ipad + msg).digest()
    outer = hashlib.sha1(opad + inner).digest()
    return outer


# ---------------------------------------------------------------------------
# HOTP (RFC 4226): HMAC-based One-Time Password
# ---------------------------------------------------------------------------

def hotp(secret_b32: str, counter: int) -> str:
    """
    Compute a 6-digit HOTP value.

    Steps (RFC 4226):
      1. Decode base32 secret to raw bytes
      2. Pack counter as big-endian 8-byte integer
      3. Compute HMAC-SHA1(key, counter_bytes)
      4. Dynamic truncation: offset = last nibble of HMAC
      5. Extract 31-bit integer from 4 bytes at offset
      6. Modulo 10^6 → 6-digit zero-padded string
    """
    # Step 1: decode base32 secret (add padding if necessary)
    secret_b32 = secret_b32.upper()
    padding = (8 - len(secret_b32) % 8) % 8
    secret_bytes = base64.b32decode(secret_b32 + '=' * padding)

    # Step 2: counter as 8-byte big-endian
    counter_bytes = struct.pack('>Q', counter)

    # Step 3: HMAC-SHA1
    mac = hmac_sha1(secret_bytes, counter_bytes)

    # Step 4: dynamic truncation — offset is low nibble of last byte
    offset = mac[-1] & 0x0F

    # Step 5: extract 31-bit integer (mask the MSB)
    code_int = struct.unpack('>I', mac[offset:offset + 4])[0] & 0x7FFFFFFF

    # Step 6: 6-digit OTP
    otp = code_int % (10 ** 6)
    return f'{otp:06d}'


# ---------------------------------------------------------------------------
# TOTP (RFC 6238): Time-based One-Time Password
# ---------------------------------------------------------------------------

TOTP_STEP = 30  # seconds per time step


def totp(secret_b32: str, unix_time: float | None = None) -> str:
    """
    Compute the current 6-digit TOTP code.
    Uses 30-second time steps (standard).
    """
    if unix_time is None:
        unix_time = time.time()
    counter = int(unix_time) // TOTP_STEP
    return hotp(secret_b32, counter)


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    """
    Verify a TOTP code against the current time with a ±window tolerance.
    window=1 → accepts codes from [T-1, T, T+1] (±30 seconds).
    """
    now = time.time()
    current_counter = int(now) // TOTP_STEP
    for delta in range(-window, window + 1):
        expected = hotp(secret_b32, current_counter + delta)
        if _hmac.compare_digest(expected, str(code).zfill(6)):
            return True
    return False


# ---------------------------------------------------------------------------
# Utility: generate a secret and build otpauth:// URI
# ---------------------------------------------------------------------------

def generate_secret() -> str:
    """Generate a cryptographically random 20-byte base32 secret (no padding)."""
    raw = os.urandom(20)
    return base64.b32encode(raw).decode('utf-8').rstrip('=')


def get_totp_uri(secret: str, username: str, issuer: str = 'Phase2-2FA') -> str:
    """
    Build a standard otpauth:// URI for QR code generation.
    Format: otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}
    """
    from urllib.parse import quote
    label = quote(f'{issuer}:{username}')
    return (
        f'otpauth://totp/{label}'
        f'?secret={secret}'
        f'&issuer={quote(issuer)}'
        f'&algorithm=SHA1'
        f'&digits=6'
        f'&period=30'
    )
