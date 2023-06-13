'''
Implement TOTP
'''
import calendar
import datetime
import hashlib
import time
from typing import Any, Optional, Union
import unicodedata
from hmac import compare_digest
from typing import Dict, Optional, Union
from urllib.parse import quote, urlencode, urlparse
import base64
import hmac


class OTP(object):
    def __init__(
        self,
        s: str,
        digits: int = 6,
        digest: Any = hashlib.sha1,
        name: Optional[str] = None,
        issuer: Optional[str] = None,
    ) -> None:
        self.digits = digits
        if digits > 10:
            raise ValueError("digits must be no greater than 10")
        self.digest = digest
        self.secret = s
        self.name = name or "Secret"
        self.issuer = issuer

    def generate_otp(self, input: int) -> str:
        if input < 0:
            raise ValueError("input must be positive integer")
        hasher = hmac.new(self.byte_secret(), self.int_to_bytestring(input), self.digest)
        hmac_hash = bytearray(hasher.digest())
        offset = hmac_hash[-1] & 0xF
        code = (
            (hmac_hash[offset] & 0x7F) << 24
            | (hmac_hash[offset + 1] & 0xFF) << 16
            | (hmac_hash[offset + 2] & 0xFF) << 8
            | (hmac_hash[offset + 3] & 0xFF)
        )
        str_code = str(10_000_000_000 + (code % 10**self.digits))
        return str_code[-self.digits :]

    def byte_secret(self) -> bytes:
        secret = self.secret
        missing_padding = len(secret) % 8
        if missing_padding != 0:
            secret += "=" * (8 - missing_padding)
        return base64.b32decode(secret, casefold=True)

    @staticmethod
    def int_to_bytestring(i: int, padding: int = 8) -> bytes:
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8
        return bytes(bytearray(reversed(result)).rjust(padding, b"\0"))


class TOTP(OTP):
    def __init__( self, s: str, digits: int = 6, digest: Any = None, name: Optional[str] = None, issuer: Optional[str] = None, interval: int = 30 ) -> None:
        if digest is None:
            digest = hashlib.sha1

        self.interval = interval
        super().__init__(s=s, digits=digits, digest=digest, name=name, issuer=issuer)

    def now(self) -> str:
        return self.generate_otp(self.timecode(datetime.datetime.now()))

    def timecode(self, for_time: datetime.datetime) -> int:
        if for_time.tzinfo:
            return int(calendar.timegm(for_time.utctimetuple()) / self.interval)
        else:
            return int(time.mktime(for_time.timetuple()) / self.interval)


'''
Using TOTP solve problem
'''
import pyotp
import time
from pwn import *


def TOTP_new(shared_secret):
    totp = TOTP(shared_secret)
    return totp.now()

def TOTP_old(shared_secret):
    totp = pyotp.TOTP(shared_secret)
    return totp.now()

test = "5VZG4WBEPL3NLPG7QTLDLD3EWOM37IDE"
print(TOTP_new(test))
print(TOTP_old(test))

# r = remote("cns.csie.org", 17504)
# context.arch = 'amd64'
# r.recvline()

# for i in range(128):
#     key = r.recvline().strip().split()[-1].decode()
#     r.sendline(TOTP_new(key).encode())


# r.interactive()