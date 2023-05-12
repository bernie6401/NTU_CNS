#! /usr/bin/env python3
from public import pk1, pk2
# from secret import flag2, flag3, secret_seed
import hashlib
from binascii import unhexlify
from Crypto.Util.number import bytes_to_long
import signal