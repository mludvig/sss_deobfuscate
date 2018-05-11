#!/usr/bin/env python3

# Decrypt / De-obfuscate sssd.conf passwords
# By Michael Ludvig

# ~ # cat /etc/sssd/sssd.conf
# [domain/LDAP]
# ldap_default_authtok = AAAQABagVAjf9KgUyIxTw3A+HUfbig7N1+L0qtY4xAULt2GYHFc1B3CBWGAE9ArooklBkpxQtROiyCGDQH+VzLHYmiIAAQID
# ldap_default_authtok_type = obfuscated_password
#
# ~ # ./sss_deobfuscate AAAQABagVAjf9KgUyIxTw3A+HUfbig7N1+L0qtY4xAULt2GYHFc1B3CBWGAE9ArooklBkpxQtROiyCGDQH+VzLHYmiIAAQID
# Decoded password: Passw0rd

# Inspired by sssd/src/util/crypto/libcrypto/crypto_obfuscate.c
# All the variable names are taken from there (hence the strange names)

import sys
import base64
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

crypto_mech_data = [
    {
        # AES-256-CBC
        "algo": algorithms.AES,
        "mode": modes.CBC,
        "keylen": 32,
        "bsize": 16,
    }
]

try:
    ldap_default_authtok = sys.argv[1]
except:
    print("Usage: %s AAAQABag...")
    quit(1)

# Decode from Base64 to Binary
tok_bin = base64.b64decode(ldap_default_authtok)
#print("Decoded: %d" % len(tok_bin))

# Method and BufSize (2x uint16)
p, p_end = 0, 4
method, ctsize = struct.unpack('HH', tok_bin[p:p_end])
try:
    mech_props = crypto_mech_data[method]
except ValueError:
    print("Unknown method: 0x%02x" % method)
    quit(1)

#print("Method:  %s" % mech_props['cipher'])
#print("CTsize: %d" % ctsize)

# Encryption key
p, p_end = p_end, p_end+mech_props['keylen']
keybuf = tok_bin[p:p_end]
#print("Key len: %d" % len(keybuf))

# Initialisation Vector
p, p_end = p_end, p_end+mech_props['bsize']
ivbuf = tok_bin[p:p_end]
#print("IV len:  %d" % len(ivbuf))

# Crypto text
p, p_end = p_end, p_end+ctsize
cryptotext = tok_bin[p:p_end]
#print("C/Text:  %d" % len(cryptotext))

# Decrypt!
cipher = Cipher(mech_props['algo'](keybuf), mech_props['mode'](ivbuf), backend=default_backend())
decryptor = cipher.decryptor()
pwdbuf = decryptor.update(cryptotext) + decryptor.finalize()

# Strip padding and trailing \x00 (it's a C-string) and convert to str
password = pwdbuf.split(b'\x00')[0].decode('ascii')

print("Decoded password: %s" % password)
