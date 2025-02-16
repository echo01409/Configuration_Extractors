from backports.pbkdf2 import pbkdf2_hmac
from base64 import b64decode
from malduck import aes, unpad

ascii_art = r"""
##################################
#    BH        _..----.._    _
#            .'  .--.    "-.(0)_
#'-.__.-'"'=:|   ,  _)_ \__ . c\'-..
#             '''------'---''---'-"
##################################
# REQUIRED LIBRARIES
    # pip install backports.pbkdf2
    # pip install malduck
##################################
# METADATA
    # Author: "Ben Hopkins"
    # Date: "2025-02-15"
    # Version: "1.0"
    # Description: Script to decode and decrypt async RAT configuration
#################################
"""
print(ascii_art)

# The key is usually found in the Client.Settings resource, the salt is hardcoded in the binary, populate both below
salt = bytes([])
aeskey = b""

# Get the configuration information from the Client.Settings resource and populate them below
config = {
    "[+] Ports": "",
    "[+] Hosts": "",
    "[+] Version": "",
    "[+] Install": "",
    "[+] MTX": "",
    "[+] Anti": "",
    "[+] Pastebin": "",
    "[+] BDOS": "",
    "[+] Group": "",
}

print("[*] Decrypted Configuration:\n")

aeskey = b64decode(aeskey)
decrypt_key = pbkdf2_hmac("sha1", aeskey, salt, 50000, 32)

for k, v in config.items():
    data = b64decode(v)
    iv = data[32:48]
    decrypted = unpad(aes.cbc.decrypt(decrypt_key, iv, data[48:]))
    print("\t{}: {}".format(k, decrypted.decode("utf-8")))
