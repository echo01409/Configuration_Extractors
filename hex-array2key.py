import re

# Key Bytes
key_data = """

# Put Hex byte array here for the AES Key

"""

# IV Bytes
iv_data = """

# Put Hex byte array here for the AES IV

"""

key_hex_values = re.findall(r'0x([0-9A-Fa-f]{2})',key_data)
iv_hex_values = re.findall(r'0x([0-9A-Fa-f]{2})',iv_data)

key_hex_string = "".join(key_hex_values)
iv_hex_string = "".join(iv_hex_values)

print("[-] Key:", key_hex_string)
print("[-] IV:", iv_hex_string)
