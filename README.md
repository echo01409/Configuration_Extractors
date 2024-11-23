# RAT-Catching

This repository was created to house all of my analysis of remote access trojan kits. The majority of these kits are written in .NET and any tooling created will have this in mind, unless otherwise stated.

Currently covered RATS include:

* X-worm





## Scripts

Scripts that are specific to a given RAT will be contained insisde that RATs folder in this repo. The scripts outlined below are agnostic and can help you in analysing any RAT written in .NET.

### Hex to Key script `hex-array2key.py` usage

Downlaod the script, open it in notepad or another text editor, and paste in your byte array, as below:

```
import re

# Key Bytes
key_data = """
		[0]	0x6D	byte
		[1]	0x38	byte
		[2]	0xFE	byte
		[3]	0x6B	byte
		[4]	0xC2	byte
		[5]	0x19	byte
		[6]	0xE6	byte
		[7]	0xA7	byte
		[8]	0x4E	byte
		[9]	0x38	byte
		[10]	0xFA	byte
		[11]	0x17	byte
		[12]	0xDA	byte
		[13]	0x4E	byte
		[14]	0x9B	byte
		[15]	0x6D	byte
		[16]	0x38	byte
		[17]	0xFE	byte
		[18]	0x6B	byte
		[19]	0xC2	byte
		[20]	0x19	byte
		[21]	0xE6	byte
		[22]	0xA7	byte
		[23]	0x4E	byte
		[24]	0x38	byte
		[25]	0xFA	byte
		[26]	0x17	byte
		[27]	0xDA	byte
		[28]	0x4E	byte
		[29]	0x9B	byte
		[30]	0x4C	byte
		[31]	0x00	byte
"""

# IV Bytes
iv_data = """
		[0]	0x2D	byte
		[1]	0x4B	byte
		[2]	0x7F	byte
		[3]	0xB0	byte
		[4]	0x12	byte
		[5]	0x65	byte
		[6]	0x79	byte
		[7]	0x22	byte
		[8]	0xC6	byte
		[9]	0xCF	byte
		[10]	0x23	byte
		[11]	0x9C	byte
		[12]	0xB6	byte
		[13]	0xE6	byte
		[14]	0x74	byte
		[15]	0xAD	byte
"""

key_hex_values = re.findall(r'0x([0-9A-Fa-f]{2})',key_data)
iv_hex_values = re.findall(r'0x([0-9A-Fa-f]{2})',iv_data)

key_hex_string = "".join(key_hex_values)
iv_hex_string = "".join(iv_hex_values)

print("[+] Key:", key_hex_string)
print("[+] IV:", iv_hex_string)
```

After saving the file, you'll be able to run the script using `cmd.exe`. Expected ouput is shown below: 

```
C:\Users\normal\Desktop> python hex-array2key.py

[-] Key: 6D38FE6BC219E6A74E38FA17DA4E9B6D38FE6BC219E6A74E38FA17DA4E9B4C00
[-] IV:  2D4B7FB012657922C6CF239CB6E674AD

```
