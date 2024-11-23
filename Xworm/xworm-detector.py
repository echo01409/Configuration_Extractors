import argparse

search_bytes_hex = bytearray.fromhex("4D 00 6F 00 64 00 69 00 66 00 69 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6C 00 6C 00 79 00 21")

search_bytes_str = bytearray("_CorExeMain", 'utf-16-le')

parser = argparse.ArgumentParser(description='Checks a binary to identify it as Xworm based on unique indicators.')
parser.add_argument('-f', '--file', help='Path to the binary file', required=True)

args = parser.parse_args()

with open(args.file, 'rb') as f:
    file_data = f.read()

index_hex = file_data.find(search_bytes_hex)
index_str = file_data.find(search_bytes_str)

if index_hex != -1 or index_str != -1:
    print(f'[+] Xworm detected!')
else:
    print('[!] No Xworm here.')
