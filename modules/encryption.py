import argparse
import subprocess
import os
from itertools import cycle
from RC4Encryption import RC4Encryption

def encryptRC4(shellcode):

	key = os.urandom(32) # RC4 KEY LENGTH!
	firstbyte = key[0]

	rc4 = RC4Encryption(key)
	rc4.make_key()
	encrypted = rc4.encrypt(b''.join(shellcode))

	# XOR'ing RC4 key
	brutekey = os.urandom(1)
	encKey = bytes(a ^ b for a, b in zip(key, cycle(brutekey)))

	return encrypted, encKey, firstbyte

def rc4Blob(encKey, firstbyte):

	# Paste key and firstbyte
	blob = f"\tBYTE bFirstByte = 0x{firstbyte.to_bytes(1,byteorder='big').hex()};\n"
	blob += "\tPBYTE pKey = NULL;\n"
	blob += "\tBYTE pEncKey[] = { "
	for i in range(0,len(encKey)):
		if i != len(encKey)-1:
			blob += f"0x{encKey[i].to_bytes(1,byteorder='big').hex()}, "
		else:
			blob += f"0x{encKey[i].to_bytes(1,byteorder='big').hex()} " + "};\n"
	blob += "\tBruteDecryption(bFirstByte, pEncKey, sizeof(pEncKey), &pKey);\n"
	blob += "\tRc4Context ctx = { 0 };\n"
	blob += "\tBYTE pTemp[sizeof(pPayload)];\n"
	blob += "\trc4Init(&ctx, pKey, sizeof(pEncKey));\n"
	blob += "\trc4Cipher(&ctx, pPayload, pTemp, sizeof(pPayload));\n"
	blob += """\tfor (int i = 0;i < sizeof(pPayload);i++)
	{
		pPayload[i] = pTemp[i];
	}\n"""

	return blob