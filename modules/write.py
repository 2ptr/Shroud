# Takes in a list of bytes for shellcode and a list of strings for decryption blob
def writePayload(shellcode, blob):

	## Read in runner template lines
	mainFileR = open("./build/template.c", "r")
	mainLines = mainFileR.readlines()
	mainFileR.close()
	
	## Loop over lines and update payload / size
	newLines = []
	for line in mainLines:

		### Update payload line
		if "BYTE pPayload[]" in line: ## XOR
			line = "\tBYTE pPayload[] = { "
			for j in range(0,len(shellcode)):
				if j != len(shellcode)-1:
					line += f"0x{shellcode[j].to_bytes(1,byteorder='big').hex()}, "
				else:
					line += f"0x{shellcode[j].to_bytes(1,byteorder='big').hex()}" + " };\n"
		
		### Update size line
		if "SIZE_T sPayloadSize" in line:
			line = f"\tSIZE_T sPayloadSize = {len(shellcode)};\n"

		newLines.append(line)

	## Update decryption protocol
	for i in range(0,len(newLines)):

		### Add in decryption blob
		if "SIZE_T sPayloadSize" in newLines[i]:
			newLines[i+1:i+1] = blob

	# Write to runner
	with open("./build/standard/main.c", mode="wt", encoding="utf-8") as mainFileW:
		for line in newLines:
			mainFileW.write(line)
	
	return