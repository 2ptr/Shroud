# Shroud
Malware generation tool for custom shellcode droppers. Intended to be a lightweight successor to [Mallet](https://github.com/Jake123otte1/Mallet). 

## Setup

Clone the repo and use the `setup.sh` script in the `setup` folder to download required packages.

## Usage

```
.▄▄ ·   ▄ .▄ ▄▄▄        ▄• ▄▌ ·▄▄▄▄  
▐█ ▀.  ██▪▐█ ▀▄ █· ▄█▀▄ █▪██▌ ██· ██ 
▄▀▀▀█▄ ██▀▀█ ▐▀▀▄ ▐█▌.▐▌█▌▐█▌ ▐█▪ ▐█▌
▐█▄▪▐█ ██▌▐▀ ▐█•█▌▐█▌.▐▌▐█▄█▌ ██. ██ 
 ▀▀▀▀  ▀▀▀ · .▀  ▀ ▀█▄▀▪ ▀▀▀  ▀▀▀▀▀•                                                                                       
                        by twopoint
                                  
usage: Shroud [-h] (--file FILE | --msf | --shell) [-L LHOST] [-P LPORT] [--dont-encrypt] output

Generate evasive shellcode droppers.

positional arguments:
  output                Output dropper file. Specify .exe or .dll.

options:
  -h, --help            show this help message and exit
  -L LHOST, --lhost LHOST
                        Listener IP for templates.
  -P LPORT, --lport LPORT
                        Listener port for templates.
  --dont-encrypt        Don't encrypt the payload.

shellcode:
  --file FILE           Custom shellcode file
  --msf                 Generate a Meterpreter template payload.
  --shell               Generate a reverse shell (cmd) template payload.
```

## Current Technique
Shroud can use shellcode templates via `msfvenom` or custom shellcode files.

The tool features RC4 and XOR decryption with some brute-forcing at runtime. The exact process may be found in `modules/encryption.py`.

By default, Shroud launches a camoflauged `RuntimeBroker.exe` process. This will eventually instead be one of a variety of innocuous windows processes (`ctfmon.exe`,`svchost.exe`,etc).

Insertion is handled by SysWhispers indirect syscalls to normal calls like `NtProtectVirtualMemory`. However, the base address is an exported function from `ntdll.dll` for thread address camo. Execution is just `NtCreateThreadEx`.

## Performance

Shroud is still early in development but performs well enough as of right now:

![VirusTotal](./setup/vt.png)

## Issues

- Several hardcoded strings. I'd like to get everything in syscalls but there are some problems. Compile time hashing is not an issue as we are updating the shell every compilation but the `GetProcAddress` replacement I was using has since been signatured by MDE. I will need to rewrite but it will take some time.
- Mapping injection issues. For whatever reason, my attempts to use `NtCreateSection` as a part of mapping injection have been in vain when the target address is a remote `ntdll` export. I don't really know why, but I am not willing to give up the thread camo for only slightly better injection heuristics.
- Some stomps don't work right now. I am not entirely sure why but some stomps (especially `Zw` calls) won't work. I can probably debug this by just reading NTSTATUSes but right now I have just been slowly removing failed stomps from the vulnerable export list.

## To-Do
- Work on version 2.0:
    - Function stomp via mapping injection at address
    - More host processes
- Future ideas:
    - DLL format
    - Normal persistence options (users, schtask, services)
