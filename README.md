# Shroud
Evasive malware generation tool for quick shellcode droppers.

## Usage

```
.▄▄ ·  ▄ .▄▄▄▄        ▄• ▄▌·▄▄▄▄  
▐█ ▀. ██▪▐█▀▄ █· ▄█▀▄ █▪██▌██· ██ 
▄▀▀▀█▄██▀▀█▐▀▀▄ ▐█▌.▐▌█▌▐█▌▐█▪ ▐█▌
▐█▄▪▐███▌▐▀▐█•█▌▐█▌.▐▌▐█▄█▌██. ██ 
 ▀▀▀▀ ▀▀▀ ·.▀  ▀ ▀█▄▀▪ ▀▀▀ ▀▀▀▀▀•                                          
                                                
                        by twopoint
Generate evasive shellcode droppers.

positional arguments:
  output                Output dropper file. Specify .exe or .dll.

options:
  -h, --help            show this help message and exit
  -L LHOST, --lhost LHOST
                        Listener IP for templates.
  -P LPORT, --lport LPORT
                        Listener port for templates.
  --export EXPORT       Exported function name for DLL.
  --process PROCESS     Target process name for creation or remote injection. Default is RuntimeBroker.exe.
```

## Current Technique
Currently, Shroud can use shellcode templates via `msfvenom` or custom shellcode files. These payloads are XOR encrypted.

The Shroud dropper searches for instances of `svchost.exe` running under the current user context and launches a `RuntimeBroker.exe` with a spoofed PPID of the `svchost.exe` process.

Injection is handled by dynamically-linked calls to standard API functions like `VirtualAllocEx` and `WriteProcessMemory`.

Execution is handled similarly with `CreateRemoteThread`.

## Results
Although quite primitive, Shroud is able to evade the vast majority of AV engines on VirusTotal:

![Virustotal](./vt.png)

Future methods will improve this.

## To-Do
- Encryption (AES, RC4, XOR)
- "Aggressive" mode (enumerate autoescalation and persistence methods)
