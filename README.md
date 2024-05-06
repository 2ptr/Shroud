# Shroud
Evasive malware generation tool for quick shellcode droppers. A lightweight spiritual successor to [Mallet](https://github.com/Jake123otte1/Mallet)

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
Currently, Shroud can use shellcode templates via `msfvenom` or custom shellcode files. These payloads are delta-encoded using [Red Siege's encoder](https://github.com/RedSiege/Delta-Encoder). XOR is also available.

The Shroud dropper searches for instances of `svchost.exe` running under the current user context and launches a `RuntimeBroker.exe` with a spoofed PPID of the `svchost.exe` process.

Injection is handled by dynamically-linked calls to standard API functions like `VirtualAllocEx` and `WriteProcessMemory`.

Execution is handled by a stomp for an `ntdll.dll` function not used in `RuntimeBroker`. The final function call is handled with `CreateRemoteThread`.

Future versions will improve various aspects of the tool.

## To-Do
- AES-256
- Persistence options
- String hashing / polymorphism
