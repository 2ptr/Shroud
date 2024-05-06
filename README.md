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
                                  
usage: Shroud [-h] (--file FILE | --msf | --shell) [-L LHOST] [-P LPORT] (--xor | --delta) [--dont-encrypt] [--process PROCESS] [--export EXPORT] output

Generate evasive shellcode droppers.

positional arguments:
  output                Output dropper file. Specify .exe or .dll.

optional arguments:
  -h, --help            show this help message and exit
  -L LHOST, --lhost LHOST
                        Listener IP for templates.
  -P LPORT, --lport LPORT
                        Listener port for templates.
  --dont-encrypt        Don't encrypt the payload. Default is AES-256
  --process PROCESS     Target process name for creation or remote injection. Default is RuntimeBroker.exe.
  --export EXPORT       Exported function name for DLL.

shellcode:
  --file FILE           Custom shellcode file
  --msf                 Generate a Meterpreter template payload.
  --shell               Generate a reverse shell (cmd) template payload.

encryption:
  --xor                 Use XOR encryption.
  --delta               Use delta encoding from Red Siege's delta encoder.
```

## Current Technique
Currently, Shroud can use shellcode templates via `msfvenom` or custom shellcode files.

Shroud has several encryption and encoding options. The default method is AES-256 encryption using [TinyAES](https://github.com/kokke/tiny-AES-c). Other options include XOR and deltas using [Red Siege's encoder](https://github.com/RedSiege/Delta-Encoder).

By default, Shroud launches a camoflauged (PPID, thread address, working directory) `RuntimeBroker.exe` process. Future updates will allow you to specify victim processes and camoflauge parameters. 

Strings are currently hardcoded. Hashing will be the first major update.

Injection is handled by dynamically-linked calls to standard API functions like `VirtualAllocEx` and `WriteProcessMemory`. I would strongly prefer to use remote file mapping, but I have yet to find a method for cross-compiling `OneCore.lib`. 

Execution is handled by a stomp for an `ntdll.dll` function not used in `RuntimeBroker`. Currently this is hardcoded to be `RtlFreeMemoryStream`. Future updates will choose a random (hashed) `ntdll.dll` export before compiling.

The final function call is handled with `CreateRemoteThread`. I may change this in the future.

## To-Do
- AES-256
- String hashing / polymorphism
- DLL format
- Persistence options
