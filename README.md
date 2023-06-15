# PEB-NTHeader-Tomfoolery
A quick implementation of GetProcAddress and GetModuleHandle winapi functions to obfuscate kernel32 and function calls within the current running process for 64 bit processes.
(change __readgsqword(0x60) to __readfsdword(0x30) for 32 bit)

(NOT DLL-ABLE YET!)

Super Helpful Source:
https://www.cynet.com/attack-techniques-hands-on/defense-evasion-techniques-peb-edition/
