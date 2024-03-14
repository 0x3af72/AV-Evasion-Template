# AV EVASION

AV Evasion techniques to be used in ESAP

Disclaimer: This is just a proof-of-concept. It is for educational purposes only.

**NOTE**: This version is outdated now. Refer to [ESAP](https://github.com/0x3af72/ESAP)'s source code for an improved version.

## Shellcode injection

is shellcode injection necessary at this stage?

## API hashing

API hashing using modified djb2 hash function to hide WINAPI functions.

## String encryption

No more strings can be found when analyzing the file.

## Shellcode execution

We use pe2shc.exe to convert the PE to shellcode.

Shellcode is executed in main.exe

## Shellcode encryption

Shellcode is encrypted using encrypt.exe

## Sandbox evasion

This is done by simply checking the current computer's specs

CPU > 4 cores, RAM > 4GB, HDD > 100GB
