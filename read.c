#include <stdio.h>
#include <inttypes.h>
#include  <malloc.h> 
#include <Windows.h>

#define uprintf printf

int64_t read_sectors(HANDLE hDrive, uint64_t SectorSize,
    uint64_t StartSector, uint64_t nSectors,
    void* pBuf)
{
    LARGE_INTEGER ptr;
    DWORD Size;

    if ((nSectors * SectorSize) > 0xFFFFFFFFUL)
    {
        uprintf("read_sectors: nSectors x SectorSize is too big\n");
        return -1;
    }
    Size = (DWORD)(nSectors * SectorSize);

    ptr.QuadPart = StartSector * SectorSize;
    if (!SetFilePointerEx(hDrive, ptr, NULL, FILE_BEGIN))
    {
        uprintf("read_sectors: Could not access sector 0x%08" PRIx64 " - %s\n", StartSector, WindowsErrorString());
        return -1;
    }

    if ((!ReadFile(hDrive, pBuf, Size, &Size, NULL)) || (Size != nSectors * SectorSize))
    {
        uprintf("read_sectors: Read error %s\n", (GetLastError() != ERROR_SUCCESS) ? WindowsErrorString() : "");
        uprintf("  Read: %d, Expected: %" PRIu64 "\n", Size, nSectors * SectorSize);
        uprintf("  StartSector: 0x%08" PRIx64 ", nSectors: 0x%" PRIx64 ", SectorSize: 0x%" PRIx64 "\n", StartSector, nSectors, SectorSize);
    }

    return (int64_t)Size;
}