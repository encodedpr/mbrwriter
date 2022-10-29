#include <stdio.h>
#include <inttypes.h>
#include  <malloc.h> 
#include <Windows.h>

#include"Header.h"

DWORD LastWriteError = 0;
BOOL large_drive = FALSE;

#define WRITE_TIMEOUT               5000
#define WRITE_RETRIES               4

#define FAC(f)                         ((f)<<16)

// A WriteFile() equivalent, with up to nNumRetries write attempts on error.
BOOL WriteFileWithRetry(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten, DWORD nNumRetries)
{
	DWORD nTry;
	BOOL readFilePointer;
	LARGE_INTEGER liFilePointer, liZero = { { 0,0 } };
	DWORD NumberOfBytesWritten;

	if (lpNumberOfBytesWritten == NULL)
		lpNumberOfBytesWritten = &NumberOfBytesWritten;

	// Need to get the current file pointer in case we need to retry
	readFilePointer = SetFilePointerEx(hFile, liZero, &liFilePointer, FILE_CURRENT);
	if (!readFilePointer)
		uprintf("Warning: Could not read file pointer %s", WindowsErrorString());

	if (nNumRetries == 0)
		nNumRetries = 1;
	for (nTry = 1; nTry <= nNumRetries; nTry++) {
		// Need to rewind our file position on retry - if we can't even do that, just give up
		if ((nTry > 1) && (!SetFilePointerEx(hFile, liFilePointer, NULL, FILE_BEGIN))) {
			uprintf("Could not set file pointer - Aborting");
			break;
		}
		if (WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, NULL)) {
			LastWriteError = 0;
			if (nNumberOfBytesToWrite == *lpNumberOfBytesWritten)
				return TRUE;
			// Some large drives return 0, even though all the data was written - See github #787 */
			if (large_drive && (*lpNumberOfBytesWritten == 0)) {
				uprintf("Warning: Possible short write");
				return TRUE;
			}
			uprintf("Wrote %d bytes but requested %d", *lpNumberOfBytesWritten, nNumberOfBytesToWrite);
		}
		else {
			uprintf("Write error %s", WindowsErrorString());
			LastWriteError = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | GetLastError();
		}
		// If we can't reposition for the next run, just abort
		if (!readFilePointer)
			break;
		if (nTry < nNumRetries) {
			uprintf("Retrying in %d seconds...", WRITE_TIMEOUT / 1000);
			// Don't sit idly but use the downtime to check for conflicting processes...
			Sleep(WRITE_TIMEOUT);
		}
	}
	if (SCODE_CODE(GetLastError()) == ERROR_SUCCESS)
		SetLastError(ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_WRITE_FAULT);
	return FALSE;
}


/* Max valid value of uiLen for contains_data */
#define MAX_DATA_LEN 65536
unsigned long ulBytesPerSector = 512;

typedef struct {
    void* _handle;
    uint64_t _offset;
} FAKE_FD;


int64_t write_sectors(HANDLE hDrive, uint64_t SectorSize,
    uint64_t StartSector, uint64_t nSectors,
    const void* pBuf)
{
    LARGE_INTEGER ptr;
    DWORD Size;

    if ((nSectors * SectorSize) > 0xFFFFFFFFUL)
    {
        uprintf("write_sectors: nSectors x SectorSize is too big\n");
        return -1;
    }
    Size = (DWORD)(nSectors * SectorSize);

    ptr.QuadPart = StartSector * SectorSize;
    if (!SetFilePointerEx(hDrive, ptr, NULL, FILE_BEGIN))
    {
        uprintf("write_sectors: Could not access sector 0x%08" PRIx64 " - %s\n", StartSector, WindowsErrorString());
        return -1;
    }

    LastWriteError = 0;
    if (!WriteFileWithRetry(hDrive, pBuf, Size, &Size, WRITE_RETRIES))
    {
        LastWriteError = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | GetLastError();
        uprintf("write_sectors: Write error %s\n", WindowsErrorString());
        uprintf("  StartSector: 0x%08" PRIx64 ", nSectors: 0x%" PRIx64 ", SectorSize: 0x%" PRIx64 "\n", StartSector, nSectors, SectorSize);
        return -1;
    }
    if (Size != nSectors * SectorSize)
    {
        /* Some large drives return 0, even though all the data was written - See github #787 */
        if (large_drive && Size == 0) {
            uprintf("Warning: Possible short write\n");
            return 0;
        }
        uprintf("write_sectors: Write error\n");
        LastWriteError = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_WRITE_FAULT;
        uprintf("  Wrote: %d, Expected: %" PRIu64 "\n", Size, nSectors * SectorSize);
        uprintf("  StartSector: 0x%08" PRIx64 ", nSectors: 0x%" PRIx64 ", SectorSize: 0x%" PRIx64 "\n", StartSector, nSectors, SectorSize);
        return -1;
    }

    return (int64_t)Size;
}


int write_data(FILE* fp, uint64_t Position,
    const void* pData, uint64_t Len)
{
    int r = 0;
    /* Windows' WriteFile() may require a buffer that is aligned to the sector size */
    unsigned char* aucBuf = (unsigned char*)_mm_malloc(MAX_DATA_LEN, 4096);
    FAKE_FD* fd = (FAKE_FD*)fp;
    HANDLE hDrive = (HANDLE)fd->_handle;
    uint64_t StartSector, EndSector, NumSectors;

    if (aucBuf == NULL)
        return 0;

    Position += fd->_offset;

    StartSector = Position / ulBytesPerSector;
    EndSector = (Position + Len + ulBytesPerSector - 1) / ulBytesPerSector;
    NumSectors = EndSector - StartSector;

    if ((NumSectors * ulBytesPerSector) > MAX_DATA_LEN)
    {
        uprintf("write_data: Please increase MAX_DATA_LEN in file.h\n");
        goto out;
    }

    if (Len > 0xFFFFFFFFUL)
    {
        uprintf("write_data: Len is too big\n");
        goto out;
    }

    /* Data to write may not be aligned on a sector boundary => read into a sector buffer first */
    if (read_sectors(hDrive, ulBytesPerSector, StartSector,
        NumSectors, aucBuf) <= 0)
        goto out;

    if (!memcpy(&aucBuf[Position - StartSector * ulBytesPerSector], pData, (size_t)Len))
        goto out;

    if (write_sectors(hDrive, ulBytesPerSector, StartSector,
        NumSectors, aucBuf) <= 0)
        goto out;

    r = 1;

out:
    _mm_free(aucBuf);
    return r;
} /* write_data */