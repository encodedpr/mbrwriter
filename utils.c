
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <Windows.h>
#include <cstdint>
#include "Header.h"
#include <cfgmgr32.h>

#define GB             1073741824LL
int IsHDD(DWORD DriveIndex, uint16_t vid, uint16_t pid, const char* strid)
{
	int score = 0;
	size_t i, mlen, ilen;
	BOOL wc;
	uint64_t drive_size;

	// Boost the score if fixed, as these are *generally* HDDs
	// NB: Due to a Windows API limitation, drives with no mounted partition will never have DRIVE_FIXED
	if (GetDriveTypeFromIndex(DriveIndex) == DRIVE_FIXED)
		score += 3;

	// Adjust the score depending on the size
	drive_size = GetDriveSize(DriveIndex);
	if (drive_size > 512 * GB)
		score += 10;
	else if (drive_size < 8 * GB)
		score -= 10;

	// Check the string against well known HDD identifiers
	if (strid != NULL) {
		ilen = strlen(strid);
		for (i = 0; i < ARRAYSIZE(str_score); i++) {
			mlen = strlen(str_score[i].name);
			if (mlen > ilen)
				break;
			wc = (str_score[i].name[mlen - 1] == '#');
			if ((_strnicmp(strid, str_score[i].name, mlen - ((wc) ? 1 : 0)) == 0)
				&& ((!wc) || ((strid[mlen] >= '0') && (strid[mlen] <= '9')))) {
				score += str_score[i].score;
				break;
			}
		}
	}

	// Adjust for oddball devices
	if (strid != NULL) {
		for (i = 0; i < ARRAYSIZE(str_adjust); i++)
			if (strstr(strid, str_adjust[i].name) != NULL)
				score += str_adjust[i].score;
	}

	// Check against known VIDs
	for (i = 0; i < ARRAYSIZE(vid_score); i++) {
		if (vid == vid_score[i].vid) {
			score += vid_score[i].score;
			break;
		}
	}

	// Check against known VID:PIDs
	for (i = 0; i < ARRAYSIZE(vidpid_score); i++) {
		if ((vid == vidpid_score[i].vid) && (pid == vidpid_score[i].pid)) {
			score += vidpid_score[i].score;
			break;
		}
	}

	// TODO: try to perform inquiry if below a specific threshold (Verbatim, etc)?
	duprintf("  Score: %d\n", score);
	return score;
}

BOOL IsVHD(const char* buffer)
{
	int i;
	// List of the Hardware IDs of the VHD devices we know
	const char* vhd_name[] = {
		"Arsenal_________Virtual_",
		"KernSafeVirtual_________",
		"Msft____Virtual_Disk____",
		"VMware__VMware_Virtual_S"	// Enabled through a cheat mode, as this lists primary disks on VMWare instances
	};

	for (i = 0; i < (int)(ARRAYSIZE(vhd_name)); i++)
		if (safe_strstr(buffer, vhd_name[i]) != NULL)
			return TRUE;
	return FALSE;
}

BOOL IsRemovable(const char* buffer)
{
	switch (*((DWORD*)buffer)) {
	case CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL:
	case CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL:
		return TRUE;
	default:
		return FALSE;
	}
}

const char* WindowsErrorString(void)
{
	static char err_string[256] = { 0 };

	DWORD size, presize;
	DWORD error_code, format_error;

	error_code = GetLastError();
	// Check for VDS error codes
	//if ((HRESULT_FACILITY(error_code) == FACILITY_ITF) && (GetVdsError(error_code) != NULL)) {
	//	static_sprintf(err_string, "[0x%08lX] %s", error_code, GetVdsError(error_code));
	//	return err_string;
	//}
	//if ((HRESULT_FACILITY(error_code) == FACILITY_WIM) && (GetVimError(error_code) != NULL)) {
	//	static_sprintf(err_string, "[0x%08lX] %s", error_code, GetVimError(error_code));
	//	return err_string;
	//}
	sprintf(err_string, "[0x%08lX] ", error_code);
	presize = (DWORD)strlen(err_string);

	size = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
		HRESULT_CODE(error_code), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
		&err_string[presize], (DWORD)(sizeof(err_string) - strlen(err_string)), NULL);
	if (size == 0) {
		format_error = GetLastError();
		if ((format_error) && (format_error != ERROR_MR_MID_NOT_FOUND) && (format_error != ERROR_MUI_FILE_NOT_LOADED))
			sprintf(err_string, "Windows error code 0x%08lX (FormatMessage error code 0x%08lX)",
				error_code, format_error);
		else
			sprintf(err_string, "Windows error code 0x%08lX", error_code);
	}
	else {
		// Microsoft may suffix CRLF to error messages, which we need to remove...
		//assert(presize > 2);
		size += presize - 2;
		// Cannot underflow if the above assert passed since our first char is neither of the following
		while ((err_string[size] == 0x0D) || (err_string[size] == 0x0A) || (err_string[size] == 0x20))
			err_string[size--] = 0;
	}

	SetLastError(error_code);	// Make sure we don't change the errorcode on exit
	return err_string;
}

void StrArrayCreate(StrArray* arr, uint32_t initial_size)
{
	if (arr == NULL) return;
	arr->Max = initial_size; arr->Index = 0;
	arr->String = (char**)calloc(arr->Max, sizeof(char*));
	if (arr->String == NULL)
		uprintf("Could not allocate string array\n");
}

int32_t StrArrayAdd(StrArray* arr, const char* str, BOOL duplicate)
{
	char** old_table;
	if ((arr == NULL) || (arr->String == NULL) || (str == NULL))
		return -1;
	if (arr->Index == arr->Max) {
		arr->Max *= 2;
		old_table = arr->String;
		arr->String = (char**)realloc(arr->String, arr->Max * sizeof(char*));
		if (arr->String == NULL) {
			free(old_table);
			uprintf("Could not reallocate string array\n");
			return -1;
		}
	}
	arr->String[arr->Index] = (duplicate) ? safe_strdup(str) : (char*)str;
	if (arr->String[arr->Index] == NULL) {
		uprintf("Could not store string in array\n");
		return -1;
	}
	return arr->Index++;
}

void StrArrayDestroy(StrArray* arr)
{
	StrArrayClear(arr);
	if (arr != NULL)
		safe_free(arr->String);
}