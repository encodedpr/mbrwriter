
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <Windows.h>

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
