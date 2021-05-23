#include "stdafx.h"

_NT_BEGIN

#include "log.h"

HRESULT GetLastHresult(ULONG dwError /*= GetLastError()*/)
{
	NTSTATUS status = RtlGetLastNtStatus();

	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

#ifdef _LOG_

HANDLE CLogFile::hFile = 0;

HRESULT CLogFile::Init()
{
	PWCHAR path = 0;
	ULONG cch = 0, need_cch;

	static const WCHAR log[] = L"\\D52FDBB5_svc.log";

	while (need_cch = GetEnvironmentVariable(L"TMP", path, cch))
	{
		if (path)
		{
			if (need_cch >= cch)
			{
				return ERROR_INSUFFICIENT_BUFFER;
			}

			wcscpy_s(path + need_cch, _countof(log), log);

			hFile = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);

			if (hFile == INVALID_HANDLE_VALUE)
			{
				hFile = 0;
				break;
			}
			
			return NOERROR;
		}

		path = (PWCHAR)alloca((cch = need_cch) * sizeof(WCHAR) + sizeof(log));
	}

	return GetLastHresult();
}

void CLogFile::printf(PCSTR format, ...)
{
	if (hFile)
	{
		va_list args;
		va_start(args, format);

		PSTR buf = 0;
		int cch = 0;

		while (0 < (cch = _vsnprintf(buf, cch, format, args)))
		{
			if (buf)
			{
				write(buf, cch);
				break;
			}

			if (!(buf = (PSTR)_malloca(cch)))
			{
				break;
			}
		}

		_freea(buf);

		va_end(args);
	}
}

HRESULT CLogFile::LogError(PCSTR prefix, HRESULT dwError)
{
	enum { ex_cch = 256 };

	LPCVOID lpSource = 0;

	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS;

	PCSTR fmt = "%s: error[%x] ";

	if (dwError & FACILITY_NT_BIT)
	{
		dwError &= ~FACILITY_NT_BIT;

		dwFlags = FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_IGNORE_INSERTS;

		static HMODULE s_nt;

		if (!s_nt)
		{
			s_nt = GetModuleHandleW(L"ntdll");
		}

		lpSource = s_nt;
	}
	else if (0 <= dwError)
	{
		fmt = "%s: error[%u] ";
	}

	int cch = _scprintf(fmt, prefix, dwError);

	if (0 < cch)
	{
		if (PSTR buf = (PSTR)_malloca(cch + ex_cch))
		{
			if (0 <= (cch = sprintf_s(buf, cch + ex_cch, fmt, prefix, dwError)))
			{
				cch += FormatMessageA(dwFlags, lpSource, dwError, 0, buf + cch, ex_cch, 0);

				write(buf, cch);
			}

			_freea(buf);
		}
	}

	return lpSource ? HRESULT_FROM_NT(dwError) : HRESULT_FROM_WIN32(dwError);
}

void LogTimeStamp()
{
	union {
		FILETIME ft;
		LARGE_INTEGER time;
	};
	GetSystemTimeAsFileTime(&ft);
	TIME_FIELDS tf;
	RtlTimeToTimeFields(&time, &tf);
	CLogFile::printf("\r\n--=[ %u-%02u-%02u %02u:%02u:%02u.%u ]=--\r\n", 
		tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second, tf.Milliseconds);
}

#endif// _LOG_

_NT_END