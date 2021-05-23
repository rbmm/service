#pragma once

HRESULT GetLastHresult(ULONG dwError = GetLastError());

#if 0 // 1
#define DbgPrint /##/
#else
#define _LOG_
#define DbgPrint CLogFile::printf
#pragma message("=========log")
#endif

#ifdef _LOG_

#define LOG(args)  CLogFile::args
void LogTimeStamp();

namespace CLogFile
{
	extern HANDLE hFile;

	inline void Destroy() { if (hFile) CloseHandle(hFile); }
	
	HRESULT Init();

	void printf(PCSTR format, ...);

	HRESULT LogError(PCSTR prefix, HRESULT dwError = GetLastHresult());

	inline void write(const void* buf, ULONG cb)
	{
		WriteFile(hFile, buf, cb, &cb, 0);
	}
};

#else

#define LOG(args)  
#define LogTimeStamp()

#endif//_LOG_