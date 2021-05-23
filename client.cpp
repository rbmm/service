#include "stdafx.h"

_NT_BEGIN

#include "log.h"
#include "common.h"

PSTR __fastcall strnrchr(SIZE_T n1, const void* str1, char c);

ULONG RunClient(HANDLE hFile, ULONGLONG BytesRemaing)
{
	ULONG dwError = NOERROR;

	if (HANDLE hSection = OpenFileMappingW(FILE_MAP_WRITE, FALSE, L"Global\\Restricted\\Section_D52FDBB5"))
	{
		PVOID BaseAddress = MapViewOfFile(hSection, FILE_MAP_WRITE, 0, 0, 0);

		NtClose(hSection);

		if (BaseAddress)
		{
			::MEMORY_BASIC_INFORMATION mbi;

			if (sizeof(mbi) == VirtualQuery(BaseAddress, &mbi, sizeof(mbi)) && mbi.RegionSize < MAXULONG)
			{
				if (HANDLE hEmptyEvent = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\Restricted\\Empty_D52FDBB5"))
				{
					if (HANDLE hDataEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Global\\Restricted\\Data_D52FDBB5"))
					{
						enum { bufSize = 0x100000 };
						ULONG dwBytes = 0, NumberOfBytesRead, len;

						mbi.RegionSize -= sizeof(ULONG);
						PULONG pcb = (PULONG)((PBYTE)BaseAddress + mbi.RegionSize);

						if (PSTR buf = new char[bufSize+1])
						{
							do 
							{
								if (!ReadFile(hFile, buf + dwBytes, bufSize - dwBytes, &NumberOfBytesRead, 0) || 
									!NumberOfBytesRead)
								{
									break;
								}

								dwBytes += NumberOfBytesRead;

								if (!(BytesRemaing -= NumberOfBytesRead))
								{
									if (buf[dwBytes-1] != '\n')
									{
										buf[dwBytes++] = '\n';
									}
								}

								PSTR psz = buf, pc;

								while (pc = strnrchr(min(dwBytes, mbi.RegionSize), psz, '\n'))
								{
									switch (WaitForSingleObject(hEmptyEvent, 4000))
									{
									case WAIT_OBJECT_0:
										break;
									case WAIT_TIMEOUT:
										dwError = ERROR_TIMEOUT;
										break;
									case WAIT_FAILED:
										dwError = GetLastError();
										break;
									default: dwError = ERROR_GEN_FAILURE;
									}

									if (dwError != NOERROR)
									{
										goto __exit;
									}

									memcpy(BaseAddress, psz, len = (ULONG)(pc - psz)), *pcb = len;

									if (!SetEvent(hDataEvent))
									{
										dwError = GetLastError();
										goto __exit;
									}

									psz = pc, dwBytes -= len;
								}

								if (dwBytes >= mbi.RegionSize)
								{	
									// too long string
									dwError = ERROR_INVALID_DATA;
									break;
								}
								
								memcpy(buf, psz, dwBytes);

							} while (BytesRemaing);
__exit:

							delete [] buf;
						}

						CloseHandle(hDataEvent);
					}
					else
					{
						dwError = GetLastError();
					}

					CloseHandle(hEmptyEvent);
				}
				else
				{
					dwError = GetLastError();
				}
			}
			else
			{
				if ((dwError = GetLastError()) == NOERROR)
				{
					dwError = ERROR_NOT_ENOUGH_MEMORY;
				}
			}
			UnmapViewOfFile(BaseAddress);
		}
		else
		{
			dwError = GetLastError();
		}
	}
	else
	{
		dwError = GetLastError();
	}

	return dwError;
}

HRESULT RunClient(PCWSTR lpFileName)
{
	HANDLE hFile = CreateFileW(lpFileName, 
		FILE_GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);

	NTSTATUS status;

	if (hFile == INVALID_HANDLE_VALUE)
	{
		status = RtlGetLastNtStatus();
		ULONG dwError = GetLastError();
		return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : dwError;
	}

	FILE_STANDARD_INFO fsi;
	if (GetFileInformationByHandleEx(hFile, FileStandardInfo, &fsi, sizeof(fsi)))
	{
		if (fsi.EndOfFile.QuadPart)
		{
			if (HANDLE hMutex = CreateMutexW(0, TRUE, L"Global\\Restricted\\mutant_D52FDBB5"))
			{
				if (GetLastError() == ERROR_ALREADY_EXISTS)
				{
					if (0 > (status = WaitExclusive(hMutex)))
					{
						goto __0;
					}
				}
				status = HRESULT_FROM_WIN32(RunClient(hFile, fsi.EndOfFile.QuadPart));

				ShowErrorBox(status, L"This is For Demo only! (run another client)");
				ReleaseMutex(hMutex);
__0:
				CloseHandle(hMutex);
			}
			else
			{
				status = HRESULT_FROM_WIN32(GetLastError());;
			}
		}
		else
		{
			status = HRESULT_FROM_NT(STATUS_MAPPED_FILE_SIZE_ZERO);
		}
	}
	else
	{
		status = HRESULT_FROM_WIN32(GetLastError());
	}

	CloseHandle(hFile);

	return status;
}

_NT_END