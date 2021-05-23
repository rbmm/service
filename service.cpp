#include "stdafx.h"

_NT_BEGIN

#include "log.h"
#include "SvcBase.h"
#include "common.h"

template<int n> struct SID_EX : public SID
{
	DWORD SubAuthority[n-1];
};

class CSvc : public CSvcBase
{
	enum { e_SectionSize = 0x1000 };//0

	HANDLE hThread = 0;
	HANDLE hSection = 0;
	HANDLE hEmptyEvent = 0;
	HANDLE hDataEvent = 0;
	PVOID BaseAddress = 0;
	ULONG nLine = 0;

	BOOL ProcessData(HANDLE hFile, PSTR buf, ULONG cb)
	{
		ULONG len = cb - 1;

		if (len <= e_SectionSize - sizeof(ULONG) - 1 && buf[len] == '\n')
		{
			char prefix[16];
			OVERLAPPED ov = {};

			while (PSTR pc = strnchr(cb, buf, '\n'))
			{
				if (!WriteFile(hFile, prefix, sprintf_s(prefix, _countof(prefix), "%08x ", ++nLine), 0, &ov) ||
					!WriteFile(hFile, buf, len = (ULONG)(pc - buf), 0, &ov))
				{
					return FALSE;
				}

				buf = pc, cb -= len;
			}
		}
		else
		{
			DbgPrint("Invalid data in section !\r\n");
		}

		return SetEvent(hEmptyEvent);
	}

	HRESULT Run(HANDLE hFile)
	{
		PSTR buf = (PSTR)BaseAddress;
		PULONG pcb = (PULONG)(buf + e_SectionSize) - 1;

__StateChanged:
		ULONG dwState = m_dwTargetState;

		DbgPrint("[%u]>state:= %x\r\n", GetTickCount(), dwState);

		if (dwState == SERVICE_STOPPED)
		{
			return S_OK;
		}

		if (ULONG dwError = SetState(dwState, SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_STOP))
		{
			return CLogFile::LogError("SetServiceStatus", dwError);
		}

		for (;;)
		{
			NTSTATUS status;
			static const LARGE_INTEGER Interval = { 0, MINLONG };
			switch (status = dwState == SERVICE_RUNNING ? 
				ZwWaitForSingleObject(hDataEvent, TRUE, 0) : ZwDelayExecution(TRUE, const_cast<PLARGE_INTEGER>(&Interval)))
			{
			case WAIT_OBJECT_0:
				if (!ProcessData(hFile, buf, *pcb))
				{
					return CLogFile::LogError("process request");
				}
				break;

			case STATUS_ALERTED:
				goto __StateChanged;
			default:
				return CLogFile::LogError("WaitForSingleObject", HRESULT_FROM_NT(status));
			}
		}
	}

	HRESULT RunService()
	{
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;
		STATIC_OBJECT_ATTRIBUTES(oa, "\\systemroot\\temp\\D52FDBB5.txt");

		NTSTATUS status = NtCreateFile(&hFile, FILE_APPEND_DATA|SYNCHRONIZE, &oa, &iosb, 0, 0,
			FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);

		if (0 <= status)
		{
			status = Run(hFile);
			NtClose(hFile);
		}

		return HRESULT_FROM_NT(status);
	}

	HRESULT RunService(PSECURITY_ATTRIBUTES psa)
	{
		ULONG dwError = Init(psa);
		return dwError == NOERROR ? RunService() : HRESULT_FROM_WIN32(dwError);
	}

	virtual HRESULT Run()
	{
		static const ::ACCESS_MASK AccessMask[] = { GENERIC_READ, GENERIC_READ, GENERIC_ALL };

		static const SID SY = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_LOCAL_SYSTEM_RID } };
		static const SID_EX<2> BA = { { SID_REVISION, 2, SECURITY_NT_AUTHORITY, { SECURITY_BUILTIN_DOMAIN_RID } }, { DOMAIN_ALIAS_RID_ADMINS } };

		PSID Sids[3] = { const_cast<SID*>(&SY), const_cast<SID_EX<2>*>(&BA), (PSID)GetCommandLineW() };
		C_ASSERT(_countof(Sids) == _countof(AccessMask));

		DWORD nAclLength = sizeof(ACL);

		int i = _countof(Sids);
		do 
		{
			nAclLength += FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(Sids[--i]);
		} while (i);

		::SECURITY_DESCRIPTOR sd;
		if (InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
		{
			if (InitializeAcl(sd.Dacl = (::PACL)alloca(nAclLength), nAclLength, ACL_REVISION))
			{
				i = _countof(Sids) - 1;
				do 
				{
					if (!AddAccessAllowedAce(sd.Dacl, ACL_REVISION, AccessMask[i], Sids[i]))
					{
						break;
					}
				} while (i--);

				if (0 > i && SetSecurityDescriptorDacl(&sd, TRUE, sd.Dacl, FALSE))
				{
					SECURITY_ATTRIBUTES sa = { sizeof(sa), &sd, FALSE };

					return RunService(&sa);
				}
			}
		}

		return HRESULT_FROM_WIN32(GetLastError());
	}

	virtual ULONG Handler(
		ULONG    dwControl,
		ULONG    /*dwEventType*/,
		PVOID   /*lpEventData*/
		)
	{
		switch (dwControl)
		{
		case SERVICE_CONTROL_CONTINUE:
		case SERVICE_CONTROL_PAUSE:
		case SERVICE_CONTROL_STOP:
			return RtlNtStatusToDosErrorNoTeb(ZwAlertThread(hThread));
		}

		return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
	}

	ULONG Init(_In_ PSECURITY_ATTRIBUTES psa)
	{
		return (hSection = CreateFileMappingW(INVALID_HANDLE_VALUE, 
			psa, PAGE_READWRITE|SEC_COMMIT, 0, e_SectionSize, L"Global\\Restricted\\Section_D52FDBB5")) &&
			(BaseAddress = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0)) &&
			(hEmptyEvent = CreateEventW(psa, FALSE, TRUE, L"Global\\Restricted\\Empty_D52FDBB5")) &&
			(hDataEvent = CreateEventW(psa, FALSE, FALSE, L"Global\\Restricted\\Data_D52FDBB5")) &&
			(hThread = OpenThread(THREAD_ALERT, FALSE, GetCurrentThreadId())) ? NOERROR : GetLastError();
	}

public:

	~CSvc()
	{
		if (hThread) CloseHandle(hThread);
		if (hDataEvent) CloseHandle(hDataEvent);
		if (hEmptyEvent) CloseHandle(hEmptyEvent);
		if (BaseAddress) UnmapViewOfFile(BaseAddress);
		if (hSection) CloseHandle(hSection);
	}
};

VOID WINAPI ServiceMain(_In_ DWORD dwArgc,_In_ PWSTR* lpszArgv)
{
	if (dwArgc)
	{
		DbgPrint("ServiceMain(%S)\r\n", lpszArgv[0]);

		CSvc svc;
		HRESULT hr = svc.ServiceMain(lpszArgv[0]);
		CLogFile::LogError("ServiceMain=", hr);
		return ;
	}
	ExitProcess(0);
}

HRESULT RunService(PCWSTR base64Sid)
{
	DbgPrint("RunService(%S)\r\n", base64Sid);

	ULONG cchString = (ULONG)wcslen(base64Sid);

	PUCHAR pbBinary = 0;
	ULONG cbBinary = 0;

	while(CryptStringToBinaryW(base64Sid, cchString, CRYPT_STRING_HEXRAW, pbBinary, &cbBinary, 0, 0))
	{
		if (pbBinary)
		{
			if (RtlValidSid(pbBinary))
			{
				memcpy(GetCommandLineW(), pbBinary, cbBinary);

				static const SERVICE_TABLE_ENTRY ServiceStartTable [] = {
					{ const_cast<PWSTR>(L"Service_D52FDBB5"), ServiceMain }, {}
				};

				return HRESULT_FROM_WIN32(bte(StartServiceCtrlDispatcher(ServiceStartTable)));
			}

			return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_3);
		}

		pbBinary = (PUCHAR)alloca(cbBinary);
	}

	return HRESULT_FROM_WIN32(GetLastError());
}

_NT_END