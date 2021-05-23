#include "stdafx.h"

_NT_BEGIN

#include "log.h"
#include "common.h"
#include <ntlsa.h>
#undef _NTDDK_
#include <sddl.h>

volatile UCHAR guz;

static const WCHAR ServiceName[] = L"Service_D52FDBB5";

struct ServiceData : SERVICE_NOTIFY
{
	ServiceData() { 
		RtlZeroMemory(this, sizeof(ServiceData)); 
		dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
		pfnNotifyCallback = ScNotifyCallback;
		pContext = this;
	}

	void OnScNotify()
	{
		DbgPrint("ScNotifyCallback(%u %08x %x %x)\r\n", 
			dwNotificationStatus, dwNotificationTriggered, 
			ServiceStatus.dwCurrentState, ServiceStatus.dwCheckPoint );
	}

	static VOID CALLBACK ScNotifyCallback (_In_ PVOID pParameter)
	{
		reinterpret_cast<ServiceData*>(pParameter)->OnScNotify();
	}
};

HRESULT DeleteService()
{
	if (SC_HANDLE scm = OpenSCManagerW(0, 0, 0))
	{
		HRESULT hr = S_OK;

		SC_HANDLE svc = OpenServiceW(scm, ServiceName, DELETE|SERVICE_STOP|SERVICE_QUERY_STATUS);

		CloseServiceHandle(scm);

		if (svc)					
		{
			ServiceData sd;

			if (ControlService(svc, SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&sd.ServiceStatus))
			{
				ULONG64 t_end = GetTickCount64() + 4000, t;

				while (sd.ServiceStatus.dwCurrentState != SERVICE_STOPPED)
				{
					if (sd.dwNotificationStatus = NotifyServiceStatusChangeW(svc, 
						SERVICE_NOTIFY_CONTINUE_PENDING|
						SERVICE_NOTIFY_DELETE_PENDING|
						SERVICE_NOTIFY_PAUSE_PENDING|
						SERVICE_NOTIFY_PAUSED|
						SERVICE_NOTIFY_RUNNING|
						SERVICE_NOTIFY_START_PENDING|
						SERVICE_NOTIFY_STOP_PENDING|
						SERVICE_NOTIFY_STOPPED, &sd))
					{
						CLogFile::LogError("SERVICE_CONTROL_STOP", sd.dwNotificationStatus);
						break;
					}

					sd.dwNotificationStatus = ERROR_TIMEOUT;

					if ((t = GetTickCount64()) >= t_end ||
						WAIT_IO_COMPLETION != SleepEx((ULONG)(t_end - t), TRUE) ||
						sd.dwNotificationStatus != NOERROR)
					{
						break;
					}
				}

				if (sd.ServiceStatus.dwCurrentState != SERVICE_STOPPED)
				{
					CLogFile::LogError("dwNotificationStatus", sd.dwNotificationStatus);
				}
			}
			else
			{
				CLogFile::LogError("SERVICE_CONTROL_STOP");
			}

			if (!DeleteService(svc))
			{
				hr = CLogFile::LogError("DeleteService");
			}

			CloseServiceHandle(svc);
			ZwTestAlert();
		}
		else
		{
			hr = CLogFile::LogError("OpenService");
		}

		return hr;
	}

	return CLogFile::LogError("OpenSCManager");
}

ULONG Install(PCWSTR lpBinaryPathName)
{
	if (SC_HANDLE scm = OpenSCManagerW(0, 0, SC_MANAGER_CREATE_SERVICE))
	{
		ULONG dwError = NOERROR;

		if (SC_HANDLE svc = CreateServiceW(
			scm,							// SCM database
			ServiceName,					// name of service
			L"Demo service D52FDBB5",		// service name to display
			SERVICE_ALL_ACCESS,				// desired access
			SERVICE_WIN32_SHARE_PROCESS,	// service type
			SERVICE_DEMAND_START,			// start type
			SERVICE_ERROR_NORMAL,			// error control type
			lpBinaryPathName,	// path to service's binary
			0,					// no load ordering group
			0,					// no tag identifier
			0,					// no dependencies
			0,					// LocalSystem account
			0))					// no password
		{
			dwError = StartServiceW(svc, 0, 0) ? NOERROR : GetLastError();

			CloseServiceHandle(svc);
		}
		else
		{
			dwError = GetLastError();
		}

		CloseServiceHandle(scm);

		return dwError;
	}

	return GetLastError();
}

ULONG InstallForSid(PSID Sid)
{
	static const WCHAR cmd[] = L"\" *s*";
	ULONG len = RtlLengthSid(Sid);
	ULONG cch = MAXSHORT + _countof(cmd) + (len << 1);
	ULONG dwError = NOERROR;

	if (PWSTR psz = new WCHAR[cch])
	{
		// <imagepath> *s*base64(sid)
		if (ULONG l = GetModuleFileNameW((HMODULE)&__ImageBase, psz + 1, MAXSHORT - 1))
		{
			*psz = '\"';
			memcpy(psz + l + 1, cmd, sizeof(cmd) - sizeof(WCHAR)), l += _countof(cmd);

			if (CryptBinaryToStringW((PBYTE)Sid, len, 
				CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF, psz + l, &(cch -= l)))
			{
				dwError = Install(psz);
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
		delete [] psz;
	}
	else
	{
		dwError = GetLastError();
	}

	return HRESULT_FROM_WIN32(dwError);
}

HRESULT InstallForUser(_In_ PCWSTR pszName)
{
	LSA_HANDLE PolicyHandle;

	LSA_OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(ObjectAttributes) };

	NTSTATUS status = LsaOpenPolicy(0, &ObjectAttributes, POLICY_LOOKUP_NAMES, &PolicyHandle);

	if (0 <= status)
	{
		PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
		PLSA_TRANSLATED_SID2 Sids;

		LSA_UNICODE_STRING Name;
		RtlInitUnicodeString(&Name, pszName);

		if (0 <= (status = (LsaLookupNames2(PolicyHandle, 0, 1, &Name, &ReferencedDomains, &Sids))))
		{
			status = InstallForSid(Sids->Sid);

			LsaFreeMemory(ReferencedDomains);
			LsaFreeMemory(Sids);
		}

		LsaClose(PolicyHandle);
	}

	return HRESULT_FROM_NT(status);
}

HRESULT InstallForStringSid(_In_ PCWSTR StringSid)
{
	PSID Sid;
	if (ConvertStringSidToSidW(StringSid, &Sid))
	{
		HRESULT status = InstallForSid(Sid);

		LocalFree(Sid);

		return status;
	}

	return HRESULT_FROM_WIN32(GetLastError());
}

HRESULT InstallForCurrentUser()
{
	HANDLE hToken;

	NTSTATUS status;

	if (OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		union {
			PTOKEN_USER ptu;
			PVOID buf;
		};

		ULONG cb = 0, rcb = sizeof(TOKEN_USER) + RtlLengthRequiredSid(SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT + 2);

		PVOID stack = alloca(guz);

		do 
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			status = NtQueryInformationToken(hToken, TokenUser, buf, cb, &rcb);

		} while (status == STATUS_BUFFER_TOO_SMALL);

		CloseHandle(hToken);

		return 0 > status ? HRESULT_FROM_NT(status) : InstallForSid(ptu->User.Sid);
	}

	return HRESULT_FROM_WIN32(GetLastError());
}

_NT_END