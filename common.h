#pragma once

PSTR __fastcall strnchr (_In_ SIZE_T n1, _In_ const void* str1, _In_ char c);
PSTR __fastcall strnrchr(_In_ SIZE_T n1, _In_ const void* str1, _In_ char c);

HRESULT DeleteService();

HRESULT InstallForUser(_In_ PCWSTR pszName);
HRESULT InstallForStringSid(_In_ PCWSTR StringSid);
HRESULT InstallForCurrentUser();

HRESULT RunService(_In_ PCWSTR base64Sid);
HRESULT RunClient(_In_ PCWSTR lpFileName);

HRESULT WaitExclusive(_In_ HANDLE hMutex);

void ShowErrorBox(_In_ HRESULT dwError, _In_ PCWSTR pzCaption);

inline ULONG bte(_In_ BOOL fOk)
{
	return fOk ? NOERROR : GetLastError();
}