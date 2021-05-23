#include "stdafx.h"

_NT_BEGIN

#include "log.h"
#include "common.h"

void ShowErrorBox(HRESULT dwError, PCWSTR pzCaption)
{
	ULONG SessionId;
	if (ProcessIdToSessionId(GetCurrentProcessId(), &SessionId) && SessionId)
	{
		PWSTR psz;
		ULONG r = dwError & FACILITY_NT_BIT ?
			FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_HMODULE, GetModuleHandle(L"ntdll"), 
			dwError &= ~FACILITY_NT_BIT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(PWSTR)&psz, 0, NULL) :
		FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM, 0, dwError,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(PWSTR)&psz, 0, NULL);

		if (r)
		{
			MessageBoxW(0, psz, pzCaption, dwError ? MB_ICONERROR|MB_OK : MB_ICONINFORMATION|MB_OK);
			LocalFree(psz);
		}
	}
	else
	{
		CLogFile::LogError("***", dwError);
	}
}

HRESULT ParseCmdLine()
{
	PWSTR argv[3];
	PWSTR psz = GetCommandLineW();
	ULONG argc = 0;

	while (PWSTR pc = wcschr(psz, '*'))
	{
		if (argc == _countof(argv))
		{
			return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);
		}
		*pc++ = 0;
		argv[argc++] = psz = pc;
	}

	if (!argc)
	{
		return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);
	}

	if (argv[0][1])
	{
		return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_1);
	}

	switch (argv[0][0])
	{
	case 'i':
		if (1 < argc)
		{
			if (!argv[1][1])
			{
				switch (argv[1][0])
				{
				case 's':
					return argc == 3 ? InstallForStringSid(argv[2]) : HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
				case 'u':
					return argc == 3 ? InstallForUser(argv[2]) : HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
				case 'c':
					return argc == 2 ? InstallForCurrentUser() : HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
				}
			}

			return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_2);
		}
		break;

	case 's':
		if (argc == 2)
		{
			CLogFile::Init();
			return RunService(argv[1]);
		}
		break;

	case 'c':
		if (argc == 2)
		{
			return RunClient(argv[1]);
		}
		break;

	case 'd':
		if (argc == 1)
		{
			CLogFile::Init();
			return DeleteService();
		}
		break;

	default:
		return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_1);
	}

	return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
}

#include "resource.h"

INT_PTR CALLBACK DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM)
{
	switch (uMsg)
	{
	case WM_NCDESTROY:
		PostQuitMessage(0);
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			DestroyWindow(hwnd);
			break;
		}
		break;
	}

	return 0;
}

HRESULT WaitExclusiveWithUI(HANDLE hMutex)
{
	if (HWND hwnd = CreateDialogW((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG1), 0, DialogProc))
	{
		MSG msg;
		for (;;)
		{
			switch (MsgWaitForMultipleObjectsEx(1, &hMutex, INFINITE, QS_ALLINPUT, MWMO_INPUTAVAILABLE))
			{
			case WAIT_OBJECT_0:
			case WAIT_ABANDONED:
				DestroyWindow(hwnd), hwnd = 0;
				[[fallthrough]];
			
			case WAIT_OBJECT_0+1:
				while (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE))
				{
					if (msg.message == WM_QUIT)
					{
						return hwnd ? HRESULT_FROM_WIN32(ERROR_CANCELLED) : S_OK;
					}

					if (hwnd && !IsDialogMessageW(hwnd, &msg))
					{
						TranslateMessage(&msg);
						DispatchMessageW(&msg);
					}
				}
				continue;
			}
		}
	}
	
	return HRESULT_FROM_WIN32(GetLastError());
}

HRESULT WaitExclusiveNoUI(HANDLE hMutex)
{
	switch (WaitForSingleObject(hMutex, INFINITE))
	{
	case WAIT_OBJECT_0:
	case WAIT_ABANDONED:
		return S_OK;
	}

	return HRESULT_FROM_NT(STATUS_UNSUCCESSFUL);
}

HRESULT WaitExclusive(HANDLE hMutex)
{
	ULONG SessionId;
	return (ProcessIdToSessionId(GetCurrentProcessId(), &SessionId) && SessionId 
		? WaitExclusiveWithUI : WaitExclusiveNoUI)(hMutex);
}

void CALLBACK ep(void* )
{
	ShowErrorBox(ParseCmdLine(), L"Exit");
	CLogFile::Destroy();
	ExitProcess(0);
}

_NT_END