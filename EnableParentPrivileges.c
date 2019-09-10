#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#define MAX_PRIVNAME_LEN 64 
#define SIZE_OF_ARRAY(array) (sizeof(array) / sizeof(array[0]))

HANDLE hToken; // process token
HANDLE hParentProcess; // handle to parent process
DWORD dwParentPID; // PID of the parent process
PTOKEN_PRIVILEGES pPrivileges; // set of privileges held by the process
CHAR szPrivilegeName[MAX_PRIVNAME_LEN]; // name of the privilege. Maximum length is assumed.
DWORD dwLen = 0; // size of the data returned in various places

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege)  // to enable or disable privilege
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	printf("Enabling %s privilege... ", lpszPrivilege);
	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("ERROR - privilege lookup failed with code %d.\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("ERROR - adjusting token failed with code %d.\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("ERROR - privilege is not held by the parent.\n");
		return FALSE;
	}

	printf("SUCCESS.\n");
	return TRUE;
}


DWORD GetParentPID()
{
	DWORD pid = GetCurrentProcessId();
	DWORD ppid = -1;
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = {0};
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(h, &pe))
	{
		do
		{
			if (pe.th32ProcessID == pid)
			{
				ppid = pe.th32ParentProcessID;
				break;
			}
		}
		while (Process32Next(h, &pe));
	}

	CloseHandle(h);
	return ppid;
}


int main()
{
	//find the parent
	dwParentPID = GetParentPID();
	if (dwParentPID == -1)
	{
		printf("Cannot find parent PID.\n");
		exit(-1);
	}

	// open the parent process
	hParentProcess = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE, //bInheritHandle
		dwParentPID); // dwProcessId (PID) 

	if (hParentProcess == NULL)
	{
		printf("Opening parent process failed.\n");
		exit(-1);
	}

	//get parent token
	if (!OpenProcessToken(
		hParentProcess,
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		printf("OpenProcessToken() for parent failed with code %d\n", GetLastError());
		exit(-1);
	}

	//check the size, expect the function to fail with the code 122, so failure check is provided by the dwLen check a bit later
	GetTokenInformation(
		hToken,
		TokenPrivileges,
		NULL,
		0,
		&dwLen);

	if (dwLen == 0)
	{
		printf("GetTokenInformation() attempt #1 failed with code %d\n", GetLastError());
		exit(-1);
	}

	//buffer for storing token information
	BYTE* pBuffer = malloc(dwLen);
	if (pBuffer == NULL)
	{
		printf("Memory allocation failed with code %d\n", GetLastError());
		exit(-1);
	}

	//let's put the data to the buffer
	if (!GetTokenInformation(
		hToken,
		TokenPrivileges,
		pBuffer,
		dwLen,
		&dwLen))
	{
		printf("GetTokenInformation() attempt #2 failed with code %d\n", GetLastError());
		exit(-1);
	}

	//iterate through privileges 
	//we can do it with one AdjustTokenPrivileges() call but iterating through an array allows us to display names and catch failed attempts.
	//the alternative way is nicely demonstrated at https://docs.microsoft.com/en-us/windows/win32/wmisdk/executing-privileged-operations-using-c- 
	//we are enabling only privileges we can resolve with LookupPrivilegeName
	
	//structured view over buffer
	TOKEN_PRIVILEGES* pPrivs = (TOKEN_PRIVILEGES*)pBuffer;

	for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++)
	{
		dwLen = SIZE_OF_ARRAY(szPrivilegeName);
		ZeroMemory(szPrivilegeName, dwLen);
		LookupPrivilegeName(
			NULL,
			&(pPrivs->Privileges[i].Luid),
			szPrivilegeName,
			&dwLen);
		SetPrivilege(hToken, szPrivilegeName, TRUE);
	}
}
