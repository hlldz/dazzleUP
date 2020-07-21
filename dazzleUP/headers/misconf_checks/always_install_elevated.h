void alwaysInstallElevatedUser() {
	BOOL result;
	DWORD dwRet;
	HKEY hKey;

	dwRet = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", NULL, KEY_READ, &hKey);

	if (dwRet == ERROR_SUCCESS) {
        DWORD dwBufferSize(sizeof(DWORD));
        DWORD nResult(0);
        LONG nError = RegQueryValueExA(hKey, "AlwaysInstallElevated", 0, NULL, reinterpret_cast<LPBYTE>(&nResult), &dwBufferSize);
        if (ERROR_SUCCESS == nError) {
			if (nResult == 1) {
				result = TRUE;
			}
			else {
				result = FALSE;
			}
        }
		else {
			result = FALSE;
		}
	}
	else {
		result = FALSE;
	}

	if (result == TRUE) {
		std::cout << "\tAlways Install Elevated User:\t Vulnerable" << "\n";
	}
}

void alwaysInstallElevatedMachine() {
	BOOL result;
	DWORD dwRet;
	HKEY hKey;

	dwRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", NULL, KEY_READ, &hKey);

	if (dwRet == ERROR_SUCCESS) {
		DWORD dwBufferSize(sizeof(DWORD));
		DWORD nResult(0);
		LONG nError = RegQueryValueExA(hKey, "AlwaysInstallElevated", 0, NULL, reinterpret_cast<LPBYTE>(&nResult), &dwBufferSize);
		if (ERROR_SUCCESS == nError) {
			if (nResult == 1) {
				result = TRUE;
			}
			else {
				result = FALSE;
			}
		}
		else {
			result = FALSE;
		}
	}
	else {
		result = FALSE;
	}

	if (result == TRUE) {
		std::cout << "\tAlways Install Elevated Machine: Vulnerable" << "\n";
	}
}

void alwaysInstallElevated() {
	std::cout << "\n[*] Always Install Elevated checking...\n\n";

	alwaysInstallElevatedUser();
	alwaysInstallElevatedMachine();
}