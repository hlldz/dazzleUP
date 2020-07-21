void modifiableRegistryAutoRunBinPaths() {
	std::cout << "\n\n[*] Modifiable binaries saved as Registry AutoRun checking...\n";
	
	std::vector <LPCSTR> registryAutoRunLocations;

	registryAutoRunLocations.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
	registryAutoRunLocations.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
	registryAutoRunLocations.push_back("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");
	registryAutoRunLocations.push_back("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
	registryAutoRunLocations.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService");
	registryAutoRunLocations.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService");
	registryAutoRunLocations.push_back("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService");
	registryAutoRunLocations.push_back("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService");

	TCHAR achClass[MAX_PATH] = TEXT("");
	DWORD cchClassName = MAX_PATH;
	DWORD cSubKeys = 0;
	DWORD cbMaxSubKey;
	DWORD cchMaxClass;
	DWORD cValues;
	DWORD cchMaxValue;
	DWORD cbMaxValueData;
	DWORD cbSecurityDescriptor;
	FILETIME ftLastWriteTime;
	DWORD i;
	LONG retCode;
	char achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	HKEY hKeyReg;
	for (LPCSTR registryKey : registryAutoRunLocations) {
		
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, registryKey, 0, KEY_READ, &hKeyReg) == ERROR_SUCCESS) {
		
			retCode = RegQueryInfoKey(hKeyReg, achClass, &cchClassName, NULL, &cSubKeys, &cbMaxSubKey, &cchMaxClass, &cValues, &cchMaxValue, &cbMaxValueData, &cbSecurityDescriptor, &ftLastWriteTime);

			if (cValues) {
			//printf("\nNumber of values: %u\n", cValues);

				std::vector<BYTE> buffer(cbMaxValueData + 1);
				//std::cout << registryKey << "\n";

				for (i = 0; i < cValues; ++i) {
					cchValue = MAX_VALUE_NAME;
					retCode = RegEnumValueA(hKeyReg, i, achValue, &cchValue, NULL, NULL, NULL, NULL);
					if (retCode == ERROR_SUCCESS) {
						DWORD lpData = cbMaxValueData;
						retCode = RegQueryValueExA(hKeyReg, achValue, 0, NULL, &buffer[0], &lpData);

						if (retCode == ERROR_SUCCESS) {
							//_tprintf(TEXT("(%u) %s : %.*s\n"), i + 1, achValue, lpData, &buffer[0]);
							//std::cout << achValue << " - " << &buffer[0];

							//std::cout << achValue << " ==> " << autoRunKeyValue << "\n";

							std::string autoRunKeyValue((char*)&buffer[0]);
							//Parsing ops for remove " char and extract binary path
							autoRunKeyValue.erase(std::remove(autoRunKeyValue.begin(), autoRunKeyValue.end(), '"'), autoRunKeyValue.end());
							std::string exeDelimeter = ".exe";
							int indexInt = stdIndexOf(autoRunKeyValue, exeDelimeter);
							std::string cleanedAutoRunKey = autoRunKeyValue.substr(0, indexInt + 4);

							//std::cout << cleanedAutoRunKey << "\n";

							if (HasPermissionF(cleanedAutoRunKey, GENERIC_WRITE)) {
								std::cout << "\n";
								std::cout << "\tKey Name:\t   HKLM\\" << registryKey << "\\" << achValue << "\n";
								std::cout << "\tKey Value:\t   HKLM\\" << autoRunKeyValue << "\n";
								std::cout << "\tModifiable Binary: " << cleanedAutoRunKey << "\n";
							}
						}
					}
				}
			}
		}
	}
}

