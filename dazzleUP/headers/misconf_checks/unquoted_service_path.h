void unquotedServicePath() {
    std::cout << "\n\n[*] Unquoted Service Paths checking...\n";

    HKEY hKey;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        TCHAR achKey[MAX_KEY_LENGTH];
        DWORD cbName;
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
        DWORD i, retCode;
        DWORD chValue = MAX_VALUE_NAME;

        retCode = RegQueryInfoKey(hKey, achClass, &cchClassName, NULL, &cSubKeys, &cbMaxSubKey, &cchMaxClass, &cValues, &cchMaxValue, &cbMaxValueData, &cbSecurityDescriptor, &ftLastWriteTime);
        if (retCode == ERROR_SUCCESS) {
            if (cSubKeys) {
                for (i = 0; i < cSubKeys; i++) {
                    cbName = MAX_KEY_LENGTH;
                    retCode = RegEnumKeyEx(hKey, i, achKey, &cbName, NULL, NULL, NULL, &ftLastWriteTime);
                    if (retCode == ERROR_SUCCESS) {
                        if ((regServiceQuery(achKey, L"ImagePath") != L"FALSE") &&
                            (regServiceQuery(achKey, L"ImagePath").find(L".exe") != std::string::npos) && // sadece exe barindiralari getir
                            (regServiceQuery(achKey, L"ImagePath").find(L" ") != std::string::npos) && //buna bakilacak
                            (regServiceQuery(achKey, L"ImagePath").compare(0, 1, L"\"") != 0) && //buna bakilacak
                            (regServiceQuery(achKey, L"ImagePath").compare(0, 1, L"\'") != 0))  //buna bakilacak
                        {
                            // Remove arguments from ImagePath
                            std::string exeSign = ".exe";
                            std::string serviceImagePathRaw = ws2s(regServiceQuery(achKey, L"ImagePath"));
                            int indexInt = stdIndexOf(serviceImagePathRaw, exeSign);

                            std::string cleanedServiceImagePath = serviceImagePathRaw.substr(0, indexInt + 4);

                            if (cleanedServiceImagePath.find(" ") != std::string::npos) {
                                std::wcout << "\n";
                                std::wcout << "\tService Name:\t\t " << achKey << "\n";
                                std::wcout << "\tService Binary Path:\t " << regServiceQuery(achKey, L"ImagePath") << "\n";
                                std::wcout << "\tService Privilege:\t " << regServiceQuery(achKey, L"ObjectName") << "\n";
                            }
                        }
                    }
                }
            }
        } 
    }
}