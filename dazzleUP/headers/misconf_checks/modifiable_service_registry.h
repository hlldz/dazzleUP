void modifiableServiceRegistry() {

    std::cout << "\n\n[*] Modifiable Service Registry Key checking...\n";

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

        if (cSubKeys) {
            for (i = 0; i < cSubKeys; i++) {
                cbName = MAX_KEY_LENGTH;
                retCode = RegEnumKeyEx(hKey, i, achKey, &cbName, NULL, NULL, NULL, &ftLastWriteTime);


                std::wstring serviceRegPath = L"SYSTEM\\CurrentControlSet\\Services\\";
                serviceRegPath += achKey;
                
                //std::wcout << serviceRegPath << "\n";
                if ((regServiceQuery(achKey, L"ImagePath") != L"FALSE") &&
                    (regServiceQuery(achKey, L"ImagePath").find(L".exe") != std::string::npos) // sadece exe barindiralari getir
                    ) {
                    
                    if ((HasPermissionR(HKEY_LOCAL_MACHINE, ws2s(serviceRegPath), KEY_WRITE))) {
                        std::wcout << "\n";
                        std::wcout << "\tService Name:\t\t " << achKey << "\n";
                        std::wcout << "\tService Privilege:\t " << regServiceQuery(achKey, L"ObjectName") << "\n";
                    }
                }

            }
        }
    }
}