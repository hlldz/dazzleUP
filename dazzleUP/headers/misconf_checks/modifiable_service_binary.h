std::string utf16ToUtf8(const std::wstring& utf16Str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
    return conv.to_bytes(utf16Str);
}

void modifiableServiceBinary() {

    std::cout << "\n\n[*] Modifiable Service Binaries checking...\n";

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

                if (retCode == ERROR_SUCCESS) {
                    if ((regServiceQuery(achKey, L"ImagePath") != L"FALSE") &&
                        (regServiceQuery(achKey, L"ImagePath").find(L".exe") != std::string::npos) // sadece exe barindiralari getir
                        ) {
                        // Remove arguments from ImagePath
                        std::string exeSign = ".exe";
                        std::string serviceImagePathRaw = ws2s(regServiceQuery(achKey, L"ImagePath"));
                        int indexInt = stdIndexOf(serviceImagePathRaw, exeSign);

                        std::string cleanedServiceImagePath = serviceImagePathRaw.substr(0, indexInt + 4);


                        
                        if ((HasPermissionF(cleanedServiceImagePath, FILE_GENERIC_WRITE))) {
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