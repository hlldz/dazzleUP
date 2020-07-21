bool isUserInAdministrativeGroup() {
    bool checkResult = FALSE;

    DWORD dwError;

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        dwError = GetLastError();
        return "OpenProcessToken failed, error " + dwError;
    }

    DWORD len = 0;
    if (!GetTokenInformation(hToken, TokenGroups, NULL, 0, &len)) {
        dwError = GetLastError();
        if (dwError != ERROR_INSUFFICIENT_BUFFER) {
            return "GetTokenInformation failed, error " + dwError;
            CloseHandle(hToken);
        }
    }

    PTOKEN_GROUPS to = (PTOKEN_GROUPS)LocalAlloc(LPTR, len);
    if (!to) {
        dwError = GetLastError();
        return "LocalAlloc failed, error " + dwError;
        CloseHandle(hToken);
    }

    if (!GetTokenInformation(hToken, TokenGroups, to, len, &len)) {
        dwError = GetLastError();
        return "GetTokenInformation failed, error " + dwError;
        LocalFree(to);
        CloseHandle(hToken);
    }

    int sidGroupCount = to->GroupCount;
    std::vector <std::string> userGroupSIDList;

    for (int i = 0; i < sidGroupCount; i++) {
        LPSTR szSID = NULL;
        ConvertSidToStringSidA(to->Groups[i].Sid, &szSID);
        userGroupSIDList.push_back(szSID);
        //std::cout << szSID << "\n";
    }

    if (std::find(userGroupSIDList.begin(), userGroupSIDList.end(), "S-1-5-32-544") != userGroupSIDList.end()) {
        checkResult = TRUE;
    }

    LocalFree(to);
    CloseHandle(hToken);

    return checkResult;
}

std::string detectProcessUser() {
    DWORD dwError;

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        dwError = GetLastError();
        return "OpenProcessToken failed, error " + dwError;
    }

    DWORD len = 0;
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &len)) {
        dwError = GetLastError();
        if (dwError != ERROR_INSUFFICIENT_BUFFER) {
            return "GetTokenInformation failed, error " + dwError;
            CloseHandle(hToken);
        }
    }

    PTOKEN_USER to = (PTOKEN_USER)LocalAlloc(LPTR, len);
    if (!to) {
        dwError = GetLastError();
        return "LocalAlloc failed, error " + dwError;
        CloseHandle(hToken);
    }

    if (!GetTokenInformation(hToken, TokenUser, to, len, &len)) {
        dwError = GetLastError();
        return "GetTokenInformation failed, error " + dwError;
        LocalFree(to);
        CloseHandle(hToken);
    }

    char nameUser[256] = { 0 };
    char domainName[256] = { 0 };
    DWORD nameUserLen = 256;
    DWORD domainNameLen = 256;
    SID_NAME_USE snu;

    if (!LookupAccountSidA(NULL, to->User.Sid, nameUser, &nameUserLen, domainName, &domainNameLen, &snu)) {
        dwError = GetLastError();
        return "LookupAccountSid failed, error " + dwError;
        LocalFree(to);
        CloseHandle(hToken);
    }

    //std::cout << domainName << "\\" << nameUser << "\n";

    std::string processUsername = domainName;
    processUsername += "\\";
    processUsername += nameUser;

    LocalFree(to);
    CloseHandle(hToken);

    return processUsername;
}

//https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/09ebc7f1-e3e9-4fd3-a57e-1d43b36e8f82/how-to-tell-what-processes-are-running-with-elevated-privileges?forum=windowssecurity
std::string integrityLevel() {
    std::string integrityLevel;

    HANDLE hToken;
    HANDLE hProcess;

    DWORD dwLengthNeeded;
    DWORD dwError = ERROR_SUCCESS;

    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel;

    hProcess = GetCurrentProcess();
    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken)) {
        // Get the Integrity level.
        if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded)) {
            dwError = GetLastError();
            if (dwError == ERROR_INSUFFICIENT_BUFFER) {
                pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
                if (pTIL != NULL) {
                    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded)) {
                        dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

                        if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID) {
                            // Low Integrity
                            integrityLevel = "LOW";
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
                            // Medium Integrity
                            integrityLevel = "MEDIUM";
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
                            // High Integrity
                            integrityLevel = "HIGH";
                        }
                    }
                    LocalFree(pTIL);
                }
            }
        }
        CloseHandle(hToken);
    }

    return integrityLevel;
}

void checkUserInAdministrativeGroup() {

    if (isUserInAdministrativeGroup() == TRUE) {
        std::cout << "\n[!] NOTE: Current user is in a local group that grants administrative privileges! Use UAC Bypass attacks to elevate privileges to admin.\n";
    }
}

int osReleaseId() {
    char releaseId[255];
    DWORD BufferSize = 8192;
    RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId", RRF_RT_ANY, NULL, (PVOID)&releaseId, &BufferSize);
    return (int)std::stoi(releaseId);
}

void getOSInfo() {

    DWORD productNameBSize = 8192;
    wchar_t productName[255];
    RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName", RRF_RT_ANY, NULL, (PVOID)&productName, &productNameBSize);

    DWORD editionIDBSize = 8192;
    wchar_t editionID[255];
    RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"EditionID", RRF_RT_ANY, NULL, (PVOID)&editionID, &editionIDBSize);

    std::wcout << "\n[*] Windows OS Info: \t" << productName << ", Edition: " << editionID << ", Release ID: " << osReleaseId() << "\n";

}

void getProcessUsername() {
    std::cout << "[*] Process Username: \t" << detectProcessUser() << "\n";
}

void getProcessIntegrityLevel() {

    std::cout << "[*] Integrity Level: \t" << integrityLevel() << "\n";

}

void getProcessPrivileges() {

    
    std::cout << "[*] Token Privileges: \n";

    DWORD dwError;

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        dwError = GetLastError();
        std::cout << "OpenProcessToken failed, error " << dwError;
    }

    DWORD len = 0;
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &len)) {
        dwError = GetLastError();
        if (dwError != ERROR_INSUFFICIENT_BUFFER) {
            std::cout << "GetTokenInformation failed, error " << dwError;
            CloseHandle(hToken);
        }
    }

    PTOKEN_PRIVILEGES tokenPrivs = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, len);

    if (!tokenPrivs) {
        dwError = GetLastError();
        std::cout << "LocalAlloc failed, error " << dwError;
        CloseHandle(hToken);
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, tokenPrivs, len, &len)) {
        dwError = GetLastError();
        std::cout << "GetTokenInformation failed, error " << dwError;
        LocalFree(tokenPrivs);
        CloseHandle(hToken);
    }

    for (DWORD i = 0; i < tokenPrivs->PrivilegeCount; i++) {


        DWORD dwSize = 0;
        LookupPrivilegeNameA(NULL, &tokenPrivs->Privileges[i].Luid, NULL, &dwSize);
        LPSTR szName = new CHAR[dwSize + 1];
        LookupPrivilegeNameA(NULL, &tokenPrivs->Privileges[i].Luid, szName, &dwSize);

        /*
        LPSTR lpPrivDisplayName = NULL;
        DWORD dwLength = 0;
        DWORD dwLangId;
        if (!LookupPrivilegeDisplayNameA(NULL, szName, lpPrivDisplayName, &dwLength, &dwLangId)) {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                std::cout << "Lookup privilege display name failed. Code: " << GetLastError() << "\n";
            }

            lpPrivDisplayName = new char[dwLength + 1];
        }
        if (!LookupPrivilegeDisplayNameA(NULL, szName, lpPrivDisplayName, &dwLength, &dwLangId)) {
            std::cout << "Lookup privilege display name failed. Code: " << GetLastError() << "\n";
        }
        std::cout << lpPrivDisplayName << " ===> ";
        delete[] lpPrivDisplayName;

        */

        auto& tAttr = tokenPrivs->Privileges[i].Attributes;
        auto& tLuid = tokenPrivs->Privileges[i].Attributes;


        if (tAttr & SE_PRIVILEGE_ENABLED) {
            std::cout << "\t\t\tENABLED:  ";
        }
        /*
        else if (tAttr & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
            std::cout << "ENABLED BY DEFAULT\n";
        }
        else if (tAttr & SE_PRIVILEGE_REMOVED) {
            std::cout << "REMOVED\n";
        }
        else if (tAttr & SE_PRIVILEGE_USED_FOR_ACCESS) {
            std::cout << "USED FOR ACCESS\n";
        }
        */
        else {
            std::cout << "\t\t\tDISABLED: ";
        }

        std::cout << szName << "\n";


    }
    CloseHandle(hToken);
}


