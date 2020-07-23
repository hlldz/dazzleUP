#include <codecvt>
#include <vector>
#include <iostream>
#include <sstream>
#include <string>
#include <regex>
#include <algorithm>

#include <windows.h>
#include <wincred.h>
#include <wuapi.h>
#include <atlbase.h>
#include <comdef.h>
#include <ATLComTime.h>

#include <sddl.h>

constexpr auto MAX_KEY_LENGTH = 255;
constexpr auto MAX_VALUE_NAME = 16383;

void textIntro() {
    std::cout << R"(
          _               _      _   _ ____  
       __| | __ _ _______| | ___| | | |  _ \ 
      / _` |/ _` |_  /_  / |/ _ \ | | | |_) |
     | (_| | (_| |/ / / /| |  __/ |_| |  __/ 
      \__,_|\__,_/___/___|_|\___|\___/|_|    

            Version    : 1.0
            Author     : Halil Dalabasmaz
            WWW        : artofpwn.com
            Twitter    : @hlldz
            Github     : @hlldz
            Licence    : GNU General Public License v3.0)" << "\n";
}

std::string ws2s(const std::wstring& wstr) {
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.to_bytes(wstr);
}

int stdIndexOf(std::string& text, std::string& pattern) {
    std::string::size_type loc = text.find(pattern, 0);
    if (loc != std::string::npos) {
        return (int)loc;
    }
    else {
        return -1;
    }
}

std::vector<std::string> strSplit(const std::string& s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;

    while (getline(ss, item, delim)) {
        result.push_back(item);
    }

    return result;
}

bool fileExists(std::string szPath) {
    DWORD dwAttrib = GetFileAttributesA(szPath.c_str());
    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

std::wstring regServiceQuery(LPCWSTR serviceRegName, LPCWSTR serviceKeyName) {
    std::wstring serviceName = L"SYSTEM\\CurrentControlSet\\Services\\";
    serviceName += serviceRegName;

    wchar_t regEntryValue[255];
    DWORD BufferSize = sizeof(regEntryValue);  //8192;
    DWORD dwRet;
    dwRet = RegGetValue(HKEY_LOCAL_MACHINE, serviceName.c_str(), serviceKeyName, RRF_RT_ANY, NULL, (PVOID)&regEntryValue, &BufferSize);

    if (dwRet == 0) {
        RegCloseKey(HKEY_LOCAL_MACHINE);
        return regEntryValue;
    }
    else {
        RegCloseKey(HKEY_LOCAL_MACHINE);
        return L"FALSE";
    }
}

//Awesome solution, http://blog.aaronballman.com/2011/08/how-to-check-access-rights/
bool HasPermissionF(std::string folderName, DWORD genericAccessRights) {
    bool bRet = false;
    DWORD length = 0;
    if (!GetFileSecurityA(folderName.c_str(), OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION, NULL, NULL, &length) &&
        ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
        PSECURITY_DESCRIPTOR security = static_cast<PSECURITY_DESCRIPTOR>(malloc(length));
        if (security && GetFileSecurityA(folderName.c_str(), OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION, security, length, &length)) {
            HANDLE hToken = NULL;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_QUERY |
                TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &hToken)) {
                HANDLE hImpersonatedToken = NULL;
                if (DuplicateToken(hToken, SecurityImpersonation, &hImpersonatedToken)) {
                    GENERIC_MAPPING mapping = { 0xFFFFFFFF };
                    PRIVILEGE_SET privileges = { 0 };
                    DWORD grantedAccess = 0, privilegesLength = sizeof(privileges);
                    BOOL result = FALSE;

                    mapping.GenericRead = FILE_GENERIC_READ;
                    mapping.GenericWrite = FILE_GENERIC_WRITE;
                    mapping.GenericExecute = FILE_GENERIC_EXECUTE;
                    mapping.GenericAll = FILE_ALL_ACCESS;

                    MapGenericMask(&genericAccessRights, &mapping);
                    if (AccessCheck(security, hImpersonatedToken, genericAccessRights,
                        &mapping, &privileges, &privilegesLength, &grantedAccess, &result)) {
                        bRet = (result == TRUE);
                    }
                    CloseHandle(hImpersonatedToken);
                }
                CloseHandle(hToken);
            }
            free(security);
        }
    }

    return bRet;
}

// Inspired by the above function, it was rewritten for the registry.
bool HasPermissionR(HKEY regRoot, std::string regKey, DWORD genericAccessRights) {
    bool bRet = false;
    HKEY hKey;

    if ((RegOpenKeyExA(regRoot, regKey.c_str(), 0, KEY_READ, &hKey)) == ERROR_SUCCESS) {
        DWORD size = 0;
        //PSECURITY_DESCRIPTOR psd = LocalAlloc(LMEM_FIXED, size);
        //LPSTR* DACL = new LPSTR;

        if (RegGetKeySecurity(hKey, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, &size) == ERROR_INSUFFICIENT_BUFFER) {
            PSECURITY_DESCRIPTOR psd = static_cast<PSECURITY_DESCRIPTOR>(malloc(size));

            if (RegGetKeySecurity(hKey, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, psd, &size) == ERROR_SUCCESS) {
                //ConvertSecurityDescriptorToStringSecurityDescriptorA(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, DACL, NULL);
                //std::cout << *DACL;

                HANDLE hToken = NULL;
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &hToken)) {
                    HANDLE hImpersonatedToken = NULL;
                    if (DuplicateToken(hToken, SecurityImpersonation, &hImpersonatedToken)) {
                        GENERIC_MAPPING mapping = { 0xFFFFFFFF };
                        PRIVILEGE_SET privileges = { 0 };
                        DWORD grantedAccess = 0, privilegesLength = sizeof(privileges);
                        BOOL result = FALSE;

                        mapping.GenericRead = KEY_READ;
                        mapping.GenericWrite = KEY_WRITE;
                        mapping.GenericExecute = KEY_EXECUTE;
                        mapping.GenericAll = KEY_ALL_ACCESS;

                        MapGenericMask(&genericAccessRights, &mapping);
                        if (AccessCheck(psd, hImpersonatedToken, genericAccessRights,
                            &mapping, &privileges, &privilegesLength, &grantedAccess, &result)) {
                            bRet = (result == TRUE);
                        }
                        else {
                            std::cout << "- AccessCheck FAILED! - " << GetLastError() << "\n";
                            bRet = FALSE;
                        }
                        CloseHandle(hImpersonatedToken);
                    }
                    CloseHandle(hToken);
                }
                free(psd);
            }
        }
    }
    else {
        //std::cout << "\n- RegOpenKeyExA FAILED! - " << GetLastError() << "\n";
        bRet = FALSE;
    }

    RegCloseKey(hKey);

    return bRet;
}
