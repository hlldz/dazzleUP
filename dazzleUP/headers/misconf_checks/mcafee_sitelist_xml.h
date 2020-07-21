bool isXMLFile(const std::wstring& str, const std::wstring& suffix) {
    return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

void findSiteListXml(std::wstring wrkdir) {
    std::wstring wrkdirtemp = wrkdir;
    if (!wrkdirtemp.empty() && (wrkdirtemp[wrkdirtemp.length() - 1] != L'\\')) {
        wrkdirtemp += L"\\";
    }

    WIN32_FIND_DATA file_data = { 0 };
    //HANDLE hFile = FindFirstFile((wrkdirtemp + L"*").c_str(), &file_data);
    // FindExSearchLimitToDirectories, NULL, FIND_FIRST_EX_LARGE_FETCH: For faster search
    HANDLE hFile = FindFirstFileEx((wrkdirtemp + L"*").c_str(), FindExInfoStandard, &file_data, FindExSearchLimitToDirectories, NULL, FIND_FIRST_EX_LARGE_FETCH);

    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if ((wcscmp(file_data.cFileName, L".") != 0) && (wcscmp(file_data.cFileName, L"..") != 0)) {
                findSiteListXml(wrkdirtemp + file_data.cFileName);
            }
        }
        else {
            if ((file_data.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) == 0) {

                if ((wrkdirtemp + file_data.cFileName).find(L"SiteList.xml") != std::string::npos) {
                    if (isXMLFile(wrkdirtemp + file_data.cFileName, L".xml") == TRUE) {
                        std::wcout << "\n\tFile is detected: " << wrkdirtemp << file_data.cFileName << "\n";
                    }
                }
            }
        }
    } while (FindNextFile(hFile, &file_data));

    FindClose(hFile);
}

void siteListXMLFile() {
    std::cout << "\n\n[*] McAfee's SiteList.xml Files checking...\n";

    std::vector <std::wstring> siteListPasswordSearchPaths;

    siteListPasswordSearchPaths.push_back(L"C:\\Program Files\\");
    siteListPasswordSearchPaths.push_back(L"C:\\Program Files (x86)\\");
    siteListPasswordSearchPaths.push_back(L"C:\\Documents and Settings\\");
    siteListPasswordSearchPaths.push_back(L"C:\\Users\\");

    for (std::wstring detected : siteListPasswordSearchPaths) {
        findSiteListXml(detected);
    }

}