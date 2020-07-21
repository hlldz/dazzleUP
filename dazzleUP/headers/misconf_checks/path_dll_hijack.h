void pathDLLHijack() {
    std::cout << "\n\n[*] Checking values of %PATH% for DLL Hijack...\n\n";

    const DWORD buffSize = 65535;
    static char buffer[buffSize];
    GetEnvironmentVariableA("Path", buffer, buffSize);

    std::string pathVar = buffer;
    std::string delimiter = ";";
    std::vector<std::string> pathVector = strSplit(pathVar, ';');

    for (auto path : pathVector) {
        if (HasPermissionF(path, GENERIC_WRITE)) {
            std::cout << "\tWritable: " << path << "\n";
        }
    }

}