void unattendedInstallFile() {
    std::cout << "\n\n[*] Unattended Install Files checking...\n";

    std::vector <std::string> unattendedInstallFileArray;

    const DWORD buffSize = 65535;
    static char buffer[buffSize];
    GetEnvironmentVariableA("WinDir", buffer, buffSize);
    std::string winDir = buffer;

    unattendedInstallFileArray.push_back("c:\\sysprep\\sysprep.xml");
    unattendedInstallFileArray.push_back("c:\\sysprep\\sysprep.inf");
    unattendedInstallFileArray.push_back("c:\\sysprep.inf");
    unattendedInstallFileArray.push_back(winDir + "\\Panther\\Unattended.xml");
    unattendedInstallFileArray.push_back(winDir + "\\Panther\\Unattend\\Unattended.xml");
    unattendedInstallFileArray.push_back(winDir + "\\Panther\\Unattend.xml");
    unattendedInstallFileArray.push_back(winDir + "\\Panther\\Unattend\\Unattend.xml");
    unattendedInstallFileArray.push_back(winDir + "\\System32\\Sysprep\\unattend.xml");
    unattendedInstallFileArray.push_back(winDir + "\\System32\\Sysprep\\Panther\\unattend.xml");

    for (std::string detected : unattendedInstallFileArray) {
        if (fileExists(detected)) {
            std::cout << "\n\tFile is detected: " << detected << "\n";
        }
    }
}