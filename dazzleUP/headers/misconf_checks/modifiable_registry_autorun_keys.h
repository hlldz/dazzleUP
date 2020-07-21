void modifiableRegistryAutoRunKeys() {
	std::cout << "\n\n[*] Modifiable Registry AutoRun Keys checking...\n\n";

	std::vector <LPCSTR> registryAutoRunLocations;

	registryAutoRunLocations.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
	registryAutoRunLocations.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
	registryAutoRunLocations.push_back("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");
	registryAutoRunLocations.push_back("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
	registryAutoRunLocations.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService");
	registryAutoRunLocations.push_back("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService");
	registryAutoRunLocations.push_back("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService");
	registryAutoRunLocations.push_back("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService");

	for (LPCSTR registryKey : registryAutoRunLocations) {
		if (HasPermissionR(HKEY_LOCAL_MACHINE, registryKey, KEY_WRITE) == TRUE) {
			std::cout << "\tWriteable:\t HKLM\\" << registryKey << "\n";
		}
	}
}

