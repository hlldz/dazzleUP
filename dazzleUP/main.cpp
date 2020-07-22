#include "headers/helpers/helpers_and_std_headers.h"
#include "headers/helpers/process_os_info.h"

#include "headers/exploit_checks/update_checker.h"
#include "headers/exploit_checks/dcom_ntlm_reflection.h"
#include "headers/exploit_checks/CVE_2019_0836.h"
#include "headers/exploit_checks/CVE_2019_0841.h"
#include "headers/exploit_checks/CVE_2019_1064.h"
#include "headers/exploit_checks/CVE_2019_1130.h"
#include "headers/exploit_checks/CVE_2019_1253.h"
#include "headers/exploit_checks/CVE_2019_1315.h"
#include "headers/exploit_checks/CVE_2019_1385.h"
#include "headers/exploit_checks/CVE_2019_1388.h"
#include "headers/exploit_checks/CVE_2019_1405.h"
#include "headers/exploit_checks/CVE_2020_0787.h"
#include "headers/exploit_checks/CVE_2020_0796.h"

#include "headers/misconf_checks/always_install_elevated.h"
#include "headers/misconf_checks/unquoted_service_path.h"
#include "headers/misconf_checks/modifiable_service_binary.h"
#include "headers/misconf_checks/modifiable_service_registry.h"
#include "headers/misconf_checks/unattended_install_file.h"
#include "headers/misconf_checks/mcafee_sitelist_xml.h"
#include "headers/misconf_checks/modifiable_registry_autorun_keys.h"
#include "headers/misconf_checks/modifiable_registry_autorun_bins.h"
#include "headers/misconf_checks/path_dll_hijack.h"
#include "headers/misconf_checks/credential_manager.h"

void process_specs() {
    std::cout << "\n\n\n\t---========== GENERAL INFORMATION ==========---\n";
    checkUserInAdministrativeGroup();
    getOSInfo();
    getProcessUsername();
    getProcessIntegrityLevel();
    getProcessPrivileges();
}

void exploit_checks() {

    std::cout << "\n\n\t---========== EXPLOIT CHECKS ==========---\n";

    detectDcomNtlmReflection();

    if (osReleaseId() >= 1809) {
        if (isUpdatesCheckable() == TRUE) {
            if (getInstalledUpdates() == TRUE) {
                CVE_2019_0836();
                CVE_2019_0841();
                CVE_2019_1064();
                CVE_2019_1130();
                CVE_2019_1253();
                CVE_2019_1385();
                CVE_2019_1388();
                CVE_2019_1405();
                CVE_2019_1315();
                CVE_2020_0787();
                CVE_2020_0796();
            }            
        }
        else {
            std::cout << "\n\n[!] Your process running under " << detectProcessUser() << " privilege. Swicth to normal user. I can't check installed updates...\n";
        }
    }
    else {
        std::cout << "\n\n[!] Target system build number is not supported by dazzleUP, passing missing updates controls...\n";
    }

}

void misconf_checks() {

    std::cout << "\n\n\t---========== MISCONFIGURATION CHECKS ==========---\n";
    alwaysInstallElevated();
    unquotedServicePath();
    modifiableServiceBinary();
    modifiableServiceRegistry();
    pathDLLHijack();
    modifiableRegistryAutoRunKeys();
    modifiableRegistryAutoRunBinPaths();
    credentialManagerEnumerate();
    unattendedInstallFile();
    siteListXMLFile();

}

int main() {
    
    textIntro();

    process_specs();
    
    exploit_checks();
    
    misconf_checks();
    
    std::cout << "\n\n[+] All done.\n";

    return 0;

}
