void credentialManagerEnumerate() {
    std::cout << "\n\n[*] Enumerating credentials form Credential Manager...\n";

    DWORD Count;
    PCREDENTIALW* Credential;

    if (CredEnumerate(NULL, CRED_ENUMERATE_ALL_CREDENTIALS, &Count, &Credential)) {
        for (size_t i = 0; i < Count; i++) {
            std::wstring credTypeDesc;

            switch (Credential[i]->Type) {
            case 1: credTypeDesc = L"CRED_TYPE_GENERIC"; break;
            case 2: credTypeDesc = L"CRED_TYPE_DOMAIN_PASSWORD"; break;
            case 3: credTypeDesc = L"CRED_TYPE_DOMAIN_CERTIFICATE"; break;
            case 4: credTypeDesc = L"CRED_TYPE_DOMAIN_VISIBLE_PASSWORD"; break;
            case 5: credTypeDesc = L"CRED_TYPE_GENERIC_CERTIFICATE"; break;
            case 6: credTypeDesc = L"CRED_TYPE_DOMAIN_EXTENDED"; break;
            case 7: credTypeDesc = L"CRED_TYPE_MAXIMUM"; break;
            default: credTypeDesc = L"ENUM_FAILED";
            }

            std::wcout << "\n";
            std::wcout << "\t Target Name: \t" << Credential[i]->TargetName << "\n";
            std::wcout << "\t Username: \t" << Credential[i]->UserName << "\n";
            std::wcout << "\t Type: \t\t" << credTypeDesc << "\n";
        }
        CredFree(Credential);
    }
}