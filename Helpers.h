#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <sstream>

inline bool g_ColorEnabled = false;

#define CLR_RESET   "\033[0m"
#define CLR_GREEN   "\033[32m"
#define CLR_RED     "\033[31m"

inline void PrintStatus(bool success, const std::string& message) {
    if (g_ColorEnabled) {
        if (success) {
            std::cout << CLR_GREEN << message << CLR_RESET << "\n";
        }
        else {
            std::cout << CLR_RED << message << CLR_RESET << "\n";
        }
    }
    else {
        std::cout << message << "\n";
    }
}


inline std::vector<std::string> Tokenize(const std::string& input) {
    std::vector<std::string> tokens;
    std::stringstream ss(input);
    std::string token;
    while (ss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

inline std::vector<BYTE> ParseHexBytes(const std::string& hexStr) {
    std::vector<BYTE> bytes;
    std::string cleanStr = (hexStr.rfind("0x", 0) == 0) ? hexStr.substr(2) : hexStr;

    if (cleanStr.length() % 2 != 0) {
        cleanStr = "0" + cleanStr;
    }

    for (size_t i = 0; i < cleanStr.length(); i += 2) {
        std::string byteString = cleanStr.substr(i, 2);
        BYTE byte = static_cast<BYTE>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

inline bool SetPrivilege(LPCWSTR lpszPrivilege, bool bEnablePrivilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        CloseHandle(hToken);
        return false;
    }

    bool success = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    return success;
}
