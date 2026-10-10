#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include "Helpers.h"
#include "Commands.h"

typedef NTSTATUS(WINAPI* pfnRtlGetVersion)(PRTL_OSVERSIONINFOW);
using KernelFuncWrapper = std::function<void(const std::vector<std::string>&)>;

bool IsRunningAsAdmin() {
    bool fIsElevated = false;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            fIsElevated = elevation.TokenIsElevated;
        }
    }

    if (hToken) {
        CloseHandle(hToken);
    }

    return fIsElevated;
}

int main() {
    if (IsRunningAsAdmin()) {
        SetConsoleTitleW(L"Administrator: Kernel Prompt");
    }
    else {
        SetConsoleTitleW(L"Kernel Prompt");
    }



    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (GetConsoleMode(hOut, &dwMode)) {
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }

    SetCurrentDirectoryW(L"C:\\Windows\\System32");

    HWND hwndConsole = GetConsoleWindow();
    if (hwndConsole) {
        HICON hIcon = LoadIconW(GetModuleHandleW(NULL), L"MAINICON");
        if (hIcon) {
            SendMessageW(hwndConsole, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
            SendMessageW(hwndConsole, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        }
    }

    SetPrivilege(SE_SYSTEMTIME_NAME, true);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        pfnRtlGetVersion RtlGetVersion = (pfnRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
        if (RtlGetVersion) {
            RTL_OSVERSIONINFOW osInfo = { 0 };
            osInfo.dwOSVersionInfoSize = sizeof(osInfo);
            if (RtlGetVersion(&osInfo) == 0) {
                std::cout << "Microsoft Windows [Version "
                    << osInfo.dwMajorVersion << "."
                    << osInfo.dwMinorVersion << "."
                    << osInfo.dwBuildNumber << "]\n";
            }
        }
    }

    std::map<std::string, KernelFuncWrapper> registry;
    registry["-NtQuerySystemInformation"] = ExecuteNtQuerySystemInformation;
    registry["-ZwSetSystemTime"] = ExecuteZwSetSystemTime;
    registry["-patch"] = ExecutePatchMemory;
    registry["-call"] = ExecuteArbitraryCall;
    registry["-color"] = ExecuteColorToggle;
    registry["-read"] = ExecuteReadMemory;
    registry["-write"] = ExecuteWriteMemory;
    //registry["-testaddr"] = ExecuteGetTestAddress;



    void(*testFnPtr)() = TargetTestFunction;
    unsigned long long testAddr = reinterpret_cast<unsigned long long>(testFnPtr);

    std::cout << "Windows Kernel Processor [Version 1.0.1010.26b]\n";

    std::wstring currentDir(MAX_PATH, L'\0');

    while (true) {
        DWORD pathLength = GetCurrentDirectoryW(0, NULL);
        if (pathLength > 0) {
            currentDir.resize(pathLength);
            GetCurrentDirectoryW(pathLength, currentDir.data());
            if (!currentDir.empty() && currentDir.back() == L'\0') {
                currentDir.pop_back();
            }
        }
        std::wcout << "\n";
        std::wcout << currentDir << L"> ";

        std::string userInput;
        if (!std::getline(std::cin, userInput) || userInput == "exit") break;
        if (userInput.empty()) continue;

        std::vector<std::string> tokens = Tokenize(userInput);
        if (tokens.empty()) continue;

        std::string commandKeyword = tokens[0];

        auto it = registry.find(commandKeyword);
        if (it != registry.end()) {
            std::vector<std::string> funcArgs(tokens.begin() + 1, tokens.end());
            it->second(funcArgs);
        }
        else if (commandKeyword == "test") {
            TargetTestFunction();
        }
        else {
            if (commandKeyword == "cd" && tokens.size() > 1) {
                std::wstring wTargetDir(tokens[1].begin(), tokens[1].end());
                if (!SetCurrentDirectoryW(wTargetDir.c_str())) {
                    std::cout << "[-] The system cannot find the path specified.\n";
                }
            }
            else {
                std::wstring wCmd(userInput.begin(), userInput.end());

                STARTUPINFOW si = { sizeof(si) };
                PROCESS_INFORMATION pi;

                if (CreateProcessW(NULL, const_cast<LPWSTR>(wCmd.c_str()), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
                else {
                    std::system(userInput.c_str());
                }
            }
        }
    }
    return 0;
}
