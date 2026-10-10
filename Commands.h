#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <tlhelp32.h>
#include "Helpers.h"

typedef enum _SYSTEM_INFORMATION_CLASS { SystemBasicInformation = 0 } SYSTEM_INFORMATION_CLASS;
typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* pfnZwSetSystemTime)(PLARGE_INTEGER, PLARGE_INTEGER);
typedef INT_PTR(WINAPI* GenericFuncPtr)(UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR);

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved; ULONG TimerResolution; ULONG PageSize; ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber; ULONG HighestPhysicalPageNumber; ULONG AllocationGranularity;
    ULONG_PTR MinimumUserAddress; ULONG_PTR MaximumUserAddress; ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

__declspec(noinline) inline void TargetTestFunction() {
    std::cout << "\n[Target Function] Internal routine executed normally.\n\n";
}


inline void ExecuteColorToggle(const std::vector<std::string>& args) {
    if (args.empty()) {
        PrintStatus(false, "[-] Error: Syntax must be: -color {1|0}");
        return;
    }
    if (args.at(0) == "1") {
        g_ColorEnabled = true;
        PrintStatus(true, "[+] Custom color formatting enabled.");
    }
    else {
        g_ColorEnabled = false;
        std::cout << "[*] Color formatting disabled.\n";
    }
}

inline void ExecuteNtQuerySystemInformation(const std::vector<std::string>& args) {
    if (args.empty()) return;
    int infoClass = std::stoi(args.at(0));
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    pfnNtQuerySystemInformation NtQuery = (pfnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (infoClass == 0 && NtQuery) {
        SYSTEM_BASIC_INFORMATION sbi = { 0 };
        ULONG retLen = 0;
        if (NtQuery(SystemBasicInformation, &sbi, sizeof(sbi), &retLen) == 0) {
            std::stringstream ss;
            ss << "[+] Page Size: " << sbi.PageSize << " bytes | CPU Cores: " << (int)sbi.NumberOfProcessors;
            PrintStatus(true, ss.str());
        }
    }
}

inline void ExecuteZwSetSystemTime(const std::vector<std::string>& args) {
    if (args.empty()) {
        PrintStatus(false, "[-] Error: Argument or -address directive required.");
        return;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    pfnZwSetSystemTime SetTime = (pfnZwSetSystemTime)GetProcAddress(hNtdll, "ZwSetSystemTime");
    if (!SetTime) return;

    unsigned long long resolvedTime = 0;

    if (args.at(0) == "-address" && args.size() >= 2) {
        unsigned long long sourceAddr = std::stoull(args.at(1), nullptr, 16);
        void* pSource = reinterpret_cast<void*>(sourceAddr);
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(GetCurrentProcess(), pSource, &resolvedTime, sizeof(resolvedTime), &bytesRead)) {
            std::stringstream ss;
            ss << "[+] Resolved value from address 0x" << std::hex << std::uppercase << sourceAddr << ": " << std::dec << resolvedTime;
            PrintStatus(true, ss.str());
        }
        else {
            PrintStatus(false, "[-] Failed to read value from specified memory address location.");
            return;
        }
    }
    else {
        resolvedTime = std::stoull(args.at(0));
    }

    LARGE_INTEGER newTime, oldTime = { 0 };
    newTime.QuadPart = static_cast<LONGLONG>(resolvedTime);
    if (SetTime(&newTime, &oldTime) == 0) {
        PrintStatus(true, "[+] Time adjusted successfully!");
    }
    else {
        PrintStatus(false, "[-] Adjustment rejected by kernel (STATUS_INVALID_PARAMETER / PRIVILEGE_NOT_HELD).");
    }
}

inline void ExecutePatchMemory(const std::vector<std::string>& args) {
    if (args.size() < 2) return;
    unsigned long long rawAddr = std::stoull(args.at(0), nullptr, 16);
    LPVOID targetAddr = reinterpret_cast<LPVOID>(rawAddr);
    std::vector<BYTE> newBytes = ParseHexBytes(args.at(1));

    HANDLE hProc = GetCurrentProcess();
    bool isExternal = false;
    if (args.size() >= 3) {
        hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, std::stoul(args.at(2)));
        if (!hProc) {
            PrintStatus(false, "[-] Failed to open target external process.");
            return;
        }
        isExternal = true;
    }

    DWORD oldProtect = 0;
    if (VirtualProtectEx(hProc, targetAddr, newBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        SIZE_T written = 0;
        WriteProcessMemory(hProc, targetAddr, newBytes.data(), newBytes.size(), &written);
        VirtualProtectEx(hProc, targetAddr, newBytes.size(), oldProtect, &oldProtect);
        FlushInstructionCache(hProc, targetAddr, newBytes.size());
        PrintStatus(true, "[+] Successfully patched memory bytes.");
    }
    if (isExternal) CloseHandle(hProc);
}

inline void ExecuteArbitraryCall(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        PrintStatus(false, "[-] Error: Syntax must be: -call {dll_name} {function_name} [args_hex_optional...]");
        return;
    }

    std::string dllName = args.at(0);
    std::string funcName = args.at(1);
    std::wstring wDllName(dllName.begin(), dllName.end());
    HMODULE hModule = LoadLibraryW(wDllName.c_str());

    if (!hModule) return;
    FARPROC rawAddress = GetProcAddress(hModule, funcName.c_str());
    if (!rawAddress) {
        FreeLibrary(hModule);
        return;
    }

    UINT_PTR params[4] = { 0, 0, 0, 0 };
    for (size_t i = 2; i < args.size() && (i - 2) < 4; ++i) {
        params[i - 2] = static_cast<UINT_PTR>(std::stoull(args.at(i), nullptr, 16));
    }

    GenericFuncPtr DynamicCall = reinterpret_cast<GenericFuncPtr>(rawAddress);
    INT_PTR returnCode = DynamicCall(params[0], params[1], params[2], params[3]);

    std::stringstream ssResult;
    ssResult << "[+] Function execution completed. Return Code: " << std::dec << returnCode;
    PrintStatus(true, ssResult.str());
    FreeLibrary(hModule);
}


inline void ExecuteReadMemory(const std::vector<std::string>& args) {
    if (args.empty()) return;
    unsigned long long rawAddr = std::stoull(args.at(0), nullptr, 16);
    LPVOID targetAddr = reinterpret_cast<LPVOID>(rawAddr);
    size_t byteCount = (args.size() >= 2) ? std::stoul(args.at(1)) : 4;

    HANDLE hProc = GetCurrentProcess();
    bool isExternal = false;
    if (args.size() >= 3) {
        hProc = OpenProcess(PROCESS_VM_READ, FALSE, std::stoul(args.at(2)));
        if (!hProc) return;
        isExternal = true;
    }

    std::vector<BYTE> buffer(byteCount);
    SIZE_T bytesRead = 0;
    if (ReadProcessMemory(hProc, targetAddr, buffer.data(), byteCount, &bytesRead)) {
        std::stringstream ss;
        ss << "[+] Address 0x" << std::hex << std::uppercase << rawAddr << " bytes: ";
        for (size_t i = 0; i < bytesRead; ++i) {
            ss << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
        }
        PrintStatus(true, ss.str());
    }
    if (isExternal) CloseHandle(hProc);
}

inline void ExecuteWriteMemory(const std::vector<std::string>& args) {
    if (args.size() < 2) return;
    unsigned long long targetAddrRaw = std::stoull(args.at(0), nullptr, 16);
    void* pTarget = reinterpret_cast<void*>(targetAddrRaw);
    unsigned long long valueToWrite = std::stoull(args.at(1));

    DWORD oldProtect = 0;
    if (VirtualProtect(pTarget, sizeof(valueToWrite), PAGE_READWRITE, &oldProtect)) {
        std::memcpy(pTarget, &valueToWrite, sizeof(valueToWrite));
        VirtualProtect(pTarget, sizeof(valueToWrite), oldProtect, &oldProtect);
        PrintStatus(true, "[+] Memory write completed successfully.");
    }
}

inline void ExecuteProcessList(const std::vector<std::string>& args) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnapshot, &pe)) {
        std::cout << std::left << std::setw(30) << "Process Name" << " | PID\n-----------------------------------------\n";
        do {
            std::wstring wName(pe.szExeFile);
            std::string name(wName.begin(), wName.end());
            if (!args.empty() && name.find(args.at(0)) == std::string::npos) continue;
            std::cout << std::left << std::setw(30) << name << " | " << std::dec << pe.th32ProcessID << "\n";
        } while (Process32NextW(hSnapshot, &pe));
        PrintStatus(true, "[+] Process scan completed.");
    }
    CloseHandle(hSnapshot);
}

inline void ExecuteKillProcess(const std::vector<std::string>& args) {
    if (args.empty()) return;
    DWORD pid = std::stoul(args.at(0));
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return;
    if (TerminateProcess(hProcess, 1)) {
        std::stringstream ss;
        ss << "[+] Process ID " << pid << " forcefully terminated.";
        PrintStatus(true, ss.str());
    }
    CloseHandle(hProcess);
}
