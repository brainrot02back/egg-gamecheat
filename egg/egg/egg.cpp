#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

DWORD GetProcessID(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}

int main() {
    const wchar_t* TARGET_PROCESS = L"Egg.exe";
    uintptr_t TARGET_ADDRESS = 0x19E18C6DE00; //this offset is dynamic meaning you will have to change it by scanning for it with cheatengine or any other tool

   
    std::cout << "         EGG CHEAT       \n";
  

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        std::cerr << "Failed to get ntdll handle\n";
        return 1;
    }

    auto NtWriteVirtualMemory = (NtWriteVirtualMemory_t)
        GetProcAddress(ntdll, "NtWriteVirtualMemory");
    if (!NtWriteVirtualMemory) {
        std::cerr << "Failed to get NtWriteVirtualMemory\n";
        return 1;
    }

    DWORD pid = GetProcessID(TARGET_PROCESS);
    if (!pid) {
        std::cerr << "Egg.exe not found. Is the game running?\n";
        return 1;
    }

    std::cout << "Egg.exe found! PID: " << pid << "\n";
    std::cout << "Target address: 0x" << std::hex << TARGET_ADDRESS << std::dec << "\n\n";

    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "OpenProcess failed. Run as Administrator. Error: " << GetLastError() << "\n";
        return 1;
    }

    while (true) {
        std::cout << "Enter value to write (or -1 to quit): ";
        int32_t value;
        std::cin >> value;

        if (value == -1) break;

        SIZE_T written = 0;
        NTSTATUS status = NtWriteVirtualMemory(
            hProcess,
            (PVOID)TARGET_ADDRESS,
            &value,
            sizeof(value),
            &written
        );

        if (status == 0)
            std::cout << "[EGG CHEAT] Written " << value << " to 0x" << std::hex << TARGET_ADDRESS << std::dec << "\n";
        else
            std::cerr << "[EGG CHEAT] Write failed. NTSTATUS: 0x" << std::hex << status << std::dec << "\n";
    }

    CloseHandle(hProcess);
    return 0;
}
