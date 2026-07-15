#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten
	);

DWORD get_process_id(const wchar_t* process_name) {
	DWORD pid = 0;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(entry);
	if (Process32FirstW(snap, &entry)) {
		do {
			if (_wcsicmp(entry.szExeFile, process_name) == 0) {
				pid = entry.th32ProcessID;
				break;
			}
		} while (Process32NextW(snap, &entry));
	}
	CloseHandle(snap);
	return pid;
}

struct Candidate {
	uintptr_t address;
};

std::vector<Candidate> candidates;

void first_scan(HANDLE h_process, int32_t value) {
	printf("performing first scan for value: %d...\n", value);
	candidates.clear();
	MEMORY_BASIC_INFORMATION mbi;
	uintptr_t address = 0;
	while (VirtualQueryEx(h_process, (LPCVOID)address, &mbi, sizeof(mbi))) {
		if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READWRITE))) {
			if (mbi.RegionSize > 0x1000000) {
				address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
				continue;
			}
			std::vector<char> buffer(mbi.RegionSize);
			SIZE_T bytes_read = 0;
			if (ReadProcessMemory(h_process, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytes_read)) {
				for (SIZE_T i = 0; i <= bytes_read - sizeof(int32_t); ++i) {
					if (*(int32_t*)(buffer.data() + i) == value) {
						candidates.push_back({ (uintptr_t)mbi.BaseAddress + i });
					}
				}
			}
		}
		address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
		if (address >= 0x7FFFFFFFFFFF) break;
	}
	printf("first scan complete. found %zu candidates.\n\n", candidates.size());
}

void next_scan(HANDLE h_process, int32_t value) {
	if (candidates.empty()) return;
	printf("next scan for value: %d (checking %zu candidates)...\n", value, candidates.size());
	std::vector<Candidate> new_candidates;
	int32_t buffer;
	for (const auto& cand : candidates) {
		SIZE_T bytes_read = 0;
		if (ReadProcessMemory(h_process, (LPCVOID)cand.address, &buffer, sizeof(buffer), &bytes_read)) {
			if (buffer == value) {
				new_candidates.push_back(cand);
			}
		}
	}
	candidates = std::move(new_candidates);
	printf("remaining candidates: %zu\n\n", candidates.size());
}

int main() {
	const wchar_t* target_process = L"Egg.exe";
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) return 1;

	auto nt_write_virtual_memory = (NtWriteVirtualMemory_t)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	if (!nt_write_virtual_memory) return 1;

	DWORD pid = get_process_id(target_process);
	if (!pid) {
		fprintf(stderr, "egg.exe not found.\n");
		return 1;
	}
	printf("egg.exe found! pid: %lu\n\n", pid);

	HANDLE h_process = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (!h_process) {
		fprintf(stderr, "openprocess failed. run as administrator.\n");
		return 1;
	}

	bool first_scan_done = false;
	while (true) {
		printf("enter current egg value: ");
		int32_t current_value;
		if (scanf_s("%d", &current_value) != 1) {
			break;
		}
		if (current_value == -1) break;

		if (!first_scan_done) {
			first_scan(h_process, current_value);
			first_scan_done = true;
		}
		else {
			next_scan(h_process, current_value);
		}

		if (candidates.size() == 1) {
			uintptr_t addr = candidates[0].address;
			printf("unique address found!\n");
			printf("address: 0x%llx\n\n", (unsigned long long)addr);

			printf("enter new egg value: ");
			int32_t new_value;
			if (scanf_s("%d", &new_value) != 1) {
				break;
			}

			SIZE_T written = 0;
			NTSTATUS status = nt_write_virtual_memory(h_process, (PVOID)addr, &new_value, sizeof(new_value), &written);
			if (status == 0)
				printf("success. set to %d\n\n", new_value);
			else
				fprintf(stderr, "write failed.\n\n");
		}
		else if (candidates.size() == 0) {
			printf("no candidates left. start over.\n\n");
			first_scan_done = false;
		}
		else {
			printf("still %zu candidates. change egg count in game and scan again.\n\n", candidates.size());
		}
	}

	CloseHandle(h_process);
	return 0;
}
