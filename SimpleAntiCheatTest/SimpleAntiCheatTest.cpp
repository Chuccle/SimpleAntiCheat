#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

bool EnableDebugPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << "\n";
        return false;
    }

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
    {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

DWORD FindProcessId(const std::wstring_view ProcessName)
{
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, ProcessName.data()) == 0)
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

void TestRemoteProcessMemory(HANDLE Process)
{
    LPVOID remoteMem = VirtualAllocEx(Process, nullptr, sizeof(int), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem)
    {
        std::wcout << L"[Blocked] VirtualAllocEx Could not allocate remote memory" << "\n";
        return;
    }
    else
    {
        std::wcout << L"[Allowed] VirtualAllocEx Could not allocate remote memory" << "\n";
    }

    int testValue = 42;
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(Process, remoteMem, &testValue, sizeof(testValue), &bytesWritten))
    {
        std::cout << "[Blocked] WriteProcessMemory failed. Error: " << GetLastError() << "\n";
    }
    else
    {
        std::cout << "[Allowed] WriteProcessMemory succeeded! Should be blocked.\n";
    }

    int readValue = 0;
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(Process, remoteMem, &readValue, sizeof(readValue), &bytesRead))
    {
        std::cout << "[Blocked] ReadProcessMemory failed. Error: " << GetLastError() << "\n";
    }
    else
    {
        std::cout << "[Allowed] ReadProcessMemory succeeded! Should be blocked.\n";
    }

    std::cout << "Read value: " << readValue << "\n";

    VirtualFreeEx(Process, remoteMem, 0, MEM_RELEASE);
}

void TestProcessOperations(DWORD Pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, Pid);
    if (!hProcess)
    {
        std::wcout << L"[Failed] Could not open process. Error: " << GetLastError() << "\n";
        return;
    }

    std::cout << "[Info] Process handle opened. Testing memory operations...\n";

    TestRemoteProcessMemory(hProcess);

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(MessageBoxW), nullptr, 0, nullptr);

    if (!hThread)
    {
        std::cout << "[Blocked] CreateRemoteThread failed. Error: " << GetLastError() << "\n";
    }
    else
    {
        std::cout << "[Allowed] CreateRemoteThread succeeded! Should be blocked.\n";
        CloseHandle(hThread);
    }

    CloseHandle(hProcess);
}

int main()
{
    if (EnableDebugPrivilege())
    {
        std::cout << "[+] SeDebugPrivilege enabled\n";
    }
    else
    {
        std::cout << "[-] Failed to enable SeDebugPrivilege\n";
    }

    std::wstring_view targetProcess = L"notepad.exe";
    DWORD pid = FindProcessId(targetProcess);

    if (pid == 0)
    {
        std::cout << "Target process not found.\n";
        return 1;
    }

    std::cout << "[Info] Found process ID: " << pid << "\n";

    TestProcessOperations(pid);

    return 0;
}