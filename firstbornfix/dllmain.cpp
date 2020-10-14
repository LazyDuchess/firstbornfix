#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <iostream>
#include <random>

const DWORD func_addr = 0x00417FB1; //address of the instruction that returns the new random value
const DWORD func_addr_offset = func_addr + 0x2;

//default randomization code
void __declspec(naked) func_stub(void) {
    __asm {
        mov[ecx], eax
        jmp[func_addr_offset]
    }
}

LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if ((DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == func_addr) {
            PCONTEXT debug_context = ExceptionInfo->ContextRecord;
            debug_context->Eip = (DWORD)&func_stub;
            std::random_device rd; // random number
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> distr(12151879, 800930084); //Generate a huge number
            debug_context->Eax = distr(gen) + debug_context->Eax; //Offset the return value of the random function with our own random number
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

//set a breakpoint on the instruction we want to replace (the randomization one!)
void set_breakpoints(void) { 
    HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hTool32 != INVALID_HANDLE_VALUE) {
        THREADENTRY32 thread_entry32;
        thread_entry32.dwSize = sizeof(THREADENTRY32);
        FILETIME exit_time, kernel_time, user_time;
        FILETIME creation_time;
        FILETIME prev_creation_time;
        prev_creation_time.dwLowDateTime = 0xFFFFFFFF;
        prev_creation_time.dwHighDateTime = INT_MAX;
        HANDLE hMainThread = NULL;
        if (Thread32First(hTool32, &thread_entry32)) {
            do {
                if (thread_entry32.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(thread_entry32.th32OwnerProcessID)
                    && thread_entry32.th32OwnerProcessID == GetCurrentProcessId()
                    && thread_entry32.th32ThreadID != GetCurrentThreadId()) {
                    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                        FALSE, thread_entry32.th32ThreadID);
                    GetThreadTimes(hThread, &creation_time, &exit_time, &kernel_time, &user_time);
                    if (CompareFileTime(&creation_time, &prev_creation_time) == -1) {
                        memcpy(&prev_creation_time, &creation_time, sizeof(FILETIME));
                        if (hMainThread != NULL)
                            CloseHandle(hMainThread);
                        hMainThread = hThread;
                    }
                    else
                        CloseHandle(hThread);
                }
                thread_entry32.dwSize = sizeof(THREADENTRY32);
            } while (Thread32Next(hTool32, &thread_entry32));
            AddVectoredExceptionHandler(1, ExceptionFilter);
            CONTEXT thread_context = { CONTEXT_DEBUG_REGISTERS };
            thread_context.Dr0 = func_addr;
            thread_context.Dr7 = (1 << 0);
            SetThreadContext(hMainThread, &thread_context);
            CloseHandle(hMainThread);
        }
        CloseHandle(hTool32);
    }
}

int APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        set_breakpoints();
    }
    return TRUE;
}