#include <iostream>
#include <windows.h>
#include <conio.h>

#define	DEF_DLL_PATH ".\\KeyBoardHook.dll"
#define DEF_MUTEX_NAME L"KeyLoggerMutex"

typedef void (*PFN_HOOKSTART)();    // �Լ� ������ ����
typedef void (*PFN_HOOKSTOP)();     // �Լ� ������ ����

void DoParentProcess();
void DoChildProcess();
extern "C" int SetExceptionCode();

using namespace std;

void DoChildProcess() {

    //MessageBox(NULL, L"ChildProcess", L"DebugMe4", MB_OK);

    HMODULE			hDll = NULL;
    PFN_HOOKSTART	HookStart = NULL;
    PFN_HOOKSTOP	HookStop = NULL;

    cout << "This is a child process!" << endl;

    // KeyBoardHook.dll �ε�
    hDll = LoadLibraryA(DEF_DLL_PATH);
    if (hDll == NULL)
    {
        cout << "LoadLibrary(" << DEF_DLL_PATH << ") failed!!! [" << dec << GetLastError() << "]";
        ExitProcess(0);
    }

    // export �Լ� �ּ� ���
    HookStart = (PFN_HOOKSTART)GetProcAddress(hDll, "HookStart");
    HookStop = (PFN_HOOKSTOP)GetProcAddress(hDll, "HookStop");

    // ��ŷ ����
    HookStart();

    // ����ڰ� 'q' �� �Է��� ������ ���
    cout << "press 'q' to quit!" << endl;
    while (_getch() != 'q');

    // ��ŷ ����
    HookStop();

    // KeyBoardHook.dll ��ε�
    FreeLibrary(hDll);

    ExitProcess(0);
}

void DoParentProcess() {
    wchar_t szPath[MAX_PATH] = { 0, };
    STARTUPINFO si = { sizeof(STARTUPINFO), };
    PROCESS_INFORMATION pi = { 0, };
    DEBUG_EVENT de = { 0, };
    CONTEXT ctx = { 0, };
    DWORD64 dwExcpAddr = 0, dwExcpCode = 0;
    BYTE pBuf[0x30] = { 0, };
    const DWORD DECODING_SIZE = 0x2b;
    const DWORD DECODING_KEY = 0x7F;
    unsigned long offset = 0;
    uint64_t functinoAddress = 0;

    cout << "This is a parent process!" << endl;

    if (!GetModuleFileName(NULL, szPath, MAX_PATH)) {
        cout << "GetModuleFileName() failed! [" << dec << GetLastError() << "]" << endl;
        return;
    }

    if (!CreateProcess(szPath, NULL, NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        cout << "CreateProcess() failed! [" << dec << GetLastError() << "]" << endl;
        return;
    }

    while (TRUE) {
        ZeroMemory(&de, sizeof(DEBUG_EVENT));

        if (!WaitForDebugEvent(&de, INFINITE)) {
            cout << "WaitForDebugEvent() failed! [" << dec << GetLastError() << "]" << endl;
            break;
        }

        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            dwExcpAddr = (DWORD64)de.u.Exception.ExceptionRecord.ExceptionAddress;
            dwExcpCode = de.u.Exception.ExceptionRecord.ExceptionCode;

            //if (dwExcpCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
            if (dwExcpCode == EXCEPTION_ACCESS_VIOLATION) {
                // find DoChildProcess function address
                functinoAddress = (uint64_t)DoChildProcess;
                ReadProcessMemory(pi.hProcess, (LPCVOID)(functinoAddress + 0x1), pBuf, 4, NULL);
                //offset = pBuf[3] * (16 ^ 6) + pBuf[2] * (16 ^ 4) + pBuf[1] * (16 ^ 2) + pBuf[0];
                offset = pBuf[3] * 0x1000000 + pBuf[2] * 0x10000 + pBuf[1] * 0x100 + pBuf[0];

                // decoding
                /*
                * (DWORD64)DoChildProcess�� �ּҰ��� E9 110f0000 ������ jmp ��ɾ��� �ּҰ��� ������.(jmp ��ɾ�� DoChildProcess �Լ��� �̵�)
                * jmp ����� ����ּ� �̵��̱� ������ 110f0000(00000f11) ���� (DWORD64)DoChildProcess ���� ���ؼ� �Լ��� ���� ��ġ�� ã�� �� �ִ�.
                * �̶�, jmp ��ɾ�(E9 XXXXXXXX) ���� '5' ��ŭ�� �� �����ش�.
                * �߰���, ���ڵ� �Ǿ� �ִ� �κ��� DoChildProcess �Լ��� �����ּҺ��� offset 0x1b ��ŭ ������ ��ġ�̱� ������ �߰��� 0x1b ���� �����ش�.
                */
                ReadProcessMemory(pi.hProcess, (LPCVOID)(functinoAddress + offset + 5 + 0x1b), pBuf, DECODING_SIZE, NULL);

                for (DWORD i = 0; i < DECODING_SIZE; i++) {
                    pBuf[i] ^= DECODING_KEY;
                }

                WriteProcessMemory(pi.hProcess, (LPVOID)(functinoAddress + offset + 5 + 0x1b), pBuf, DECODING_SIZE, NULL);


                // change RIP
                ctx.ContextFlags = CONTEXT_FULL;
                GetThreadContext(pi.hThread, &ctx);
                ctx.Rip += 6;
                SetThreadContext(pi.hThread, &ctx);
            }
        } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            break;
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
}

void main() {

    HANDLE hMutex = NULL;
    if (!(hMutex = CreateMutex(NULL, FALSE, DEF_MUTEX_NAME))) {
        cout << "CreateMutex() failed! [" << dec << GetLastError() << "]" << endl;
        return;
    }

    // check mutex
    if (GetLastError() != ERROR_ALREADY_EXISTS) {
        DoParentProcess();
    }
    else {
        SetExceptionCode();
        DoChildProcess();
    }
}