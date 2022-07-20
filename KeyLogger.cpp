#include <iostream>
#include <windows.h>
#include <conio.h>

#define	DEF_DLL_PATH ".\\KeyBoardHook.dll"
#define DEF_MUTEX_NAME L"KeyLoggerMutex"

typedef void (*PFN_HOOKSTART)();    // 함수 포인터 정의
typedef void (*PFN_HOOKSTOP)();     // 함수 포인터 정의

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

    // KeyBoardHook.dll 로딩
    hDll = LoadLibraryA(DEF_DLL_PATH);
    if (hDll == NULL)
    {
        cout << "LoadLibrary(" << DEF_DLL_PATH << ") failed!!! [" << dec << GetLastError() << "]";
        ExitProcess(0);
    }

    // export 함수 주소 얻기
    HookStart = (PFN_HOOKSTART)GetProcAddress(hDll, "HookStart");
    HookStop = (PFN_HOOKSTOP)GetProcAddress(hDll, "HookStop");

    // 후킹 시작
    HookStart();

    // 사용자가 'q' 를 입력할 때까지 대기
    cout << "press 'q' to quit!" << endl;
    while (_getch() != 'q');

    // 후킹 종료
    HookStop();

    // KeyBoardHook.dll 언로딩
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
                * (DWORD64)DoChildProcess의 주소값은 E9 110f0000 형식의 jmp 명령어의 주소값을 가진다.(jmp 명령어로 DoChildProcess 함수로 이동)
                * jmp 명령은 상대주소 이동이기 때문에 110f0000(00000f11) 값을 (DWORD64)DoChildProcess 값에 더해서 함수의 실제 위치를 찾을 수 있다.
                * 이때, jmp 명령어(E9 XXXXXXXX) 길이 '5' 만큼을 더 더해준다.
                * 추가로, 인코딩 되어 있는 부분은 DoChildProcess 함수의 시작주소부터 offset 0x1b 만큼 떨어진 위치이기 때문에 추가로 0x1b 값을 더해준다.
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