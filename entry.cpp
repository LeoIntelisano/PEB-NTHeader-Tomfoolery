// currently not working

#include "funcs.h"
/*
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved)  // reserved
{
     
     //UCANTFINDME_LOADLIB lib = (UCANTFINDME_LOADLIB)pGetProcAddress(pGetModuleHandle(L"Kernel32.dll"), (char*)"LoadLibraryA");
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        printf("Im in!\n");
        DLL_msg msgbox = (DLL_msg)pGetProcAddress(pGetModuleHandle(L"user32.dll"), (char*)"MessageBoxA");
       
        typedef HANDLE(*OPENTHREAD)(DWORD, BOOL, DWORD);
        
        typedef DWORD(*GETCURRENTTHREADID)();
        GETCURRENTTHREADID get_thread_id = (GETCURRENTTHREADID)pGetProcAddress(pGetModuleHandle(L"kernel32.dll"), (char*)"GetCurrentThreadId");
        DWORD tid = get_thread_id();
       
        OPENTHREAD open_thread = (OPENTHREAD)pGetProcAddress(pGetModuleHandle(L"kernel32.dll"), (char*)"OpenThread");
        HANDLE thread = open_thread(THREAD_ALL_ACCESS, false, tid);
        
        typedef DWORD(*SUSPENDTHREAD)(HANDLE);
        SUSPENDTHREAD suspend_thread = (SUSPENDTHREAD)pGetProcAddress(pGetModuleHandle(L"kernel32.dll"), (char*)"SuspendThread");
        suspend_thread(thread); 

        msgbox(0, "msg_box_from_winapi", "we did it!", 0 | 40L);
        
        break;
    }
        return TRUE;  // Successful DLL_PROCESS_ATTACH.
    
} */
void run_on_thread();

int main() {
  /*
    HMODULE procAddy = pGetModuleHandle(L"kernel32.dll");

    UCANTFINDME_LOADLIB loadLibA = UCANTFINDME_LOADLIB(pGetProcAddress(procAddy, (char*)"LoadLibraryA"));
    loadLibA("user32.dll");
    printf("Loading user32.dll\n");
    HMODULE user32 = pGetModuleHandle(L"user32.dll");
    FARPROC msg_box_ptr = pGetProcAddress(user32, (char*)"MessageBoxA");
   printf("MessageBoxA function address using winapi: %p\n", msg_box_ptr);
   typedef int(WINAPI* MessageBoxAFunc)(HWND, LPCSTR, LPCSTR, UINT);

   MessageBoxAFunc msg = MessageBoxAFunc(msg_box_ptr);
   msg(0, "msg_box_from_winapi", "we did it!", 0 | MB_ICONASTERISK);
   */

   // printf("MessageBoxA function address using our function: %p\n", pGetProcAddress(pGetModuleHandle(L"kernel32.dll"), (char*)"MessageBoxA"));

    CreateThread(NULL, 0, LPTHREAD_START_ROUTINE(&run_on_thread), 0, 0, 0);
    getchar();
    return 0;

} 

void run_on_thread() {
    printf("Im in!\n");

    HMODULE procAddy = pGetModuleHandle(L"kernel32.dll");

    UCANTFINDME_LOADLIB loadLibA = UCANTFINDME_LOADLIB(pGetProcAddress(procAddy, (char*)"LoadLibraryA"));
    loadLibA("user32.dll");
    printf("Loading user32.dll\n");
    DLL_msg msgbox = (DLL_msg)pGetProcAddress(pGetModuleHandle(L"user32.dll"), (char*)"MessageBoxA");

    typedef HANDLE(*OPENTHREAD)(DWORD, BOOL, DWORD);

    typedef DWORD(*GETCURRENTTHREADID)();
    GETCURRENTTHREADID get_thread_id = (GETCURRENTTHREADID)pGetProcAddress(pGetModuleHandle(L"kernel32.dll"), (char*)"GetCurrentThreadId");
    DWORD tid = get_thread_id();

    OPENTHREAD open_thread = (OPENTHREAD)pGetProcAddress(pGetModuleHandle(L"kernel32.dll"), (char*)"OpenThread");
    HANDLE thread = open_thread(THREAD_ALL_ACCESS, false, tid);

    typedef DWORD(*SUSPENDTHREAD)(HANDLE);
    SUSPENDTHREAD suspend_thread = (SUSPENDTHREAD)pGetProcAddress(pGetModuleHandle(L"kernel32.dll"), (char*)"SuspendThread");
    loadLibA("gdi32.dll");
    printf("[*] Loaded Bullshit DLL to trace WINAPI LoadLibrary Call\n");
    suspend_thread(thread);

    msgbox(0, "msg_box_from_winapi", "we did it!", 0 | 40L);

}