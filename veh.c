#include <Windows.h>
#include <stdio.h>

// compile: cl veh.c -o veh.exe
// This uses VEH to act as a hook and get function addresses

// By Sleepy :)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

volatile DWORD_PTR address = 0;

LONG CALLBACK code2Run(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        DWORD_PTR faultAddr = (DWORD_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress;
        printf("[VEH] Function called at [%p]\n", faultAddr);

        //ExceptionInfo->ContextRecord->Rip += 1; // Skip faulting instruction
        VirtualProtect((LPVOID)faultAddr, 16, PAGE_EXECUTE_READ | PAGE_GUARD, NULL);

        return EXCEPTION_CONTINUE_EXECUTION;
}

return EXCEPTION_CONTINUE_EXECUTION;
}

int main() {

   // Read DOS header
    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)GetModuleHandle("KERNEL32.DLL");
    if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid PE file\n");
        return FALSE;
    }

    // Read NT headers
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
       printf("Invalid NT headers\n");
        return FALSE;
    }


    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {

        SIZE_T rawSize = section->SizeOfRawData;

            if (strcmp(section->Name, ".data") == 0 || strcmp(section->Name, ".text") == 0) {
    
                printf("Mapped section: %.*s\n", 8, section->Name);

                    if (memcmp(section->Name, ".text", 5) == 0) {

                         // address is global
                         address = dh + section->VirtualAddress;
                      
                         HANDLE vHandler = AddVectoredExceptionHandler(1, code2Run);
                      
                         // printf("size %lu\n", section->Misc.VirtualSize);

                         // setting the .text section as PAGE_EXECUTE_READ | PAGE_GUARD so it hits out vHandler
                         DWORD oldProtect;
                         if (!VirtualProtect(((DWORD_PTR)dh + section->VirtualAddress), section->Misc.VirtualSize, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtect)) {
                            printf("error %lu\n", GetLastError());
                            return 0;
                            }

                         // idk a test? remove from final injector
                         FlushInstructionCache(GetCurrentProcess(), (LPCVOID)address, sizeof(FARPROC));

                         // test call 
                         Beep(800, 200);


                         RemoveVectoredExceptionHandler(vHandler);

                        typedef NTSTATUS (NTAPI* pNtTerminateProcess)(HANDLE, NTSTATUS);

                        pNtTerminateProcess NtTerminateProcess = (pNtTerminateProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtTerminateProcess");
                        if (!NtTerminateProcess) return FALSE;
                        NTSTATUS status = NtTerminateProcess(NULL, 0);
                        if (NT_SUCCESS(status)) {
                        printf("See ya!\n");
                        printf("\a");
                        } else {
                        printf("NTSTATUS: 0x%08X - Error killing\n", status);
                        }   
                        NtTerminateProcess(NULL, 0);

           
                        return 0;

}
}




return 0;
}
}
