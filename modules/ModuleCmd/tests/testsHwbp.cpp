#include <peb.hpp>
#include <hwbp.hpp>

#include <iostream>


LONG WINAPI hanlderToTrigger(EXCEPTION_POINTERS * ExceptionInfo) 
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) 
    {
        BYTE* baseAddress = (BYTE*)xGetProcAddress(xGetLibAddress((PCHAR)"Kernel32", TRUE, NULL), (PCHAR)"GetProcessVersion", 0);
        if (EXCEPTION_CURRENT_IP(ExceptionInfo) == baseAddress) 
        {            
            std::cout << "Hello from GetProcessVersion " << std::endl;
            EXCEPTION_SET_IP(ExceptionInfo, baseAddress + EXCEPTION_BREAKPOINT_STEP);
        }        
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


int main()
{

    void* baseAddress = (void*)xGetProcAddress(xGetLibAddress((PCHAR)"Kernel32.dll", TRUE, NULL), (PCHAR)"GetProcessVersion", 0);

    std::cout << "baseAddress " << baseAddress << std::endl;

    int indexHWBP = 0;
    HANDLE bp;
    set_hwbp(GetCurrentThread(), baseAddress, hanlderToTrigger, indexHWBP, &bp);

    std::cout << "bp " << bp << std::endl;

    std::cout << "GetProcessVersion with bp " << std::endl;

    GetProcessVersion(-1);

    std::cout << "unset_hwbp " << std::endl;

    unset_hwbp(GetCurrentThread(), indexHWBP);

    std::cout << "remove_hwbp_handler " << std::endl;
    
    remove_hwbp_handler(bp);

    std::cout << "GetProcessVersion without bp " << std::endl;

    GetProcessVersion(-1);

    std::cout << "End " << std::endl;

    return 0;
}

