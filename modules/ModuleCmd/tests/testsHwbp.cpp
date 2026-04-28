#include <peb.hpp>
#include <hwbp.hpp>

#include <iostream>

static volatile LONG gHwbpHits = 0;
static volatile LONG gUnexpectedExceptions = 0;
static volatile LONG gUnexpectedAddresses = 0;
static void* gExpectedAddress = nullptr;

LONG WINAPI hanlderToTrigger(EXCEPTION_POINTERS * ExceptionInfo) 
{
    if (EXCEPTION_CODE(ExceptionInfo) != HWBP_EXCEPTION_CODE)
    {
        InterlockedIncrement(&gUnexpectedExceptions);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (!EXCEPTION_HIT_ADDRESS(ExceptionInfo, gExpectedAddress))
    {
        InterlockedIncrement(&gUnexpectedAddresses);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    InterlockedIncrement(&gHwbpHits);
    EXCEPTION_SET_IP(ExceptionInfo, (BYTE*)gExpectedAddress + EXCEPTION_BREAKPOINT_STEP);
    return EXCEPTION_CONTINUE_EXECUTION;
}


int main()
{
    void* baseAddress = (void*)xGetProcAddress(xGetLibAddress((PCHAR)"Kernel32.dll", TRUE, NULL), (PCHAR)"GetProcessVersion", 0);
    if (!baseAddress)
    {
        std::cerr << "Failed to resolve GetProcessVersion" << std::endl;
        return 1;
    }

    gExpectedAddress = baseAddress;
    InterlockedExchange(&gHwbpHits, 0);
    InterlockedExchange(&gUnexpectedExceptions, 0);
    InterlockedExchange(&gUnexpectedAddresses, 0);

    int indexHWBP = 0;
    HANDLE bp = nullptr;
    if (!set_hwbp(GetCurrentThread(), baseAddress, hanlderToTrigger, indexHWBP, &bp))
    {
        std::cerr << "set_hwbp failed" << std::endl;
        return 1;
    }

    if (!bp)
    {
        std::cerr << "set_hwbp returned a null handler" << std::endl;
        return 1;
    }

    GetProcessVersion(-1);
    GetProcessVersion(-1);

    LONG hitCount = InterlockedCompareExchange(&gHwbpHits, 0, 0);
    LONG unexpectedExceptions = InterlockedCompareExchange(&gUnexpectedExceptions, 0, 0);
    LONG unexpectedAddresses = InterlockedCompareExchange(&gUnexpectedAddresses, 0, 0);

    if (hitCount != 2)
    {
        std::cerr << "Expected 2 HWBP hits while armed, got " << hitCount << std::endl;
        unset_hwbp(GetCurrentThread(), indexHWBP);
        remove_hwbp_handler(bp);
        return 1;
    }

    if (unexpectedExceptions != 0 || unexpectedAddresses != 0)
    {
        std::cerr << "Unexpected HWBP state: exceptions=" << unexpectedExceptions
                  << " addresses=" << unexpectedAddresses << std::endl;
        unset_hwbp(GetCurrentThread(), indexHWBP);
        remove_hwbp_handler(bp);
        return 1;
    }

    unset_hwbp(GetCurrentThread(), indexHWBP);
    remove_hwbp_handler(bp);

    GetProcessVersion(-1);
    GetProcessVersion(-1);

    LONG hitCountAfterUnset = InterlockedCompareExchange(&gHwbpHits, 0, 0);
    if (hitCountAfterUnset != hitCount)
    {
        std::cerr << "HWBP still triggered after unset/remove, count=" << hitCountAfterUnset << std::endl;
        return 1;
    }

    std::cout << "testsHwbp passed with " << hitCountAfterUnset << " expected hits" << std::endl;

    return 0;
}

