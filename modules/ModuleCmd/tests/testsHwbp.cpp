#include <hwbp.hpp>

#include <iostream>

static volatile LONG gHwbpHits = 0;
static volatile LONG gUnexpectedExceptions = 0;
static volatile LONG gUnexpectedAddresses = 0;
static volatile LONG gUnexpectedArguments = 0;
static volatile LONG gTargetBodyExecutions = 0;

static void* gExpectedAddress = nullptr;
static ULONG_PTR gExpectedArgument = 0;
static ULONG_PTR gHookedReturnValue = 0;

extern "C" __declspec(noinline) int WINAPI TargetFunction(int value)
{
    InterlockedIncrement(&gTargetBodyExecutions);
    return value + 1;
}

LONG WINAPI hanlderToTrigger(EXCEPTION_POINTERS* ExceptionInfo)
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

    if ((ULONG_PTR)EXCEPTION_ARG_1(ExceptionInfo) != gExpectedArgument)
    {
        InterlockedIncrement(&gUnexpectedArguments);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    InterlockedIncrement(&gHwbpHits);
    EXCEPTION_SET_RET(ExceptionInfo, gHookedReturnValue);
    EXCEPTION_SET_IP(ExceptionInfo, EXCEPTION_GET_RET(ExceptionInfo));

#if !defined(_M_ARM64)
    EXCEPTION_ADJ_STACK(ExceptionInfo, sizeof(PVOID));
    EXCEPTION_RESUME(ExceptionInfo);
#endif

    return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
    constexpr int kExpectedArgument = 10;
    constexpr int kExpectedNormalReturn = kExpectedArgument + 1;
    constexpr int kHookedReturnValue = 1337;

    gExpectedAddress = (void*)&TargetFunction;
    gExpectedArgument = (ULONG_PTR)kExpectedArgument;
    gHookedReturnValue = (ULONG_PTR)kHookedReturnValue;

    InterlockedExchange(&gHwbpHits, 0);
    InterlockedExchange(&gUnexpectedExceptions, 0);
    InterlockedExchange(&gUnexpectedAddresses, 0);
    InterlockedExchange(&gUnexpectedArguments, 0);
    InterlockedExchange(&gTargetBodyExecutions, 0);

    const int indexHWBP = 0;
    HANDLE bp = nullptr;
    if (!set_hwbp(GetCurrentThread(), gExpectedAddress, hanlderToTrigger, indexHWBP, &bp))
    {
        std::cerr << "set_hwbp failed" << std::endl;
        return 1;
    }

    if (!bp)
    {
        std::cerr << "set_hwbp returned a null handler" << std::endl;
        return 1;
    }

    const int hookedResult1 = TargetFunction(kExpectedArgument);
    const int hookedResult2 = TargetFunction(kExpectedArgument);

    const LONG hitCount = InterlockedCompareExchange(&gHwbpHits, 0, 0);
    const LONG unexpectedExceptions = InterlockedCompareExchange(&gUnexpectedExceptions, 0, 0);
    const LONG unexpectedAddresses = InterlockedCompareExchange(&gUnexpectedAddresses, 0, 0);
    const LONG unexpectedArguments = InterlockedCompareExchange(&gUnexpectedArguments, 0, 0);
    const LONG targetBodyExecutions = InterlockedCompareExchange(&gTargetBodyExecutions, 0, 0);

    if (hookedResult1 != kHookedReturnValue || hookedResult2 != kHookedReturnValue)
    {
        std::cerr << "Hooked return values mismatch: " << hookedResult1 << ", " << hookedResult2 << std::endl;
        unset_hwbp(GetCurrentThread(), indexHWBP);
        remove_hwbp_handler(bp);
        return 1;
    }

    if (hitCount != 2)
    {
        std::cerr << "Expected 2 HWBP hits while armed, got " << hitCount << std::endl;
        unset_hwbp(GetCurrentThread(), indexHWBP);
        remove_hwbp_handler(bp);
        return 1;
    }

    if (targetBodyExecutions != 0)
    {
        std::cerr << "Target function body executed while breakpoint was armed: " << targetBodyExecutions << std::endl;
        unset_hwbp(GetCurrentThread(), indexHWBP);
        remove_hwbp_handler(bp);
        return 1;
    }

    if (unexpectedExceptions != 0 || unexpectedAddresses != 0 || unexpectedArguments != 0)
    {
        std::cerr << "Unexpected HWBP state: exceptions=" << unexpectedExceptions
                  << " addresses=" << unexpectedAddresses
                  << " arguments=" << unexpectedArguments << std::endl;
        unset_hwbp(GetCurrentThread(), indexHWBP);
        remove_hwbp_handler(bp);
        return 1;
    }

    unset_hwbp(GetCurrentThread(), indexHWBP);
    remove_hwbp_handler(bp);

    const int normalResult = TargetFunction(kExpectedArgument);
    const LONG hitCountAfterUnset = InterlockedCompareExchange(&gHwbpHits, 0, 0);
    const LONG targetBodyExecutionsAfterUnset = InterlockedCompareExchange(&gTargetBodyExecutions, 0, 0);

    if (normalResult != kExpectedNormalReturn)
    {
        std::cerr << "Normal return value mismatch after unset: " << normalResult << std::endl;
        return 1;
    }

    if (hitCountAfterUnset != hitCount)
    {
        std::cerr << "HWBP still triggered after unset/remove, count=" << hitCountAfterUnset << std::endl;
        return 1;
    }

    if (targetBodyExecutionsAfterUnset != 1)
    {
        std::cerr << "Target function body should execute exactly once after unset, got "
                  << targetBodyExecutionsAfterUnset << std::endl;
        return 1;
    }

    std::cout << "testsHwbp passed with " << hitCountAfterUnset << " expected hits" << std::endl;
    return 0;
}
