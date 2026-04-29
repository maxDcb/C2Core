
#include "hwbp.hpp"
#include "peb.hpp"


#if defined(_WIN32)

namespace
{
    constexpr int ULONG_PTR_BITS = static_cast<int>(sizeof(ULONG_PTR) * 8);

    constexpr DWORD DR7_ENABLE_SHIFT = 0;
    constexpr DWORD DR7_ENABLE_STRIDE = 2;
    constexpr DWORD DR7_ENABLE_BITS = 2;
    constexpr DWORD DR7_LOCAL_ENABLE = 1;
    constexpr DWORD DR7_RW_LEN_SHIFT = 16;
    constexpr DWORD DR7_RW_LEN_STRIDE = 4;
    constexpr DWORD DR7_RW_LEN_BITS = 4;

    bool is_valid_breakpoint_index(UINT32 index)
    {
        return index < HWBP_MAX_BREAKPOINTS;
    }

#if defined(_M_ARM64)
    constexpr DWORD ARM64_BCR_ENABLE_SHIFT = 0;
    constexpr DWORD ARM64_BCR_PMC_SHIFT    = 1;
    constexpr DWORD ARM64_BCR_BAS_SHIFT    = 5;

    constexpr DWORD ARM64_BCR_ENABLE = 0x1;
    constexpr DWORD ARM64_BCR_PMC_EL0 = 0x2;
    constexpr DWORD ARM64_BCR_BAS_A64 = 0xF;
#endif
}


ULONG_PTR set_bits(
    IN ULONG_PTR dw,
    IN int lowBit,
    IN int bits,
    IN ULONG_PTR newValue)
{
    if (lowBit < 0 || bits <= 0 || lowBit >= ULONG_PTR_BITS)
        return dw;

    if (bits > ULONG_PTR_BITS - lowBit)
        bits = ULONG_PTR_BITS - lowBit;

    ULONG_PTR mask = (bits == ULONG_PTR_BITS) ? ~static_cast<ULONG_PTR>(0) : ((static_cast<ULONG_PTR>(1) << bits) - 1);
    dw = (dw & ~(mask << lowBit)) | ((newValue & mask) << lowBit);
    return dw;
}


BOOL enable_breakpoint(
    OUT CONTEXT* ctx,
    IN PVOID address,
    IN int index)
{
    if (!ctx || index < 0 || !is_valid_breakpoint_index(static_cast<UINT32>(index)))
        return FALSE;

#if defined(_M_ARM64)
    ctx->Bvr[index] = ((DWORD64)address) & ~0x3ull;
    ctx->Bcr[index] = 0;
    ctx->Bcr[index] = (DWORD)set_bits(ctx->Bcr[index], ARM64_BCR_ENABLE_SHIFT, 1, ARM64_BCR_ENABLE);
    ctx->Bcr[index] = (DWORD)set_bits(ctx->Bcr[index], ARM64_BCR_PMC_SHIFT, 2, ARM64_BCR_PMC_EL0);
    ctx->Bcr[index] = (DWORD)set_bits(ctx->Bcr[index], ARM64_BCR_BAS_SHIFT, 4, ARM64_BCR_BAS_A64);

    return TRUE;
#else
    switch (index)
    {
        case 0:
            ctx->Dr0 = (ULONG_PTR)address;
            break;
        case 1:
            ctx->Dr1 = (ULONG_PTR)address;
            break;
        case 2:
            ctx->Dr2 = (ULONG_PTR)address;
            break;
        case 3:
            ctx->Dr3 = (ULONG_PTR)address;
            break;
        default:
            return FALSE;
    }

    ctx->Dr7 = set_bits(ctx->Dr7, DR7_RW_LEN_SHIFT + (index * DR7_RW_LEN_STRIDE), DR7_RW_LEN_BITS, 0);
    ctx->Dr7 = set_bits(ctx->Dr7, DR7_ENABLE_SHIFT + (index * DR7_ENABLE_STRIDE), DR7_ENABLE_BITS, DR7_LOCAL_ENABLE);

    return TRUE;
#endif
}


typedef PVOID (WINAPI * RtlAddVectoredExceptionHandler_t)( 
ULONG First,
exception_callback Handler
);


typedef ULONG (WINAPI * RtlRemoveVectoredExceptionHandler_t)(
PVOID Handle
);


VOID clear_breakpoint(
    IN CONTEXT* ctx,
    IN DWORD index)
{
    if (!ctx || !is_valid_breakpoint_index(index))
        return;

#if defined(_M_ARM64)
    ctx->Bcr[index] = 0;
    ctx->Bvr[index] = 0;
#else
    // Clear the relevant hardware breakpoint
    switch (index)
    {
        case 0:
            ctx->Dr0 = 0;
            break;
        case 1:
            ctx->Dr1 = 0;
            break;
        case 2:
            ctx->Dr2 = 0;
            break;
        case 3:
            ctx->Dr3 = 0;
            break;
        default:
            return;
    }

    ctx->Dr7 = set_bits(ctx->Dr7, DR7_ENABLE_SHIFT + (index * DR7_ENABLE_STRIDE), DR7_ENABLE_BITS, 0);
    ctx->Dr7 = set_bits(ctx->Dr7, DR7_RW_LEN_SHIFT + (index * DR7_RW_LEN_STRIDE), DR7_RW_LEN_BITS, 0);
    ctx->Dr6 = 0;
#endif
}


BOOL set_hwbp(
    IN HANDLE hThread,
    IN PVOID address,
    IN exception_callback hwbp_handler,
    IN UINT32 index,
    OUT PHANDLE phHwBpHandler)
{
    BOOL     ret_val      = FALSE;
    HANDLE   hHwBpHandler = NULL;
    CONTEXT  threadCtx    = { 0 };
    RtlAddVectoredExceptionHandler_t RtlAddVectoredExceptionHandler = NULL;

    if (phHwBpHandler)
        *phHwBpHandler = NULL;

    if (!hThread || !address || !hwbp_handler || !is_valid_breakpoint_index(index))
    {
        goto Cleanup;
    }

    memset(&threadCtx, 0, sizeof(threadCtx));
    threadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    RtlAddVectoredExceptionHandler = (RtlAddVectoredExceptionHandler_t)xGetProcAddress(xGetLibAddress((PCHAR)"ntdll", TRUE, NULL), (PCHAR)"RtlAddVectoredExceptionHandler", 0);
    if (!RtlAddVectoredExceptionHandler)
    {
        goto Cleanup;
    }

    hHwBpHandler = RtlAddVectoredExceptionHandler(1, hwbp_handler);
    if (!hHwBpHandler)
    {
        goto Cleanup;
    }

    if (!GetThreadContext(hThread, &threadCtx))
    {
        goto Cleanup;
    }

    if (!enable_breakpoint(&threadCtx, address, index))
        goto Cleanup;

    if (!SetThreadContext(hThread, &threadCtx))
    {
        goto Cleanup;
    }

    if (phHwBpHandler)
        *phHwBpHandler = hHwBpHandler;

    ret_val = TRUE;

Cleanup:
    if (!ret_val && hHwBpHandler)
    {
        remove_hwbp_handler(hHwBpHandler);
    }

    return ret_val;
}


VOID remove_hwbp_handler(
    IN HANDLE hHwBpHandler)
{
    if (!hHwBpHandler)
        return;

    RtlRemoveVectoredExceptionHandler_t RtlRemoveVectoredExceptionHandler = (RtlRemoveVectoredExceptionHandler_t)xGetProcAddress(xGetLibAddress((PCHAR)"ntdll", TRUE, NULL), (PCHAR)"RtlRemoveVectoredExceptionHandler", 0);
    if (!RtlRemoveVectoredExceptionHandler)
    {
        return;
    }

    if (!RtlRemoveVectoredExceptionHandler(hHwBpHandler))
    {
        return;
    }
}


VOID unset_hwbp(
    IN HANDLE hThread,
    IN UINT32 index)
{
    CONTEXT  threadCtx = { 0 };

    if (!hThread || !is_valid_breakpoint_index(index))
        return;

    memset(&threadCtx, 0, sizeof(threadCtx));
    threadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(hThread, &threadCtx))
    {
        goto cleanup;
    }

    clear_breakpoint(&threadCtx, index);

    if (!SetThreadContext(hThread, &threadCtx))
    {
        goto cleanup;
    }

cleanup:
    return;
}


#endif
