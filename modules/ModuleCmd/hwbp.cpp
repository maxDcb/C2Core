
#include "hwbp.hpp"
#include "peb.hpp"


#if _WIN32


ULONG_PTR set_bits(
    IN ULONG_PTR dw,
    IN int lowBit,
    IN int bits,
    IN ULONG_PTR newValue)
{
    ULONG_PTR mask = (1UL << bits) - 1UL;
    dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
    return dw;
}


BOOL enable_breakpoint(
    OUT CONTEXT* ctx,
    IN PVOID address,
    IN int index)
{
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

    ctx->Dr7 = set_bits(ctx->Dr7, 16, 16, 0);
    ctx->Dr7 = set_bits(ctx->Dr7, (index * 2), 1, 1);

    return TRUE;
}


typedef PVOID (WINAPI * RtlAddVectoredExceptionHandler_t)( 
ULONG First,
exception_callback Handler
);


typedef PVOID (WINAPI * RtlRemoveVectoredExceptionHandler_t)( 
PVOID Handle
);


VOID clear_breakpoint(
    IN CONTEXT* ctx,
    IN DWORD index)
{
    // Clear the releveant hardware breakpoint
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
    }

    ctx->Dr7 = set_bits(ctx->Dr7, (index * 2), 1, 0);
    ctx->Dr6 = 0;
    ctx->EFlags = 0;
}


BOOL set_hwbp(
    IN HANDLE hThread,
    IN PVOID address,
    IN exception_callback hwbp_handler,
    IN UINT32 index,
    OUT PHANDLE phHwBpHandler)
{
    BOOL     ret_val      = FALSE;
    NTSTATUS status       = STATUS_UNSUCCESSFUL;
    HANDLE   hHwBpHandler = NULL;
    CONTEXT  threadCtx    = { 0 };

    memset(&threadCtx, 0, sizeof(threadCtx));
    threadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    RtlAddVectoredExceptionHandler_t RtlAddVectoredExceptionHandler = (RtlAddVectoredExceptionHandler_t)xGetProcAddress(xGetLibAddress((PCHAR)"ntdll", TRUE, NULL), (PCHAR)"RtlAddVectoredExceptionHandler", 0);
    if (!RtlAddVectoredExceptionHandler)
    {
        goto Cleanup;
    }

    hHwBpHandler = RtlAddVectoredExceptionHandler(1, hwbp_handler);
    if (!hHwBpHandler)
    {
        goto Cleanup;
    }

    status = GetThreadContext(hThread, &threadCtx);
    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    if (!enable_breakpoint(&threadCtx, address, index))
        goto Cleanup;

    status = SetThreadContext (hThread, &threadCtx);
    if (!NT_SUCCESS(status))
    {
        goto Cleanup;
    }

    if (phHwBpHandler)
        *phHwBpHandler = hHwBpHandler;

    ret_val = TRUE;

Cleanup:
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
    NTSTATUS status    = STATUS_UNSUCCESSFUL;
    CONTEXT  threadCtx = { 0 };

    memset(&threadCtx, 0, sizeof(threadCtx));
    threadCtx.ContextFlags = CONTEXT_ALL;

    status = GetThreadContext(hThread, &threadCtx);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    clear_breakpoint(&threadCtx, index);

    status = SetThreadContext (hThread, &threadCtx);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

cleanup:
    return;
}


#endif