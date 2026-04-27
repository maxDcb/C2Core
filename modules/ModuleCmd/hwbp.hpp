#pragma once

#if defined(_WIN32)

#if !defined(_M_IX86) && !defined(_M_X64) && !defined(_M_ARM64)
#error "hwbp supports only Windows x86/x64/ARM64 targets."
#endif


#include <windows.h>


#define STATUS_UNSUCCESSFUL 0xC0000001

// Breakpoint slot indices used by current callers.
#define NT_DEVICE_IO_CONTROL_FILE_INDEX 0
#define CREATE_FILE_INDEX               1

// hwbp related macros, simplify x64/x86 support

typedef LONG (CALLBACK* exception_callback)(PEXCEPTION_POINTERS);

#if defined(_M_ARM64)
    #define HWBP_MAX_BREAKPOINTS 2
    #define EXCEPTION_CODE(e) (e->ExceptionRecord->ExceptionCode)
    #define EXCEPTION_CURRENT_IP(e) ((PVOID)e->ContextRecord->Pc)
    #define EXCEPTION_SET_IP( e, p ) e->ContextRecord->Pc = (DWORD64)(p)
    #define EXCEPTION_SET_RET( e, r ) e->ContextRecord->X0 = (DWORD64)(r)
    #define EXCEPTION_RESUME( e ) ((void)0)
    #define EXCEPTION_GET_RET( e ) ((PVOID)e->ContextRecord->Lr)
    #define EXCEPTION_ADJ_STACK( e, i ) e->ContextRecord->Sp += (DWORD64)(i)
    #define EXCEPTION_ARG_1( e ) ( e->ContextRecord->X0 )
    #define EXCEPTION_ARG_2( e ) ( e->ContextRecord->X1 )
    #define EXCEPTION_BREAKPOINT_STEP 4

#elif defined(_M_X64)
    #define HWBP_MAX_BREAKPOINTS 4
    #define EXCEPTION_CODE(e) (e->ExceptionRecord->ExceptionCode)
    #define EXCEPTION_CURRENT_IP(e) ((PVOID)e->ContextRecord->Rip)
    #define EXCEPTION_SET_IP( e, p ) e->ContextRecord->Rip = (DWORD64)(p)
    #define EXCEPTION_SET_RET( e, r ) e->ContextRecord->Rax = (DWORD64)(r)
    #define EXCEPTION_RESUME( e ) e->ContextRecord->EFlags = ( 1 << 16 )
    #define EXCEPTION_GET_RET( e ) *( PVOID* ) ( e->ContextRecord->Rsp )
    #define EXCEPTION_ADJ_STACK( e, i ) e->ContextRecord->Rsp += i
    #define EXCEPTION_ARG_1( e ) ( e->ContextRecord->Rcx )
    #define EXCEPTION_ARG_2( e ) ( e->ContextRecord->Rdx )
    #define EXCEPTION_BREAKPOINT_STEP 1

#else
    #define HWBP_MAX_BREAKPOINTS 4
    #define EXCEPTION_CODE( e ) (e->ExceptionRecord->ExceptionCode)
    #define EXCEPTION_CURRENT_IP( e ) ((PVOID)e->ContextRecord->Eip)
    #define EXCEPTION_SET_IP( e, p ) e->ContextRecord->Eip = (DWORD)(ULONG_PTR)(p)
    #define EXCEPTION_SET_RET( e, r ) e->ContextRecord->Eax = (DWORD)(ULONG_PTR)(r)
    #define EXCEPTION_RESUME( e ) e->ContextRecord->EFlags = ( 1 << 16 )
    #define EXCEPTION_GET_RET( e ) *( PVOID* ) ( e->ContextRecord->Esp )
    #define EXCEPTION_ADJ_STACK( e, i ) e->ContextRecord->Esp += i
    #define EXCEPTION_ARG_1( e ) *(PVOID*)(e->ContextRecord->Esp + sizeof(PVOID))
    #define EXCEPTION_ARG_2( e ) *(PVOID*)(e->ContextRecord->Esp + sizeof(PVOID)*2)
    #define EXCEPTION_BREAKPOINT_STEP 1
#endif


ULONG_PTR set_bits(
    ULONG_PTR dw,
    int lowBit,
    int bits,
    ULONG_PTR newValue);


VOID clear_breakpoint(
    IN CONTEXT* ctx,
    IN DWORD index);


BOOL enable_breakpoint(
    OUT CONTEXT* ctx,
    IN PVOID address,
    IN int index);


BOOL set_hwbp(
    IN HANDLE hThread,
    IN PVOID address,
    IN exception_callback hwbp_handler,
    IN UINT32 index,
    OUT PHANDLE phHwBpHandler);


VOID unset_hwbp(
    IN HANDLE hThread,
    IN UINT32 index);


VOID remove_hwbp_handler(
    IN HANDLE hHwBpHandler);


#endif
