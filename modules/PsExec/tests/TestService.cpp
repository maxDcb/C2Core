// TestService.cpp
#include <windows.h>
#include <string>
#include <thread>
#include <iostream>

SERVICE_STATUS        g_ServiceStatus = {};
SERVICE_STATUS_HANDLE g_StatusHandle  = nullptr;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;
std::wstring          g_CommandLine; // Command to execute

void ReportServiceStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint)
{
    static DWORD checkPoint = 1;

    g_ServiceStatus.dwCurrentState = currentState;
    g_ServiceStatus.dwWin32ExitCode = win32ExitCode;
    g_ServiceStatus.dwWaitHint = waitHint;
    g_ServiceStatus.dwCheckPoint = 
        (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) ? 0 : checkPoint++;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    switch (ctrlCode)
    {
        case SERVICE_CONTROL_STOP:
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
            SetEvent(g_ServiceStopEvent);
            ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
            break;
        default:
            break;
    }
}

void ExecuteCommand()
{
    if (!g_CommandLine.empty())
    {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        std::wstring cmd = L"cmd.exe /C " + g_CommandLine;

        if (CreateProcessW(
                nullptr,
                cmd.data(),
                nullptr,
                nullptr,
                FALSE,
                CREATE_NO_WINDOW,
                nullptr,
                nullptr,
                &si,
                &pi))
        {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
}

void WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
    g_StatusHandle = RegisterServiceCtrlHandlerW(L"TestService", ServiceCtrlHandler);
    if (!g_StatusHandle)
        return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    g_ServiceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!g_ServiceStopEvent)
    {
        ReportServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    // Execute provided command
    ExecuteCommand();

    // Wait until service is stopped
    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

int wmain(int argc, wchar_t* argv[])
{
    // If run interactively, act as test runner
    if (argc > 1 && wcscmp(argv[1], L"/test") == 0)
    {
        std::wstring cmd = (argc > 2) ? argv[2] : L"echo Hello > C:\\Temp\\svc_test.txt";
        g_CommandLine = cmd;
        ExecuteCommand();
        return 0;
    }

    if (argc > 1)
        g_CommandLine = argv[1];
    else
        g_CommandLine = L"echo Hello > C:\\Temp\\svc_test.txt";

    SERVICE_TABLE_ENTRYW ServiceTable[] =
    {
        { (LPWSTR)L"TestService", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
        { nullptr, nullptr }
    };

    StartServiceCtrlDispatcherW(ServiceTable);
    return 0;
}
