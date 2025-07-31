#include "EnumerateShares.hpp"
#include "Common.hpp"

#include <cstring>
#ifdef _WIN32
#include <windows.h>
#include <lm.h>
#pragma comment(lib, "netapi32.lib")
#else
#include <samba-4.0/libsmbclient.h>
#endif

using namespace std;

constexpr std::string_view moduleName = "enumerateShares";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32
__declspec(dllexport) EnumerateShares* EnumerateSharesConstructor()
{
    return new EnumerateShares();
}
#else
__attribute__((visibility("default"))) EnumerateShares* EnumerateSharesConstructor()
{
    return new EnumerateShares();
}
#endif

EnumerateShares::EnumerateShares()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

EnumerateShares::~EnumerateShares()
{
}

std::string EnumerateShares::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "enumerateShares:\n";
    info += "List available SMB shares.\n";
#endif
    return info;
}

int EnumerateShares::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
    std::string host;
    if(splitedCmd.size() > 1)
        host = splitedCmd[1];
    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd(host);
    return 0;
}

int EnumerateShares::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string host = c2Message.cmd();
    std::string out = runEnum(host);
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(host);
    c2RetMessage.set_returnvalue(out);
    return 0;
}

std::string EnumerateShares::runEnum(const std::string& host)
{
#ifdef _WIN32
    std::string result;
    std::wstring wserver;
    if(!host.empty())
        wserver = L"\\\\" + std::wstring(host.begin(), host.end());
    LPBYTE buf = nullptr;
    DWORD read = 0, total = 0, resume = 0;
    NET_API_STATUS status = NetShareEnum(host.empty()? NULL : (LPWSTR)wserver.c_str(), 1, &buf, MAX_PREFERRED_LENGTH, &read, &total, &resume);
    if(status == NERR_Success || status == ERROR_MORE_DATA)
    {
        PSHARE_INFO_1 info = (PSHARE_INFO_1)buf;
        for(DWORD i=0; i<read; ++i)
        {
            char name[256] = {0};
            WideCharToMultiByte(CP_UTF8, 0, info[i].shi1_netname, -1, name, sizeof(name), NULL, NULL);
            result += name;
            if(info[i].shi1_remark)
            {
                char rem[256] = {0};
                WideCharToMultiByte(CP_UTF8, 0, info[i].shi1_remark, -1, rem, sizeof(rem), NULL, NULL);
                result += " - ";
                result += rem;
            }
            result += "\n";
        }
        NetApiBufferFree(buf);
    }
    if(result.empty())
        result = "Enumeration failed or no shares";
    return result;
#else
    std::string result;
    auto auth_fn = [](SMBCCTX*, const char*, const char*, char*, int, char* u, int ulen, char* p, int plen){ if(ulen>0) u[0]='\0'; if(plen>0) p[0]='\0'; };
    SMBCCTX* ctx = smbc_new_context();
    if(!ctx) return result;
    smbc_setOptionUseKerberos(ctx, 0);
    smbc_setOptionFallbackAfterKerberos(ctx, 1);
    smbc_setFunctionAuthDataWithContext(ctx, auth_fn);
    if(!smbc_init_context(ctx))
    {
        smbc_free_context(ctx, 1);
        return result;
    }
    smbc_set_context(ctx);
    std::string url = "smb://" + (host.empty()? std::string("") : host);
    int dir = smbc_opendir(url.c_str());
    if(dir >= 0)
    {
        struct smbc_dirent* ent;
        while((ent = smbc_readdir(dir)) != nullptr)
        {
            if(ent->smbc_type == SMBC_FILE_SHARE)
            {
                result += ent->name;
                result += '\n';
            }
        }
        smbc_closedir(dir);
    }
    smbc_free_context(ctx, 1);
    if(result.empty())
        result = "Enumeration failed or no shares";
    return result;
#endif
}

