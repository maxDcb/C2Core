#include "Whoami.hpp"
#include "Common.hpp"

#include <cstring>
#include <sstream>
#ifdef _WIN32
#include <sddl.h>
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <pwd.h>
#include <unistd.h>
#include <grp.h>
#endif

using namespace std;

constexpr std::string_view moduleName = "whoami";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32
__declspec(dllexport) Whoami* WhoamiConstructor()
{
    return new Whoami();
}
#else
__attribute__((visibility("default"))) Whoami* WhoamiConstructor()
{
    return new Whoami();
}
#endif

Whoami::Whoami()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleName), moduleHash)
#else
    : ModuleCmd("", moduleHash)
#endif
{
}

Whoami::~Whoami()
{
}

std::string Whoami::getInfo()
{
    std::string info;
#ifdef BUILD_TEAMSERVER
    info += "whoami:\n";
    info += "Print current user information.\n";
#endif
    return info;
}

int Whoami::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
    c2Message.set_instruction(splitedCmd[0]);
    return 0;
}

int Whoami::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    std::string out = getInfoString();
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_returnvalue(out);
    return 0;
}

std::string Whoami::getInfoString()
{
    std::string result;
#ifdef _WIN32
    char name[256];
    DWORD size = sizeof(name);
    if(GetUserNameA(name, &size))
    {
        result += "User: ";
        result += name;
        result += "\n";
    }

    HANDLE token = NULL;
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        DWORD len = 0;
        GetTokenInformation(token, TokenGroups, nullptr, 0, &len);
        std::vector<BYTE> buf(len);
        if(GetTokenInformation(token, TokenGroups, buf.data(), len, &len))
        {
            PTOKEN_GROUPS groups = reinterpret_cast<PTOKEN_GROUPS>(buf.data());
            result += "Groups:\n";
            for(DWORD i = 0; i < groups->GroupCount; ++i)
            {
                char gname[256];
                char gdomain[256];
                DWORD gnlen = sizeof(gname);
                DWORD gdlen = sizeof(gdomain);
                SID_NAME_USE use;
                if(LookupAccountSidA(NULL, groups->Groups[i].Sid, gname, &gnlen, gdomain, &gdlen, &use))
                {
                    if(gdlen)
                    {
                        result += " - ";
                        result += gdomain;
                        result += "\\";
                        result += gname;
                    }
                    else
                    {
                        result += " - ";
                        result += gname;
                    }
                }
                else
                {
                    LPSTR sidStr = nullptr;
                    if(ConvertSidToStringSidA(groups->Groups[i].Sid, &sidStr))
                    {
                        result += " - ";
                        result += sidStr;
                        LocalFree(sidStr);
                    }
                }
                result += "\n";
            }
        }
        CloseHandle(token);
    }
#else
    struct passwd* pw = getpwuid(geteuid());
    if(pw)
    {
        result += "User: ";
        result += pw->pw_name;
        result += "\nUID: ";
        result += std::to_string(pw->pw_uid);
        result += " GID: ";
        result += std::to_string(pw->pw_gid);
        result += "\n";
    }
    int ngroups = getgroups(0, nullptr);
    if(ngroups > 0)
    {
        std::vector<gid_t> groups(ngroups);
        getgroups(ngroups, groups.data());
        result += "Groups: ";
        for(int i=0;i<ngroups;i++)
        {
            struct group* gr = getgrgid(groups[i]);
            if(gr)
                result += gr->gr_name;
            else
                result += std::to_string(groups[i]);
            if(i+1<ngroups)
                result += ", ";
        }
        result += "\n";
    }
#endif
    if(result.empty())
        result = "No information";
    return result;
}

