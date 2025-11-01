#include <iostream>
#include <memory>
#include <vector>
#include <string>

#include "../SpawnAs.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif


int main()
{
    // Test 1 : launchAsUserW
    // CreateProcessAsUserW - calling process has the right privileges; this is the most “native”/powerful path
    // Privileges needed on the caller: SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege (and often SeImpersonatePrivilege).
    // Pros: works great from services / SYSTEM; full control over profile & environment.
    // --logon-type 2 --with-profile
    {
        std::unique_ptr<SpawnAs> module = std::make_unique<SpawnAs>();
        std::vector<std::string> cmd = {
            "spawnAs",          // nom / token d'appel (optionnel selon ton parser)
            "root", "root",     // user + password
            "--",               // séparation options / commande
            "cmd.exe", "/c", "echo test1 > C:\\Users\\root\\Desktop\\test1.txt"
        };

        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << "[Test1] returnvalue:\n" << ret.returnvalue() << std::endl;
        std::cerr  << "[Test1] error: " << err << std::endl;
    }

    // Test 2 : launchWithTokenW
    // CreateProcessWithTokenW - caller lacks SeAssignPrimaryToken/SeIncreaseQuota, but has SeImpersonatePrivilege (typical for admins).
    // Privileges needed on the caller: mainly SeImpersonatePrivilege. 
    // Pros: often succeeds where CPAsUserW fails due to missing privileges.
    // --logon-type 2 --no-profile
    {
        std::unique_ptr<SpawnAs> module = std::make_unique<SpawnAs>();
        std::vector<std::string> cmd = {
            "spawnAs",         
            "--no-profile",
            "root", "root",
            "--",
            "cmd.exe", "/c", "echo test2 > C:\\Users\\root\\Desktop\\test2.txt"
        };

        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << "[Test2] returnvalue:\n" << ret.returnvalue() << std::endl;
        std::cerr  << "[Test2] error: " << err << std::endl;
    }

    // Test 2 : launchWithLogonW
    // CreateProcessWithLogonW - last resort; works from an interactive context where services/privileges are limited.
    // it’s not supported for services; it’s designed for interactive callers.
    // Pros: simplest API surface (credentials in, process out).
    // --logon-type 9
    {
        std::unique_ptr<SpawnAs> module = std::make_unique<SpawnAs>();
        std::vector<std::string> cmd = {
            "spawnAs",
            "-d", ".",                 // override domain (here local .)
            "-l", "9",                 // logon-type 9 = LOGON32_LOGON_NEW_CREDENTIALS (netonly)
            "root", "root",
            "--",
            "cmd.exe", "/c", "echo test3 > C:\\Users\\root\\Desktop\\test3.txt"
        };

        C2Message message;
        C2Message ret;

        module->init(cmd, message);
        module->process(message, ret);

        std::string err;
        module->errorCodeToMsg(ret, err);

        std::cout << "[Test3] returnvalue:\n" << ret.returnvalue() << std::endl;
        std::cerr  << "[Test3] error: " << err << std::endl;
    }


    return 0;
}