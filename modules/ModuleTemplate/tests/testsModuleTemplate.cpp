#include "../ModuleTemplate.hpp"

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif


bool testModuleTemplate();


int main()
{
    bool res;

    std::cout << "[+] testModuleTemplate" << std::endl;
    res = testModuleTemplate();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}


// test function
bool testModuleTemplate()
{

    std::unique_ptr<ModuleTemplate> moduleTemplate = std::make_unique<ModuleTemplate>();
    bool ok = true;

    // ----- correct argument -----
    {
        std::vector<std::string> cmd = {"moduleTemplate", "arg1"};
        C2Message msg, ret;
        moduleTemplate->init(cmd, msg);
        moduleTemplate->process(msg, ret);
        ok &= ret.returnvalue().find("return value") != std::string::npos;
    }

    // ----- wrong argument triggers error -----
    {
        std::vector<std::string> cmd = {"moduleTemplate", "notarg1"};
        C2Message msg, ret;
        moduleTemplate->init(cmd, msg);
        moduleTemplate->process(msg, ret);
        std::string err;
        moduleTemplate->errorCodeToMsg(ret, err);
#ifdef BUILD_TEAMSERVER
        ok &= ret.errorCode() == 1 && !err.empty();
#else
        ok &= ret.errorCode() == 1;
#endif
    }

    // ----- missing argument -----
    {
        std::vector<std::string> cmd = {"moduleTemplate"};
        C2Message msg, ret;
        ok &= moduleTemplate->init(cmd, msg) == -1;
        ok &= !msg.returnvalue().empty();
    }

    // ----- followUp path -----
    {
        C2Message ret;
        ret.set_errorCode(-1);
        ret.set_args("dummy");
        ok &= moduleTemplate->followUp(ret) == 0;
    }

    return ok;
}
