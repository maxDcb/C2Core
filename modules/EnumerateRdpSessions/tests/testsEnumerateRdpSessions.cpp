#include "../EnumerateRdpSessions.hpp"

#include <iostream>
#include <memory>
#include <vector>

int main()
{
    bool ok = true;

    std::unique_ptr<EnumerateRdpSessions> module = std::make_unique<EnumerateRdpSessions>();
    std::vector<std::string> cmd = {"enumerateRdpSessions", "-s", "rdp-host"};

    C2Message message;
    C2Message ret;

    ok &= module->init(cmd, message) == 0;
    ok &= message.instruction() == "enumerateRdpSessions";

    std::string packed = message.cmd();
    std::string server = packed.substr(0, packed.find('\0'));
    ok &= server == "rdp-host";

    module->process(message, ret);

#ifdef _WIN32
    ok &= ret.errorCode() == 0;
#else
    ok &= ret.errorCode() == EnumerateRdpSessions::ERROR_WINDOWS_ONLY;
    std::string err;
    module->errorCodeToMsg(ret, err);
    ok &= !err.empty();
#endif

    std::cout << (ok ? "[+] enumerateRdpSessions tests passed" : "[-] enumerateRdpSessions tests failed") << std::endl;
    return ok ? 0 : 1;
}
