#include "../HostContext.hpp"

#include <memory>

int main()
{
    std::unique_ptr<HostContext> module(HostContextConstructor());
    if (!module || module->osCompatibility() != (OS_LINUX | OS_WINDOWS)) return 1;

    C2Message invalid;
    std::vector<std::string> empty;
    if (module->init(empty, invalid) != -1 || invalid.returnvalue() != "Usage: hostContext") return 2;
    std::vector<std::string> extra{"hostContext", "unexpected"};
    if (module->init(extra, invalid) != -1) return 3;

    C2Message failed;
    failed.set_errorCode(1);
    std::string error;
    module->errorCodeToMsg(failed, error);
    if (error != "Failed to collect host identity and OS information.") return 8;

    std::vector<std::string> command{"hostContext"};
    C2Message message, response;
    if (module->init(command, message) != 0 || message.instruction() != "hostContext"
            || module->process(message, response) != 0)
        return 4;
    if (response.instruction() != "hostContext" || response.errorCode() != 0) return 5;
    const std::string output = response.returnvalue();
    if (output.find("Hostname: ") == std::string::npos
        || output.find("Kernel: ") == std::string::npos
        || output.find("OS: ") == std::string::npos
        || output.find("Resolver configuration:\n") == std::string::npos
        || output.find("IPv4 routes:\n") == std::string::npos)
        return 6;
#ifdef _WIN32
    if (output.find("Kernel: Windows NT ") == std::string::npos
            || output.find("OS: Windows") == std::string::npos)
        return 7;
#else
    if (output.find("Kernel: Linux ") == std::string::npos) return 7;
#endif
    return 0;
}
