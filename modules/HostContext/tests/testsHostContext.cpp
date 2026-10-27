#include "../HostContext.hpp"

int main()
{
#ifdef _WIN32
    return 0;
#else
    HostContext module;
    std::vector<std::string> command{"hostContext"};
    C2Message message, response;
    if (module.init(command, message) != 0 || module.process(message, response) != 0)
        return 1;
    const std::string output = response.returnvalue();
    return output.find("Hostname: ") == std::string::npos
        || output.find("Kernel: Linux ") == std::string::npos
        || output.find("OS: ") == std::string::npos
        || output.find("Resolver configuration:\n") == std::string::npos
        || output.find("IPv4 routes:\n") == std::string::npos;
#endif
}
