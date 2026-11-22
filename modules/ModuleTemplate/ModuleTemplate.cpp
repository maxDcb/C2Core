#include "ModuleTemplate.hpp"

#include <cstdint>

namespace
{
    constexpr char moduleName[] = "moduleTemplate";
    constexpr std::size_t maxConfigurableBytes = 1024;
}

#ifdef _WIN32

__declspec(dllexport) ModuleTemplate* ModuleTemplateConstructor()
{
    return new ModuleTemplate();
}

#else

__attribute__((visibility("default"))) ModuleTemplate* ModuleTemplateConstructor()
{
    return new ModuleTemplate();
}

#endif

ModuleTemplate::ModuleTemplate() : ModuleCmd(moduleName)
{
}

std::string ModuleTemplate::getInfo()
{
#ifdef BUILD_TEAMSERVER
    return "Usage: moduleTemplate <text>\nCounts the bytes in the supplied text.";
#else
    return {};
#endif
}

int ModuleTemplate::osCompatibility()
{
    return OS_LINUX | OS_WINDOWS;
}

int ModuleTemplate::initConfig(const nlohmann::json& config)
{
    if (!config.is_object())
        return -1;

    const auto limit = config.find("max_bytes");
    if (limit == config.end())
    {
        maxBytes = defaultMaxBytes;
        return 0;
    }
    if (!limit->is_number_integer())
        return -1;

    const auto bytes = limit->get<std::uint64_t>();
    if (bytes == 0 || bytes > maxConfigurableBytes)
        return -1;

    maxBytes = static_cast<std::size_t>(bytes);
    return 0;
}

int ModuleTemplate::init(std::vector<std::string>& args, C2Message& request)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (args.size() != 2 || args.front() != moduleName || args[1].empty())
    {
        request.set_returnvalue(getInfo());
        return -1;
    }

    request.set_instruction(moduleName);
    request.set_data(args[1]);
#else
    (void)args;
    (void)request;
#endif
    return 0;
}

int ModuleTemplate::process(C2Message& request, C2Message& response)
{
    response.set_returnvalue({});
    if (request.instruction() != moduleName || request.data().empty())
    {
        response.set_errorCode(static_cast<int>(Status::InvalidRequest));
    }
    else if (request.data().size() > maxBytes)
    {
        response.set_errorCode(static_cast<int>(Status::LimitExceeded));
    }
    else
    {
        response.set_returnvalue(std::to_string(request.data().size()));
        response.set_errorCode(static_cast<int>(Status::Success));
    }
    return 0;
}

int ModuleTemplate::errorCodeToMsg(const C2Message& response, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
    switch (static_cast<Status>(response.errorCode()))
    {
        case Status::InvalidRequest:
            errorMsg = "Expected a moduleTemplate request with a nonempty sample.";
            break;
        case Status::LimitExceeded:
            errorMsg = "The sample exceeds the configured byte limit.";
            break;
        default:
            break;
    }
#else
    (void)response;
    (void)errorMsg;
#endif
    return 0;
}

int ModuleTemplate::followUp(const C2Message& response)
{
#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS)
    if (response.errorCode() == static_cast<int>(Status::Success) && !response.returnvalue().empty())
        lastResult = response.returnvalue();
#else
    (void)response;
#endif
    return 0;
}

int ModuleTemplate::recurringExec(C2Message& response)
{
    if (!pendingSample)
        return 0;

    response.set_returnvalue(std::to_string(*pendingSample));
    response.set_errorCode(static_cast<int>(Status::Success));
    pendingSample.reset();
    return 1;
}

const std::string& ModuleTemplate::lastResultForTest() const
{
    return lastResult;
}

void ModuleTemplate::recordSampleForTest(std::size_t byteCount)
{
    pendingSample = byteCount;
}
