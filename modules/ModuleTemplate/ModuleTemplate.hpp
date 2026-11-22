#pragma once

#include "ModuleCmd.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

// In-memory example built into the local test executable.
class ModuleTemplate final : public ModuleCmd
{
public:
    ModuleTemplate();

    std::string getInfo() override;
    int osCompatibility() override;
    int initConfig(const nlohmann::json& config) override;
    int init(std::vector<std::string>& args, C2Message& request) override;
    int process(C2Message& request, C2Message& response) override;
    int errorCodeToMsg(const C2Message& response, std::string& errorMsg) override;
    int followUp(const C2Message& response) override;
    int recurringExec(C2Message& response) override;

    const std::string& lastResultForTest() const;
    void recordSampleForTest(std::size_t byteCount);

private:
    enum class Status : int
    {
        Success = 0,
        InvalidRequest = 1,
        LimitExceeded = 2
    };

    static constexpr std::size_t defaultMaxBytes = 64;
    std::size_t maxBytes = defaultMaxBytes;
    std::string lastResult;
    std::optional<std::size_t> pendingSample;
};

#ifdef _WIN32

extern "C" __declspec(dllexport) ModuleTemplate * ModuleTemplateConstructor();

#else

extern "C"  __attribute__((visibility("default"))) ModuleTemplate * ModuleTemplateConstructor();

#endif
