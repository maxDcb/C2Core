#pragma once

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#if defined(_WIN32) && (defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS))
#include <chrono>
#include <cstring>

#include <donut.h>
#endif

namespace assembly_exec_tests
{
struct GeneratedShellcode
{
    bool ok = false;
    std::string error;
    std::filesystem::path path;
    std::string bytes;
};

#if defined(_WIN32) && (defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS))
inline int donutArch(const std::string& arch)
{
    if (arch == "x86")
        return DONUT_ARCH_X86;
    if (arch == "arm64")
        return DONUT_ARCH_ARM64;
    return DONUT_ARCH_X64;
}

inline bool copyBounded(char* destination, std::size_t destinationSize, const std::string& value)
{
    if (destinationSize == 0 || value.size() >= destinationSize)
        return false;
    std::memcpy(destination, value.c_str(), value.size());
    destination[value.size()] = '\0';
    return true;
}

inline std::filesystem::path tempShellcodePath()
{
    const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / ("c2-assemblyexec-test-" + std::to_string(suffix) + ".bin");
}

inline GeneratedShellcode generateDonutShellcodeForTest(
    const std::string& sourcePath,
    const std::string& method,
    const std::string& arguments,
    const std::string& arch,
    bool exitProcess)
{
    GeneratedShellcode result;
    result.path = tempShellcodePath();

    DONUT_CONFIG config;
    std::memset(&config, 0, sizeof(config));
    config.inst_type = DONUT_INSTANCE_EMBED;
    config.arch = donutArch(arch);
    config.bypass = DONUT_BYPASS_CONTINUE;
    config.format = DONUT_FORMAT_BINARY;
    config.compress = DONUT_COMPRESS_NONE;
    config.entropy = DONUT_ENTROPY_DEFAULT;
    config.headers = DONUT_HEADERS_OVERWRITE;
    config.exit_opt = exitProcess ? DONUT_OPT_EXIT_PROCESS : DONUT_OPT_EXIT_THREAD;
    config.thread = 0;
    config.unicode = 0;

    if (!copyBounded(config.input, sizeof(config.input), sourcePath)
        || !copyBounded(config.output, sizeof(config.output), result.path.string())
        || !copyBounded(config.method, sizeof(config.method), method)
        || !copyBounded(config.args, sizeof(config.args), arguments))
    {
        result.error = "Donut test input, output, method or arguments are too long.";
        return result;
    }

    const int err = DonutCreate(&config);
    if (err != DONUT_ERROR_OK)
    {
        result.error = "Donut test error: ";
        result.error += DonutError(err);
        return result;
    }

    std::ifstream input(result.path, std::ios::binary);
    result.bytes.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    DonutDelete(&config);

    if (result.bytes.empty())
    {
        result.error = "Donut test generated an empty shellcode payload.";
        return result;
    }

    result.ok = true;
    return result;
}
#else
inline GeneratedShellcode generateDonutShellcodeForTest(
    const std::string&,
    const std::string&,
    const std::string&,
    const std::string&,
    bool)
{
    GeneratedShellcode result;
    result.error = "Donut shellcode generation is only available in Windows assemblyExec tests.";
    return result;
}
#endif
} // namespace assembly_exec_tests
