#pragma once

#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <vector>

namespace assembly_exec_command
{
struct CommandOptions
{
    std::string mode;
    std::string generator = "raw";
    std::string sourceType = "raw";
    std::string sourcePath;
    std::string method;
    std::string arguments;
    std::string displayCommand;
    std::string error;
    bool modeOnly = false;
};

inline std::string lowerCopy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

inline std::string joinCommandTail(const std::vector<std::string>& parts, size_t start)
{
    std::string result;
    for (size_t index = start; index < parts.size(); ++index)
    {
        if (!result.empty())
            result += " ";
        result += parts[index];
    }
    return result;
}

inline bool isModeName(const std::string& value)
{
    const std::string lowered = lowerCopy(value);
    return lowered == "thread" || lowered == "process" || lowered == "processwithspoofedparent";
}

inline std::string normalizeModeName(const std::string& value)
{
    const std::string lowered = lowerCopy(value);
    if (lowered == "thread")
        return "thread";
    if (lowered == "process")
        return "process";
    if (lowered == "processwithspoofedparent")
        return "processWithSpoofedParent";
    return "";
}

inline CommandOptions parseCommandOptions(const std::vector<std::string>& tokens)
{
    CommandOptions options;
    options.displayCommand = joinCommandTail(tokens, 1);

    if (tokens.size() == 2 && isModeName(tokens[1]))
    {
        options.mode = normalizeModeName(tokens[1]);
        options.modeOnly = true;
        return options;
    }

    for (size_t index = 1; index < tokens.size(); ++index)
    {
        const std::string& token = tokens[index];
        if (token == "--")
        {
            options.arguments = joinCommandTail(tokens, index + 1);
            break;
        }
        if (token == "--mode")
        {
            if (++index >= tokens.size())
            {
                options.error = "--mode requires a value.";
                return options;
            }
            options.mode = normalizeModeName(tokens[index]);
            if (options.mode.empty())
            {
                options.error = "Unsupported execution mode.";
                return options;
            }
        }
        else if (token == "--raw" || token == "-r")
        {
            if (++index >= tokens.size())
            {
                options.error = token + " requires a file path.";
                return options;
            }
            options.generator = "raw";
            options.sourceType = "raw";
            options.sourcePath = tokens[index];
        }
        else if (token == "--donut-exe" || token == "-e")
        {
            if (++index >= tokens.size())
            {
                options.error = token + " requires a file path.";
                return options;
            }
            options.generator = "donut";
            options.sourceType = "dotnet_exe";
            options.sourcePath = tokens[index];
            if (token == "-e")
            {
                options.arguments = joinCommandTail(tokens, index + 1);
                break;
            }
        }
        else if (token == "--donut-dll" || token == "-d")
        {
            if (++index >= tokens.size())
            {
                options.error = token + " requires a file path.";
                return options;
            }
            options.generator = "donut";
            options.sourceType = "dotnet_dll";
            options.sourcePath = tokens[index];
            if (token == "-d")
            {
                if (++index >= tokens.size())
                {
                    options.error = "Method is mandatory for DLL.";
                    return options;
                }
                options.method = tokens[index];
                options.arguments = joinCommandTail(tokens, index + 1);
                break;
            }
        }
        else if (token == "--method")
        {
            if (++index >= tokens.size())
            {
                options.error = "--method requires a value.";
                return options;
            }
            options.method = tokens[index];
        }
        else
        {
            options.error = "Unknown assemblyExec option: " + token;
            return options;
        }
    }

    if (options.sourcePath.empty())
    {
        options.error = "A payload source must be provided.";
        return options;
    }
    if (options.sourceType == "dotnet_dll" && options.method.empty())
    {
        options.error = "Method is mandatory for DLL.";
        return options;
    }
    return options;
}
} // namespace assembly_exec_command

#endif
