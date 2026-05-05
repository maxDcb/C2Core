#pragma once

#if defined(BUILD_TEAMSERVER) || defined(C2CORE_BUILD_TESTS) || defined(C2CORE_BUILD_FUNCTIONAL_TESTS)

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <vector>

namespace inject_command
{
struct CommandOptions
{
    int pid = -1;
    bool hasPid = false;
    std::string generator = "raw";
    std::string sourceType = "raw";
    std::string sourcePath;
    std::string method;
    std::string arguments;
    std::string displayCommand;
    std::string error;
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

inline bool parsePidValue(const std::string& value, int& pid)
{
    try
    {
        size_t parsed = 0;
        const int parsedPid = std::stoi(value, &parsed);
        if (parsed != value.size())
            return false;
        pid = parsedPid;
        return true;
    }
    catch (...)
    {
        return false;
    }
}

inline bool setPid(CommandOptions& options, const std::string& value)
{
    int pid = -1;
    if (!parsePidValue(value, pid))
    {
        options.error = "Pid must be an integer.";
        return false;
    }
    options.pid = pid;
    options.hasPid = true;
    return true;
}

inline bool setSource(CommandOptions& options, const std::vector<std::string>& tokens, size_t& index, const std::string& token)
{
    if (++index >= tokens.size())
    {
        options.error = token + " requires a file path.";
        return false;
    }

    options.sourcePath = tokens[index];
    if (token == "--raw" || token == "-r")
    {
        options.generator = "raw";
        options.sourceType = "raw";
    }
    else if (token == "--donut-exe" || token == "-e")
    {
        options.generator = "donut";
        options.sourceType = "dotnet_exe";
    }
    else if (token == "--donut-dll" || token == "-d")
    {
        options.generator = "donut";
        options.sourceType = "dotnet_dll";
    }
    return true;
}

inline CommandOptions parseCommandOptions(const std::vector<std::string>& tokens)
{
    CommandOptions options;
    options.displayCommand = joinCommandTail(tokens, 1);

    for (size_t index = 1; index < tokens.size(); ++index)
    {
        const std::string& token = tokens[index];
        if (token == "--")
        {
            options.arguments = joinCommandTail(tokens, index + 1);
            break;
        }
        if (token == "--pid")
        {
            if (++index >= tokens.size())
            {
                options.error = "--pid requires a value.";
                return options;
            }
            if (!setPid(options, tokens[index]))
                return options;
        }
        else if (token == "--raw" || token == "-r")
        {
            if (!setSource(options, tokens, index, token))
                return options;
            if (token == "-r")
            {
                if (++index >= tokens.size())
                {
                    options.error = "Pid must be an integer.";
                    return options;
                }
                if (!setPid(options, tokens[index]))
                    return options;
            }
        }
        else if (token == "--donut-exe" || token == "-e")
        {
            if (!setSource(options, tokens, index, token))
                return options;
            if (token == "-e")
            {
                if (++index >= tokens.size())
                {
                    options.error = "Pid must be an integer.";
                    return options;
                }
                if (!setPid(options, tokens[index]))
                    return options;
                options.arguments = joinCommandTail(tokens, index + 1);
                break;
            }
        }
        else if (token == "--donut-dll" || token == "-d")
        {
            if (!setSource(options, tokens, index, token))
                return options;
            if (token == "-d")
            {
                if (++index >= tokens.size())
                {
                    options.error = "Pid must be an integer.";
                    return options;
                }
                if (!setPid(options, tokens[index]))
                    return options;
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
            int positionalPid = -1;
            if (!options.hasPid && parsePidValue(token, positionalPid))
            {
                options.pid = positionalPid;
                options.hasPid = true;
            }
            else
            {
                options.error = "Unknown inject option: " + token;
                return options;
            }
        }
    }

    if (options.sourcePath.empty())
    {
        options.error = "A payload source must be provided.";
        return options;
    }
    if (!options.hasPid)
    {
        options.error = "Pid must be an integer.";
        return options;
    }
    if (options.sourceType == "dotnet_dll" && options.method.empty())
    {
        options.error = "Method is mandatory for DLL.";
        return options;
    }
    return options;
}
} // namespace inject_command

#endif
