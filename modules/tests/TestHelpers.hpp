#pragma once

#include <cstdlib>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace test_helpers
{
    inline bool expect(bool condition, const std::string& message)
    {
        if (!condition)
        {
            std::cerr << "[FAIL] " << message << std::endl;
        }
        return condition;
    }

    inline std::vector<std::string> splitPackedFields(const std::string& packed)
    {
        std::vector<std::string> fields;
        size_t start = 0;
        while (start < packed.size())
        {
            const size_t end = packed.find('\0', start);
            if (end == std::string::npos)
            {
                fields.emplace_back(packed.substr(start));
                break;
            }
            fields.emplace_back(packed.substr(start, end - start));
            start = end + 1;
        }
        return fields;
    }

    inline bool hasEnvFlag(const char* name)
    {
        const char* value = std::getenv(name);
        return value != nullptr && value[0] != '\0' && std::string(value) != "0";
    }

    inline std::string envOr(const char* name, const std::string& fallback = "")
    {
        const char* value = std::getenv(name);
        return value != nullptr ? std::string(value) : fallback;
    }

    inline std::filesystem::path writeTempFile(const std::string& name, const std::string& content)
    {
        const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())
            + "_" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
        std::filesystem::path path = std::filesystem::temp_directory_path() / (name + "_" + suffix);
        std::ofstream out(path, std::ios::binary);
        out << content;
        return path;
    }
}
