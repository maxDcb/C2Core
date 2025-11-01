#include "Registry.hpp"

#include "Common.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#pragma comment(lib, "advapi32.lib")
#endif

using namespace std;

constexpr std::string_view moduleNameRegistry = "registry";
constexpr unsigned long long moduleHashRegistry = djb2(moduleNameRegistry);

#ifdef _WIN32
extern "C" __declspec(dllexport) Registry* RegistryConstructor()
{
    return new Registry();
}
#else
extern "C" __attribute__((visibility("default"))) Registry* RegistryConstructor()
{
    return new Registry();
}
#endif

Registry::Registry()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleNameRegistry), moduleHashRegistry)
#else
    : ModuleCmd("", moduleHashRegistry)
#endif
{
}

Registry::~Registry() = default;

std::string Registry::getInfo()
{
    std::ostringstream oss;
#ifdef BUILD_TEAMSERVER
    oss << "Registry Module:\n";
    oss << "Manipulate local or remote Windows registry keys." << '\n';
    oss << "Usage:" << '\n';
    oss << "  registry <operation> [options]\n";
    oss << "Operations:" << '\n';
    oss << "  set           Create or update a value." << '\n';
    oss << "  deleteValue   Delete an existing value." << '\n';
    oss << "  query         Query the value data." << '\n';
    oss << "  createKey     Create a key." << '\n';
    oss << "  deleteKey     Delete a key recursively." << '\n';
    oss << "Options:" << '\n';
    oss << "  -s <server>           Remote host (omit for localhost)." << '\n';
    oss << "  -h <hive>             Root hive (HKLM, HKCU, HKU, HKCR, HKCC)." << '\n';
    oss << "  -k <subKey>           Sub key path." << '\n';
    oss << "  -n <valueName>        Value name (required for value operations)." << '\n';
    oss << "  -d <data>             Data for set (default empty)." << '\n';
    oss << "  -t <type>             Value type for set (REG_SZ, REG_DWORD, REG_QWORD, REG_EXPAND_SZ)." << '\n';
    oss << "Example:" << '\n';
    oss << "  registry set -h HKLM -k Software\\Acme -n Path -d C:/Temp -t REG_SZ" << '\n';
#endif
    return oss.str();
}

std::string Registry::packParameters(const Parameters& params) const
{
    std::string packed;
    packed.push_back(static_cast<char>(params.operation));

    auto append = [&packed](const std::string& value)
    {
        packed.append(value);
        packed.push_back('\0');
    };

    append(params.server);
    append(params.rootKey);
    append(params.subKey);
    append(params.valueName);
    append(params.valueData);
    append(params.valueType);
    return packed;
}

Registry::Parameters Registry::unpackParameters(const std::string& data) const
{
    Parameters params;
    if (data.empty())
    {
        return params;
    }

    params.operation = static_cast<Operation>(static_cast<unsigned char>(data[0]));

    size_t start = 1;
    std::vector<std::string> parts;
    while (start < data.size())
    {
        size_t end = data.find('\0', start);
        if (end == std::string::npos)
        {
            break;
        }
        parts.emplace_back(data.substr(start, end - start));
        start = end + 1;
    }

    if (parts.size() >= 6)
    {
        params.server = parts[0];
        params.rootKey = parts[1];
        params.subKey = parts[2];
        params.valueName = parts[3];
        params.valueData = parts[4];
        params.valueType = parts[5];
    }

    return params;
}

#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)

namespace
{
    Registry::Operation operationFromString(const std::string& op, bool& valid)
    {
        std::string lower = op;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower == "set")
        {
            valid = true;
            return Registry::Operation::SetValue;
        }
        if (lower == "deletevalue" || lower == "delete" || lower == "delvalue")
        {
            valid = true;
            return Registry::Operation::DeleteValue;
        }
        if (lower == "query" || lower == "get")
        {
            valid = true;
            return Registry::Operation::QueryValue;
        }
        if (lower == "createkey" || lower == "create")
        {
            valid = true;
            return Registry::Operation::CreateKey;
        }
        if (lower == "deletekey" || lower == "delkey")
        {
            valid = true;
            return Registry::Operation::DeleteKey;
        }
        valid = false;
        return Registry::Operation::SetValue;
    }
}

#endif

int Registry::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    std::vector<std::string> args = regroupStrings(splitedCmd);
    if (args.size() < 2)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    Parameters params;
    bool operationValid = false;
    params.operation = operationFromString(args[1], operationValid);
    if (!operationValid)
    {
        c2Message.set_returnvalue("Unknown operation '" + args[1] + "'.\n" + getInfo());
        return -1;
    }
    params.valueType = "REG_SZ";

    for (size_t i = 2; i < args.size(); ++i)
    {
        const std::string& token = args[i];
        if (token == "-s" && i + 1 < args.size())
        {
            params.server = args[++i];
        }
        else if (token == "-h" && i + 1 < args.size())
        {
            params.rootKey = args[++i];
        }
        else if (token == "-k" && i + 1 < args.size())
        {
            params.subKey = args[++i];
        }
        else if (token == "-n" && i + 1 < args.size())
        {
            params.valueName = args[++i];
        }
        else if (token == "-d" && i + 1 < args.size())
        {
            params.valueData = args[++i];
        }
        else if (token == "-t" && i + 1 < args.size())
        {
            params.valueType = args[++i];
        }
    }

    if (params.rootKey.empty() || params.subKey.empty())
    {
        c2Message.set_returnvalue("Missing required hive or subkey.\n" + getInfo());
        return -1;
    }

    if ((params.operation == Operation::SetValue || params.operation == Operation::DeleteValue || params.operation == Operation::QueryValue) && params.valueName.empty())
    {
        c2Message.set_returnvalue("Value name required for this operation.\n" + getInfo());
        return -1;
    }

    if (params.operation == Operation::SetValue && params.valueData.empty())
    {
        params.valueData = "";
    }

    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd(packParameters(params));
#endif
    return 0;
}

int Registry::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());

    Parameters params = unpackParameters(c2Message.cmd());

    int error = 0;
    std::string result;

#ifdef _WIN32
    error = execute(params, result);
#else
    result = "Only supported on Windows.\n";
#endif

    if (error)
    {
        c2RetMessage.set_errorCode(error);
    }

    c2RetMessage.set_returnvalue(result);
    return 0;
}

#define ERROR_INVALID_ROOT 1
#define ERROR_CONNECT 2
#define ERROR_OPEN_KEY 3
#define ERROR_SET_VALUE 4
#define ERROR_DELETE_VALUE 5
#define ERROR_QUERY_VALUE 6
#define ERROR_CREATE_KEY 7
#define ERROR_DELETE_KEY 8

int Registry::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    if (c2RetMessage.errorCode() > 0)
    {
        errorMsg = c2RetMessage.returnvalue();
    }
#endif
    return 0;
}

#ifdef _WIN32
namespace
{
    std::wstring toWide(const std::string& input)
    {
        if (input.empty())
        {
            return std::wstring();
        }
        int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0);
        std::wstring wide(sizeNeeded, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), wide.data(), sizeNeeded);
        return wide;
    }

    std::string formatWinError(LONG error)
    {
        LPVOID buffer = nullptr;
        DWORD size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPSTR>(&buffer),
            0,
            nullptr);
        std::string message;
        if (size && buffer)
        {
            message.assign(static_cast<const char*>(buffer), size);
            LocalFree(buffer);
        }
        else
        {
            message = "Error code: " + std::to_string(error);
        }
        return message;
    }

    HKEY resolveRoot(const std::string& root)
    {
        std::string upper = root;
        std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        if (upper == "HKLM" || upper == "HKEY_LOCAL_MACHINE")
            return HKEY_LOCAL_MACHINE;
        if (upper == "HKCU" || upper == "HKEY_CURRENT_USER")
            return HKEY_CURRENT_USER;
        if (upper == "HKCR" || upper == "HKEY_CLASSES_ROOT")
            return HKEY_CLASSES_ROOT;
        if (upper == "HKU" || upper == "HKEY_USERS")
            return HKEY_USERS;
        if (upper == "HKCC" || upper == "HKEY_CURRENT_CONFIG")
            return HKEY_CURRENT_CONFIG;
        return nullptr;
    }

    DWORD resolveValueType(const std::string& type)
    {
        std::string upper = type;
        std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        if (upper == "REG_DWORD")
            return REG_DWORD;
        if (upper == "REG_QWORD")
            return REG_QWORD;
        if (upper == "REG_EXPAND_SZ")
            return REG_EXPAND_SZ;
        return REG_SZ;
    }
}


int Registry::execute(const Parameters& params, std::string& result) const
{
    HKEY root = resolveRoot(params.rootKey);
    if (!root)
    {
        result = "Unknown root hive.";
        return ERROR_INVALID_ROOT;
    }

    HKEY baseHandle = root;
    HKEY connectedHandle = nullptr;
    if (!params.server.empty())
    {
        LONG status = RegConnectRegistryW(toWide(params.server).c_str(), root, &connectedHandle);
        if (status != ERROR_SUCCESS)
        {
            result = formatWinError(status);
            return ERROR_CONNECT;
        }
        baseHandle = connectedHandle;
    }

    auto closeHandles = [&]()
    {
        if (connectedHandle)
        {
            RegCloseKey(connectedHandle);
        }
    };

    auto openOrCreateKey = [&](REGSAM access, HKEY& keyHandle, bool create)
    {
        LONG status;
        if (create)
        {
            status = RegCreateKeyExW(baseHandle, toWide(params.subKey).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, access, nullptr, &keyHandle, nullptr);
        }
        else
        {
            status = RegOpenKeyExW(baseHandle, toWide(params.subKey).c_str(), 0, access, &keyHandle);
        }
        return status;
    };

    LONG status = ERROR_SUCCESS;
    switch (params.operation)
    {
    case Operation::SetValue:
    {
        HKEY keyHandle = nullptr;
        status = openOrCreateKey(KEY_SET_VALUE, keyHandle, true);
        if (status != ERROR_SUCCESS)
        {
            result = formatWinError(status);
            closeHandles();
            return ERROR_OPEN_KEY;
        }

        DWORD type = resolveValueType(params.valueType);
        std::vector<unsigned char> buffer;
        try
        {
            if (type == REG_DWORD)
            {
                DWORD value = static_cast<DWORD>(std::stoul(params.valueData.empty() ? "0" : params.valueData));
                buffer.resize(sizeof(DWORD));
                std::memcpy(buffer.data(), &value, sizeof(DWORD));
            }
            else if (type == REG_QWORD)
            {
                unsigned long long value = std::stoull(params.valueData.empty() ? "0" : params.valueData);
                buffer.resize(sizeof(unsigned long long));
                std::memcpy(buffer.data(), &value, sizeof(unsigned long long));
            }
            else
            {
                std::wstring wideData = toWide(params.valueData);
                buffer.resize((wideData.size() + 1) * sizeof(wchar_t));
                std::memcpy(buffer.data(), wideData.c_str(), buffer.size());
            }
        }
        catch (const std::exception&)
        {
            RegCloseKey(keyHandle);
            result = "Failed to parse numeric registry data.";
            closeHandles();
            return ERROR_SET_VALUE;
        }

        status = RegSetValueExW(keyHandle, toWide(params.valueName).c_str(), 0, type, buffer.empty() ? nullptr : buffer.data(), static_cast<DWORD>(buffer.size()));
        RegCloseKey(keyHandle);
        if (status != ERROR_SUCCESS)
        {
            result = formatWinError(status);
            closeHandles();
            return ERROR_SET_VALUE;
        }

        result = "Value set successfully.\n";
        break;
    }
    case Operation::DeleteValue:
    {
        HKEY keyHandle = nullptr;
        status = openOrCreateKey(KEY_SET_VALUE, keyHandle, false);
        if (status != ERROR_SUCCESS)
        {
            result = formatWinError(status);
            closeHandles();
            return ERROR_OPEN_KEY;
        }

        status = RegDeleteValueW(keyHandle, toWide(params.valueName).c_str());
        RegCloseKey(keyHandle);
        if (status != ERROR_SUCCESS)
        {
            result = formatWinError(status);
            closeHandles();
            return ERROR_DELETE_VALUE;
        }

        result = "Value deleted successfully.\n";
        break;
    }
    case Operation::QueryValue:
    {
        HKEY keyHandle = nullptr;
        status = openOrCreateKey(KEY_QUERY_VALUE, keyHandle, false);
        if (status != ERROR_SUCCESS)
        {
            result = formatWinError(status);
            closeHandles();
            return ERROR_OPEN_KEY;
        }

        DWORD type = 0;
        DWORD dataSize = 0;
        status = RegQueryValueExW(keyHandle, toWide(params.valueName).c_str(), nullptr, &type, nullptr, &dataSize);
        if (status != ERROR_SUCCESS)
        {
            RegCloseKey(keyHandle);
            result = formatWinError(status);
            closeHandles();
            return ERROR_QUERY_VALUE;
        }

        std::vector<unsigned char> buffer(dataSize ? dataSize : 1);
        status = RegQueryValueExW(keyHandle, toWide(params.valueName).c_str(), nullptr, &type, buffer.data(), &dataSize);
        RegCloseKey(keyHandle);
        if (status != ERROR_SUCCESS)
        {
            result = formatWinError(status);
            closeHandles();
            return ERROR_QUERY_VALUE;
        }

        std::ostringstream oss;
        oss << "Type: " << type << "\n";
        if (type == REG_DWORD && dataSize >= sizeof(DWORD))
        {
            DWORD value = 0;
            std::memcpy(&value, buffer.data(), sizeof(DWORD));
            oss << "Data: " << value << "\n";
        }
        else if (type == REG_QWORD && dataSize >= sizeof(unsigned long long))
        {
            unsigned long long value = 0;
            std::memcpy(&value, buffer.data(), sizeof(unsigned long long));
            oss << "Data: " << value << "\n";
        }
        else
        {
            std::wstring wide(reinterpret_cast<wchar_t*>(buffer.data()), dataSize / sizeof(wchar_t));
            if (!wide.empty() && wide.back() == L'\0')
            {
                wide.pop_back();
            }
            oss << "Data: ";
            int length = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
            std::string utf8;
            if (length > 0)
            {
                utf8.resize(length);
                WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), utf8.data(), length, nullptr, nullptr);
            }
            oss << utf8 << "\n";
        }
        result = oss.str();
        break;
    }
    case Operation::CreateKey:
    {
        HKEY keyHandle = nullptr;
        status = openOrCreateKey(KEY_CREATE_SUB_KEY, keyHandle, true);
        if (status != ERROR_SUCCESS)
        {
            result = formatWinError(status);
            closeHandles();
            return ERROR_CREATE_KEY;
        }
        RegCloseKey(keyHandle);
        result = "Key created successfully.\n";
        break;
    }
    case Operation::DeleteKey:
    {
        status = RegDeleteTreeW(baseHandle, toWide(params.subKey).c_str());
        if (status != ERROR_SUCCESS)
        {
            result = formatWinError(status);
            closeHandles();
            return ERROR_DELETE_KEY;
        }
        result = "Key deleted successfully.\n";
        break;
    }
    default:
        result = "Unsupported operation.";
        closeHandles();
        return ERROR_INVALID_ROOT;
    }

    closeHandles();
    return 0;
}
#endif
