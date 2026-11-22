#include "../Registry.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <string>
#include <vector>

using namespace test_helpers;

namespace
{
struct PackedRegistry
{
    Registry::Operation operation = Registry::Operation::SetValue;
    std::vector<std::string> fields;
};

PackedRegistry unpackPackedRegistry(const C2Message& message)
{
    PackedRegistry packed;
    if (!message.cmd().empty())
    {
        packed.operation = static_cast<Registry::Operation>(static_cast<unsigned char>(message.cmd()[0]));
        packed.fields = splitPackedFields(message.cmd().substr(1));
    }
    return packed;
}

bool expectPackedRegistry(const C2Message& message,
                          Registry::Operation expectedOperation,
                          const std::string& expectedServer,
                          const std::string& expectedHive,
                          const std::string& expectedSubKey,
                          const std::string& expectedValueName,
                          const std::string& expectedValueData,
                          const std::string& expectedValueType,
                          const std::string& label)
{
    const auto packed = unpackPackedRegistry(message);
    bool ok = true;
    ok &= expect(message.instruction() == "registry", label + ": instruction should be set");
    ok &= expect(!message.cmd().empty(), label + ": registry parameters should be packed");
    ok &= expect(packed.operation == expectedOperation, label + ": operation should be packed");
    ok &= expect(packed.fields.size() == 6, label + ": packed registry parameters should contain six string fields");
    if (packed.fields.size() == 6)
    {
        ok &= expect(packed.fields[0] == expectedServer, label + ": server should be packed");
        ok &= expect(packed.fields[1] == expectedHive, label + ": hive should be packed");
        ok &= expect(packed.fields[2] == expectedSubKey, label + ": subkey should be packed");
        ok &= expect(packed.fields[3] == expectedValueName, label + ": value name should be packed");
        ok &= expect(packed.fields[4] == expectedValueData, label + ": value data should be packed");
        ok &= expect(packed.fields[5] == expectedValueType, label + ": value type should be packed");
    }
    return ok;
}

bool expectContains(const std::string& text, const std::string& needle, const std::string& label)
{
    return expect(text.find(needle) != std::string::npos, label);
}
}

int main()
{
    bool ok = true;

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "set", "-s", "server01", "-h", "HKCU", "-k", "Software\\C2CoreTest", "-n", "Path", "-d", "C:/Temp", "-t", "REG_SZ"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "registry set should be accepted");
        ok &= expectPackedRegistry(message,
                                   Registry::Operation::SetValue,
                                   "server01",
                                   "HKCU",
                                   "Software\\C2CoreTest",
                                   "Path",
                                   "C:/Temp",
                                   "REG_SZ",
                                   "set operation");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "set", "-h", "HKCU", "-k", "Software\\C2CoreTest", "-n", "Count", "-d", "42", "-t", "REG_DWORD"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "registry set DWORD should be accepted");
        ok &= expectPackedRegistry(message,
                                   Registry::Operation::SetValue,
                                   "",
                                   "HKCU",
                                   "Software\\C2CoreTest",
                                   "Count",
                                   "42",
                                   "REG_DWORD",
                                   "set DWORD operation");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "query", "-h", "HKLM", "-k", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "-n", "ProductName"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "registry query should be accepted");
        ok &= expectPackedRegistry(message,
                                   Registry::Operation::QueryValue,
                                   "",
                                   "HKLM",
                                   "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                   "ProductName",
                                   "",
                                   "REG_SZ",
                                   "query operation");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "get", "-h", "HKLM", "-k", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "-n", "ProductName"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "registry get alias should be accepted");
        ok &= expect(unpackPackedRegistry(message).operation == Registry::Operation::QueryValue, "get alias should pack query operation");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "deleteValue", "-h", "HKCU", "-k", "Software\\C2CoreTest", "-n", "Path"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "registry deleteValue should be accepted");
        ok &= expectPackedRegistry(message,
                                   Registry::Operation::DeleteValue,
                                   "",
                                   "HKCU",
                                   "Software\\C2CoreTest",
                                   "Path",
                                   "",
                                   "REG_SZ",
                                   "deleteValue operation");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "delete", "-h", "HKCU", "-k", "Software\\C2CoreTest", "-n", "Path"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "registry delete alias should be accepted");
        ok &= expect(unpackPackedRegistry(message).operation == Registry::Operation::DeleteValue, "delete alias should pack deleteValue operation");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "createKey", "-h", "HKCU", "-k", "Software\\C2CoreTest"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "registry createKey should be accepted");
        ok &= expectPackedRegistry(message,
                                   Registry::Operation::CreateKey,
                                   "",
                                   "HKCU",
                                   "Software\\C2CoreTest",
                                   "",
                                   "",
                                   "REG_SZ",
                                   "createKey operation");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "create", "-h", "HKCU", "-k", "Software\\C2CoreTest"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "registry create alias should be accepted");
        ok &= expect(unpackPackedRegistry(message).operation == Registry::Operation::CreateKey, "create alias should pack createKey operation");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "deleteKey", "-h", "HKCU", "-k", "Software\\C2CoreTest"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "registry deleteKey should be accepted");
        ok &= expectPackedRegistry(message,
                                   Registry::Operation::DeleteKey,
                                   "",
                                   "HKCU",
                                   "Software\\C2CoreTest",
                                   "",
                                   "",
                                   "REG_SZ",
                                   "deleteKey operation");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "delkey", "-h", "HKCU", "-k", "Software\\C2CoreTest"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "registry delkey alias should be accepted");
        ok &= expect(unpackPackedRegistry(message).operation == Registry::Operation::DeleteKey, "delkey alias should pack deleteKey operation");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "query", "-h", "HKCU", "-k", "Software\\C2CoreTest"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "query without value name should be rejected");
        ok &= expectContains(message.returnvalue(), "Value name required", "query without value name should explain the error");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "set", "-h", "HKCU", "-n", "Path", "-d", "C:/Temp"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "missing subkey should be rejected");
        ok &= expectContains(message.returnvalue(), "Missing required hive or subkey", "missing subkey should explain the error");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "unknown"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "unknown operation should be rejected");
        ok &= expectContains(message.returnvalue(), "Unknown operation", "unknown operation should explain the error");
    }

    {
        Registry module;
        C2Message message;
        message.set_instruction("registry");
        message.set_cmd(std::string(1, static_cast<char>(Registry::Operation::QueryValue)));
        C2Message ret;

        ok &= expect(module.process(message, ret) == 0, "malformed packed command should return normally");
        ok &= expect(ret.instruction() == "registry", "malformed packed command should preserve instruction");
#ifdef _WIN32
        ok &= expect(ret.errorCode() == 1, "malformed packed command should fail with invalid root on Windows");
        ok &= expect(ret.returnvalue().empty(), "malformed packed command should not carry error text");
#else
        ok &= expect(ret.errorCode() == 9 && ret.returnvalue().empty(),
            "Linux should return a code-only unsupported response");
#endif
    }

#ifdef _WIN32
    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "query", "-h", "HKLM", "-k", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "-n", "ProductName"};
        C2Message message;
        C2Message ret;

        ok &= expect(module.init(cmd, message) == 0, "read-only registry query should initialize");
        ok &= expect(module.process(message, ret) == 0, "read-only registry query should process");
        ok &= expect(ret.errorCode() == 0, "read-only registry query should set code zero");
        ok &= expectContains(ret.returnvalue(), "Type:", "read-only registry query should return a type");
        ok &= expectContains(ret.returnvalue(), "Data:", "read-only registry query should return data");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "query", "-h", "HKCU", "-k", "Software\\C2CoreDefinitelyMissingReadOnlyKey", "-n", "Value"};
        C2Message message;
        C2Message ret;
        std::string error;

        ok &= expect(module.init(cmd, message) == 0, "missing key query should initialize");
        ok &= expect(module.process(message, ret) == 0, "missing key query should process");
        ok &= expect(ret.errorCode() == 3, "missing key query should report open-key error");
        ok &= expect(ret.returnvalue().empty(), "missing key query should not carry error text");
        ok &= expect(module.errorCodeToMsg(ret, error) == 0, "errorCodeToMsg should return success");
        ok &= expect(error == "Could not open registry key.",
            "errorCodeToMsg should translate the received code");
    }
#endif

    {
        Registry module;
        C2Message ret;
        ret.set_errorCode(3);
        std::string error;

        ok &= expect(module.errorCodeToMsg(ret, error) == 0, "errorCodeToMsg should return success");
        ok &= expect(error == "Could not open registry key.",
            "errorCodeToMsg should work with only the code");
    }

    return ok ? 0 : 1;
}
