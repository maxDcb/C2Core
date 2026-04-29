#include "../Registry.hpp"
#include "../../tests/TestHelpers.hpp"

#include <iostream>
#include <vector>

using namespace test_helpers;

int main()
{
    bool ok = true;

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "set", "-h", "HKCU", "-k", "Software\\C2CoreTest", "-n", "Path", "-d", "C:/Temp", "-t", "REG_SZ"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == 0, "registry set should be accepted");
        ok &= expect(message.instruction() == "registry", "instruction should be set");
        ok &= expect(!message.cmd().empty(), "registry parameters should be packed");
        const std::string packedFields = message.cmd().substr(1);
        const auto fields = splitPackedFields(packedFields);
        ok &= expect(fields.size() == 6, "packed registry parameters should contain six string fields");
        if (fields.size() == 6)
        {
            ok &= expect(fields[1] == "HKCU", "hive should be packed");
            ok &= expect(fields[2] == "Software\\C2CoreTest", "subkey should be packed");
            ok &= expect(fields[3] == "Path", "value name should be packed");
            ok &= expect(fields[4] == "C:/Temp", "value data should be packed");
            ok &= expect(fields[5] == "REG_SZ", "value type should be packed");
        }
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "query", "-h", "HKCU", "-k", "Software\\C2CoreTest"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "query without value name should be rejected");
        ok &= expect(!message.returnvalue().empty(), "query without value name should explain the error");
    }

    {
        Registry module;
        std::vector<std::string> cmd = {"registry", "unknown"};
        C2Message message;

        ok &= expect(module.init(cmd, message) == -1, "unknown operation should be rejected");
        ok &= expect(!message.returnvalue().empty(), "unknown operation should explain the error");
    }

    {
        Registry module;
        C2Message ret;
        ret.set_errorCode(3);
        ret.set_returnvalue("open failed");
        std::string error;

        ok &= expect(module.errorCodeToMsg(ret, error) == 0, "errorCodeToMsg should return success");
        ok &= expect(error == "open failed", "errorCodeToMsg should expose process error text");
    }

    return ok ? 0 : 1;
}
