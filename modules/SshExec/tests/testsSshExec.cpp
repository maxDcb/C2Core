#include "../SshExec.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace
{
    bool expect(bool condition, const std::string& message)
    {
        if (!condition)
        {
            std::cerr << "[FAIL] " << message << std::endl;
            return false;
        }
        return true;
    }

    std::vector<std::string> splitPackedParameters(const std::string& packed)
    {
        std::vector<std::string> parts;
        size_t start = 0;
        while (start < packed.size())
        {
            size_t end = packed.find('\0', start);
            if (end == std::string::npos)
            {
                break;
            }
            parts.emplace_back(packed.substr(start, end - start));
            start = end + 1;
        }
        return parts;
    }

    bool testInitWithOptions()
    {
        SshExec module;
        C2Message message;
        std::vector<std::string> cmd = {
            "sshExec", "-h", "server.example", "-P", "2222", "-u", "alice", "-p", "secret", "-c", "whoami"
        };

        bool ok = expect(module.init(cmd, message) == 0, "init should accept explicit SSH options");
        ok &= expect(message.instruction() == "sshExec", "instruction should be set");

        std::vector<std::string> fields = splitPackedParameters(message.cmd());
        ok &= expect(fields.size() == 5, "packed SSH parameters should contain five fields");
        if (fields.size() == 5)
        {
            ok &= expect(fields[0] == "server.example", "host should be packed");
            ok &= expect(fields[1] == "2222", "port should be packed");
            ok &= expect(fields[2] == "alice", "username should be packed");
            ok &= expect(fields[3] == "secret", "password should be packed");
            ok &= expect(fields[4] == "whoami", "command should be packed");
        }
        return ok;
    }

    bool testInitWithPositionalArguments()
    {
        SshExec module;
        C2Message message;
        std::vector<std::string> cmd = {"sshExec", "server.local", "bob", "password", "whoami"};

        bool ok = expect(module.init(cmd, message) == 0, "init should accept positional SSH arguments");
        std::vector<std::string> fields = splitPackedParameters(message.cmd());
        ok &= expect(fields.size() == 5, "packed positional SSH parameters should contain five fields");
        if (fields.size() == 5)
        {
            ok &= expect(fields[0] == "server.local", "positional host should be packed");
            ok &= expect(fields[1] == "22", "default port should be packed");
            ok &= expect(fields[2] == "bob", "positional username should be packed");
            ok &= expect(fields[3] == "password", "positional password should be packed");
            ok &= expect(fields[4] == "whoami", "remaining positional token should form the command");
        }
        return ok;
    }

    bool testInitWithCommandTail()
    {
        SshExec module;
        C2Message message;
        std::vector<std::string> cmd = {"sshExec", "-h", "server.example", "-u", "alice", "-p", "secret", "--", "id", "-u"};

        bool ok = expect(module.init(cmd, message) == 0, "init should accept command tail after --");
        std::vector<std::string> fields = splitPackedParameters(message.cmd());
        ok &= expect(fields.size() == 5, "packed command-tail SSH parameters should contain five fields");
        if (fields.size() == 5)
        {
            ok &= expect(fields[4] == "id -u", "command tail should preserve command options");
        }
        return ok;
    }

    bool testMissingRequiredParameters()
    {
        SshExec module;
        C2Message message;
        std::vector<std::string> cmd = {"sshExec", "-h", "server.example", "-u", "alice", "-p", "secret"};

        bool ok = expect(module.init(cmd, message) == -1, "init should reject missing command");
        ok &= expect(
            message.returnvalue().find("Missing required parameters.") != std::string::npos,
            "missing parameters should explain the error"
        );
        return ok;
    }

    bool testProcessRejectsInvalidPackedParameters()
    {
        SshExec module;
        C2Message message;
        C2Message ret;

        message.set_instruction("sshExec");
        message.set_cmd("");

        bool ok = expect(module.process(message, ret) == 0, "process should return after local parameter validation");
        ok &= expect(ret.instruction() == "sshExec", "process should preserve instruction");
        ok &= expect(ret.errorCode() == SshExec::ErrorExecute, "invalid packed parameters should set ErrorExecute");
        ok &= expect(ret.returnvalue() == "Invalid parameters.", "invalid packed parameters should not reach SSH networking");

        std::string errorMsg;
        ok &= expect(module.errorCodeToMsg(ret, errorMsg) == 0, "errorCodeToMsg should return success");
        ok &= expect(errorMsg == "Invalid parameters.", "errorCodeToMsg should expose process error text");
        return ok;
    }
}

int main()
{
    bool ok = true;
    ok &= testInitWithOptions();
    ok &= testInitWithPositionalArguments();
    ok &= testInitWithCommandTail();
    ok &= testMissingRequiredParameters();
    ok &= testProcessRejectsInvalidPackedParameters();

    if (!ok)
    {
        return 1;
    }

    std::cout << "Finish" << std::endl;
    return 0;
}
