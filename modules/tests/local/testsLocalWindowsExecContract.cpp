#include "MessageTestHelpers.hpp"
#include "../../DcomExec/DcomExec.hpp"
#include "../../PsExec/PsExec.hpp"
#include "../../SpawnAs/SpawnAs.hpp"

#include <iostream>
#include <string>

using test_helpers::roundTripMessage;

namespace
{
    template <typename Module>
    bool checkError(Module& executor, Module& receiver, const C2Message& prepared,
                    int expectedCode, const char* scenario)
    {
        C2Message request = roundTripMessage(prepared);
        C2Message rawResponse;
        executor.process(request, rawResponse);
        const C2Message response = roundTripMessage(rawResponse);
        C2Message codeOnly;
        codeOnly.set_errorCode(expectedCode);
        std::string message;
        receiver.errorCodeToMsg(codeOnly, message);
        const bool ok = response.errorCode() == expectedCode &&
            response.returnvalue().empty() && !message.empty() &&
            response.instruction() == request.instruction();
        if (!ok)
            std::cerr << scenario << ": code=" << response.errorCode() << " expected=" << expectedCode << " output=" << response.returnvalue().size() << " instruction=" << response.instruction() << " mapped=" << message << "\n";
        return ok;
    }

    template <typename Module>
    bool checkAllErrorCodes(Module& module, int maxCode, const char* scenario)
    {
        for (int code = 1; code <= maxCode; ++code)
        {
            C2Message codeOnly;
            codeOnly.set_errorCode(code);
            std::string rendered;
            module.errorCodeToMsg(codeOnly, rendered);
            if (rendered.empty())
            {
                std::cerr << scenario << ": no message for code " << code << '\n';
                return false;
            }
        }
        C2Message success;
        success.set_errorCode(0);
        std::string rendered = "stale";
        module.errorCodeToMsg(success, rendered);
        if (!rendered.empty())
            std::cerr << scenario << ": success left stale error text: " << rendered << '\n';
        return rendered.empty();
    }
}

int main()
{
    bool ok = true;
    {
        DcomExec preparer, executor, receiver;
        C2Message invalid;
        invalid.set_instruction("dcomExec");
        invalid.set_cmd("truncated");
        ok &= checkError(executor, receiver, invalid, 14, "DcomExec malformed");
        ok &= checkAllErrorCodes(receiver, 15, "DcomExec");
#ifndef _WIN32
        C2Message valid;
        std::vector<std::string> args = {"dcomExec", "-h", "example.invalid", "-c", "cmd.exe"};
        ok &= preparer.init(args, valid) == 0;
        ok &= checkError(executor, receiver, valid, 15, "DcomExec unsupported");
#endif
    }
    {
        PsExec executor, receiver;
        C2Message invalid;
        invalid.set_instruction("psExec");
        invalid.set_cmd("target");
        ok &= checkError(executor, receiver, invalid, 5, "PsExec empty payload");
        ok &= checkAllErrorCodes(receiver, 11, "PsExec");
#ifndef _WIN32
        C2Message valid;
        valid.set_instruction("psExec");
        valid.set_cmd("example.invalid");
        valid.set_data("service bytes");
        ok &= checkError(executor, receiver, valid, 11, "PsExec unsupported");
#endif
    }
    {
        SpawnAs executor, receiver;
        C2Message invalid;
        invalid.set_instruction("spawnAs");
        invalid.set_cmd("truncated");
        ok &= checkError(executor, receiver, invalid, 1, "SpawnAs malformed");
        C2Message noCommand;
        noCommand.set_instruction("spawnAs");
        noCommand.set_cmd(std::string("local\0user\0secret", 17));
        ok &= checkError(executor, receiver, noCommand, 2, "SpawnAs empty command");
        ok &= checkAllErrorCodes(receiver, 4, "SpawnAs");
#ifndef _WIN32
        noCommand.set_data("cmd.exe");
        ok &= checkError(executor, receiver, noCommand, 3, "SpawnAs unsupported");
#endif
    }
    return ok ? 0 : 1;
}
