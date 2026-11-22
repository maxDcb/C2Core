#include "../ModuleTemplate.hpp"
#include "../../tests/TestHelpers.hpp"
#include "../../tests/local/MessageTestHelpers.hpp"

#include <string>
#include <vector>

namespace
{
    using test_helpers::expect;
    using test_helpers::roundTripMessage;

    bool testRequestLifecycle()
    {
        ModuleTemplate preparer;
        ModuleTemplate executor;
        ModuleTemplate receiver;
        ModuleCmd& receivingModule = receiver;

        bool ok = expect(preparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
            "the example declares Linux and Windows support");

        std::vector<std::string> args{"moduleTemplate"};
        C2Message rejected;
        ok &= expect(preparer.init(args, rejected) == -1 && rejected.returnvalue() == preparer.getInfo(),
            "init rejects missing arguments and returns usage");

        const std::string sample("a\0b", 3);
        args.push_back(sample);
        C2Message prepared;
        if (!expect(preparer.init(args, prepared) == 0, "init accepts a nonempty sample"))
            return false;

        C2Message request = roundTripMessage(prepared);
        ok &= expect(request.instruction() == "moduleTemplate" && request.data() == sample,
            "init prepares the instruction and exact sample bytes");

        ok &= expect(executor.initConfig({{"max_bytes", 3}}) == 0, "initConfig accepts a byte limit");
        C2Message result;
        result.set_uuid("local-example");
        executor.process(request, result);
        const C2Message response = roundTripMessage(result);
        ok &= expect(response.errorCode() == 0 && response.returnvalue() == "3",
            "process returns a byte count and sets success on the response");
        ok &= expect(response.uuid() == "local-example", "process preserves caller-owned message fields");

        std::string error;
        receivingModule.errorCodeToMsg(response, error);
        ok &= expect(error.empty(), "errorCodeToMsg produces no error text on success");
        receivingModule.followUp(response);
        ok &= expect(receiver.lastResultForTest() == "3", "followUp records success on a separate instance");

        ok &= expect(executor.initConfig({{"max_bytes", 2}}) == 0, "the executor can set a lower limit");
        for (const auto& invalid : {nlohmann::json(-1), nlohmann::json(0), nlohmann::json(1025), nlohmann::json("2")})
        {
            ok &= expect(executor.initConfig({{"max_bytes", invalid}}) == -1,
                "initConfig rejects invalid limits");
        }

        executor.process(request, result);
        const C2Message limitError = roundTripMessage(result);
        ok &= expect(limitError.errorCode() == 2 && limitError.returnvalue().empty(),
            "process applies the executor's last valid limit and clears stale output on failure");
        receivingModule.errorCodeToMsg(limitError, error);
        ok &= expect(error == "The sample exceeds the configured byte limit.",
            "errorCodeToMsg translates the received limit error code");
        receivingModule.followUp(limitError);
        ok &= expect(receiver.lastResultForTest() == "3", "followUp preserves the last success after an error");

        C2Message incomplete;
        incomplete.set_instruction("moduleTemplate");
        C2Message invalidRequest = roundTripMessage(incomplete);
        executor.process(invalidRequest, result);
        const C2Message invalidResponse = roundTripMessage(result);
        receivingModule.errorCodeToMsg(invalidResponse, error);
        ok &= expect(invalidResponse.errorCode() == 1 && invalidResponse.returnvalue().empty()
            && error == "Expected a moduleTemplate request with a nonempty sample.",
            "process validates a received request and its error code identifies the failure");

        ok &= expect(executor.initConfig(nlohmann::json::object()) == 0, "omitting the limit restores the default");
        executor.process(request, result);
        ok &= expect(result.errorCode() == 0 && result.returnvalue() == "3", "the default limit permits the sample");
        return ok;
    }

    bool testRecurringExec()
    {
        ModuleTemplate example;
        ModuleCmd& module = example;
        C2Message result;

        bool ok = expect(module.recurringExec(result) == 0 && result.errorCode() == -1,
            "recurringExec leaves the response untouched when no sample is available");
        example.recordSampleForTest(0);
        ok &= expect(module.recurringExec(result) == 1, "recurringExec reports a pending sample");

        const C2Message response = roundTripMessage(result);
        ok &= expect(response.errorCode() == 0 && response.returnvalue() == "0",
            "a zero-byte sample survives serialization as a successful result");

        ModuleTemplate receiver;
        receiver.followUp(response);
        ok &= expect(receiver.lastResultForTest() == "0", "followUp can consume a recurring result on a fresh instance");
        C2Message nextResult;
        ok &= expect(module.recurringExec(nextResult) == 0 && nextResult.returnvalue().empty(),
            "recurringExec consumes the sample once");
        return ok;
    }
}

int main()
{
    const bool lifecyclePassed = testRequestLifecycle();
    const bool recurringPassed = testRecurringExec();
    return lifecyclePassed && recurringPassed ? 0 : 1;
}
