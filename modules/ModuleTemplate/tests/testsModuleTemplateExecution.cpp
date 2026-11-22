#include "../ModuleTemplate.hpp"
#include "../../tests/TestHelpers.hpp"
#include "../../tests/local/MessageTestHelpers.hpp"

#include <string>
#include <vector>

int main()
{
    using test_helpers::expect;
    using test_helpers::roundTripMessage;

    ModuleTemplate executor;
    C2Message preparedLocally;
    std::vector<std::string> args{"moduleTemplate", "sample"};
    executor.init(args, preparedLocally);
    bool ok = expect(executor.getInfo().empty() && preparedLocally.instruction().empty()
        && preparedLocally.data().empty(), "the execution variant leaves preparation and help inactive");

    C2Message fixture;
    fixture.set_instruction("moduleTemplate");
    fixture.set_data("sample");
    C2Message request = roundTripMessage(fixture);
    C2Message result;
    executor.process(request, result);
    const C2Message response = roundTripMessage(result);
    ok &= expect(response.errorCode() == 0 && response.returnvalue() == "6",
        "the execution variant processes the received sample");

    executor.followUp(response);
    ok &= expect(executor.lastResultForTest().empty(), "the execution variant leaves follow-up inactive");
    ok &= expect(executor.initConfig({{"max_bytes", 2}}) == 0, "the execution variant applies a local limit");
    executor.process(request, result);
    const C2Message rejected = roundTripMessage(result);
    std::string error;
    executor.errorCodeToMsg(rejected, error);
    ok &= expect(rejected.errorCode() == 2 && rejected.returnvalue().empty() && error.empty(),
        "the execution variant produces the error code for the receiving role");

    executor.recordSampleForTest(6);
    C2Message recurring;
    const int emitted = executor.recurringExec(recurring);
    ok &= expect(emitted == 1 && recurring.errorCode() == 0 && recurring.returnvalue() == "6",
        "the execution variant produces a sample supplied by the test");
    C2Message next;
    ok &= expect(executor.recurringExec(next) == 0, "the sample is produced once");
    return ok ? 0 : 1;
}
