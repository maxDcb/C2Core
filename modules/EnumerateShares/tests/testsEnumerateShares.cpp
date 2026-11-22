#include "../EnumerateShares.hpp"
#include "../../tests/TestHelpers.hpp"

#include <string>
#include <vector>

namespace
{
class TestShares : public EnumerateShares
{
protected:
    bool runEnum(const std::string& host, std::string& result) override
    {
        if (host == "failure")
            return false;
        if (host == "one-share")
            result = "Public\n";
        return true;
    }
};
}

int main()
{
    bool ok = true;
    TestShares module;
    C2Message request;
    std::vector<std::string> invalid;
    ok &= test_helpers::expect(module.init(invalid, request) == -1,
        "empty command is rejected");
    invalid = {"enumerateShares", "host", "extra"};
    ok &= test_helpers::expect(module.init(invalid, request) == -1,
        "extra arguments are rejected");

    std::vector<std::string> command = {"enumerateShares", "one-share"};
    C2Message response;
    ok &= test_helpers::expect(module.init(command, request) == 0,
        "host argument is prepared");
    module.process(request, response);
    ok &= test_helpers::expect(response.errorCode() == 0
        && response.returnvalue() == "Public\n",
        "a share listing is a successful result");

    command = {"enumerateShares"};
    request = C2Message{};
    response = C2Message{};
    module.init(command, request);
    module.process(request, response);
    ok &= test_helpers::expect(response.errorCode() == 0
        && response.returnvalue().empty(),
        "zero shares is still a successful enumeration");

    command = {"enumerateShares", "failure"};
    request = C2Message{};
    response = C2Message{};
    module.init(command, request);
    module.process(request, response);
    ok &= test_helpers::expect(response.errorCode() == 1
        && response.returnvalue().empty(),
        "enumeration failure transports a code without a message");
    std::string error;
    module.errorCodeToMsg(response, error);
    ok &= test_helpers::expect(error == "Failed to enumerate shares.",
        "the receiver translates the error code");
    return ok ? 0 : 1;
}
