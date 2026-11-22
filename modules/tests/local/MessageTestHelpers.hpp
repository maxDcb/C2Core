#pragma once

#include <C2Message.hpp>
#include <ModuleCmd.hpp>

#include <stdexcept>
#include <string>
#include <vector>

namespace test_helpers
{
    inline C2Message roundTripMessage(const C2Message& message)
    {
        std::string serialized;
        if (!message.SerializeToString(&serialized))
            throw std::runtime_error("Could not serialize the local test message");

        C2Message decoded;
        if (!decoded.ParseFromArray(serialized.data(), static_cast<int>(serialized.size())))
            throw std::runtime_error("Could not deserialize the local test message");

        return decoded;
    }

    struct MessageExchange
    {
        C2Message request;
        C2Message response;
    };

    inline MessageExchange exchangeMessages(ModuleCmd& preparer, ModuleCmd& executor,
        std::vector<std::string> args)
    {
        C2Message prepared;
        if (preparer.init(args, prepared) != 0)
            throw std::runtime_error("The module did not prepare a local test request");

        MessageExchange exchange;
        exchange.request = roundTripMessage(prepared);
        C2Message result;
        executor.process(exchange.request, result);
        exchange.response = roundTripMessage(result);
        return exchange;
    }
}
