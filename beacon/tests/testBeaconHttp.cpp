#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "BeaconHttp.hpp"

#ifdef __linux__
#include "httplib.h"

#include <chrono>
#include <iostream>
#include <thread>

class TestBeaconHttp : public BeaconHttp
{
public:
    using BeaconHttp::BeaconHttp;
    const std::string& beaconHash() const { return m_beaconHash; }
    void setSleepMs(int duration) { m_aliveTimerMs = duration; }
};

std::string encodeStopTask(const std::string& beaconHash)
{
    MultiBundleC2Message envelope;
    auto* bundle = envelope.add_bundlec2messages();
    bundle->set_beaconhash(beaconHash);
    bundle->add_c2messages()->set_instruction(EndCmd);
    std::string data;
    envelope.SerializeToString(&data);
    XOR(data, "key");
    return base64_encode(data);
}

bool containsStopResult(const std::string& payload)
{
    std::string data = base64_decode(payload);
    if (!XOR(data, "key"))
        return false;
    MultiBundleC2Message envelope;
    if (!envelope.ParseFromArray(data.data(), static_cast<int>(data.size())))
        return false;
    for (int bundleIndex = 0; bundleIndex < envelope.bundlec2messages_size(); ++bundleIndex)
    {
        const auto* bundle = envelope.bundlec2messages(bundleIndex);
        for (int messageIndex = 0; messageIndex < bundle->c2messages_size(); ++messageIndex)
        {
            const auto message = bundle->c2messages(messageIndex);
            if (message.instruction() == EndCmd && message.errorCode() == 0 &&
                message.returnvalue() == CmdStatusSuccess)
                return true;
        }
    }
    return false;
}
#endif

int main() {
    std::string config = R"({
        "xorKey":"key",
        "ModulesConfig":{},
        "ListenerHttpConfig":{
            "uri":["/checkin"],
            "client":{"headers":{}}
        }
    })";
    std::string ip = "127.0.0.1";
    int port = 1;
    BeaconHttp b(config, ip, port, false);
    b.checkIn();
    if (!b.hasPendingOutputForTest())
        return 1;

#ifdef __linux__
    httplib::Server server;
    const int listenPort = server.bind_to_any_port("127.0.0.1");
    if (listenPort <= 0)
        return 2;
    std::string liveConfig = R"({"xorKey":"key","ModulesConfig":{},"ListenerHttpConfig":{"uri":["/checkin"],"client":{"headers":{}}}})";
    TestBeaconHttp liveBeacon(liveConfig, ip, listenPort, false);
    liveBeacon.setSleepMs(5000);
    int requests = 0;
    bool finalResultSeen = false;
    bool repeatedResultSeen = false;
    server.Post("/checkin", [&](const httplib::Request& request, httplib::Response& response) {
        ++requests;
        if (requests == 1)
        {
            response.set_content(encodeStopTask(liveBeacon.beaconHash()), "text/plain");
        }
        else
        {
            const bool hasResult = containsStopResult(request.body);
            if (requests == 2)
            {
                finalResultSeen = hasResult;
                response.status = 503;
            }
            else
            {
                repeatedResultSeen = hasResult;
                response.status = 200;
            }
        }
    });
    std::thread serverThread([&] { server.listen_after_bind(); });
    const auto startedAt = std::chrono::steady_clock::now();
    liveBeacon.run();
    const auto elapsed = std::chrono::steady_clock::now() - startedAt;
    server.stop();
    serverThread.join();
    if (requests != 3 || !finalResultSeen || !repeatedResultSeen ||
        liveBeacon.hasPendingOutputForTest() || elapsed >= std::chrono::seconds(3))
    {
        std::cerr << "Final stop result was not retried promptly after HTTP failure\n";
        return 3;
    }
#endif
    return 0;
}
