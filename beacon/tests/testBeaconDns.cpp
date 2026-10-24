#include "BeaconDns.hpp"
#include "ListenerDns.hpp"
#include <server.hpp>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

class TestListenerDns : public ListenerDns
{
public:
    using ListenerDns::ListenerDns;
    std::string key() const { return m_key; }
};

class TestBeaconDns : public BeaconDns
{
public:
    using BeaconDns::BeaconDns;
    void poll() { checkIn(); }
    const std::string& hash() const { return m_beaconHash; }
    std::size_t taskCount() const { return m_tasks.size(); }
    void queueResult()
    {
        C2Message result;
        result.set_instruction("dns-contract-result");
        m_taskResult.push(result);
    }
};

int main()
{
    std::filesystem::create_directories("logs");

    dns::Server reservation(0, "contract.test");
    if (!reservation.launch())
    {
        std::cerr << "DNS port reservation failed\n";
        return 1;
    }
    const int port = reservation.getPort();
    reservation.stop();

    TestListenerDns listener("contract.test", port);
    if (!listener.isRunning())
    {
        std::cerr << "DNS listener did not start\n";
        return 2;
    }

    nlohmann::json configJson;
    configJson["xorKey"] = listener.key();
    configJson["ModulesConfig"] = nlohmann::json::object();
    std::string config = configJson.dump();
    TestBeaconDns beacon(config, "127.0.0.1", "contract.test", port);

    for (int i = 0; i < 20 && listener.getNumberOfSession() == 0; ++i)
    {
        beacon.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (listener.getNumberOfSession() != 1)
    {
        std::cerr << "DNS beacon did not register\n";
        return 3;
    }

    beacon.queueResult();
    bool resultReceived = false;
    for (int i = 0; i < 20 && !resultReceived; ++i)
    {
        beacon.poll();
        resultReceived = listener.getTaskResult(beacon.hash()).instruction() ==
                         "dns-contract-result";
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!resultReceived)
    {
        std::cerr << "DNS result was not delivered\n";
        return 4;
    }

    C2Message task;
    task.set_instruction("dns-contract-task");
    listener.queueTask(beacon.hash(), task);
    for (int i = 0; i < 20 && beacon.taskCount() == 0; ++i)
    {
        beacon.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (beacon.taskCount() != 1)
    {
        std::cerr << "DNS task was not delivered exactly once\n";
        return 5;
    }

    return 0;
}
