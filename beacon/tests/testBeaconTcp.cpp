#include "BeaconTcp.hpp"
#include "ListenerTcp.hpp"
#include <SocketServer.hpp>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

class TestListenerTcp : public ListenerTcp
{
public:
    using ListenerTcp::ListenerTcp;
    std::string key() const { return m_key; }
};

class TestBeaconTcp : public BeaconTcp
{
public:
    using BeaconTcp::BeaconTcp;
    void poll() { checkIn(); }
    const std::string& hash() const { return m_beaconHash; }
    std::size_t taskCount() const { return m_tasks.size(); }
    void queueResult()
    {
        C2Message result;
        result.set_instruction("tcp-contract-result");
        m_taskResult.push(result);
    }
};

int main()
{
    std::filesystem::create_directories("logs");
    int port = 0;
    {
        SocketServer reservation(0);
        reservation.launch();
        if (!reservation.isServerLaunched())
            return 1;
        port = reservation.getServerPort();
    }

    TestListenerTcp listener("127.0.0.1", port);
    if (listener.init() != 1)
        return 1;

    nlohmann::json configJson;
    configJson["xorKey"] = listener.key();
    configJson["ModulesConfig"] = nlohmann::json::object();
    std::string config = configJson.dump();
    std::string ip = "127.0.0.1";
    TestBeaconTcp beacon(config, ip, port);

    for (int i = 0; i < 100 && listener.getNumberOfSession() == 0; ++i)
    {
        beacon.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (listener.getNumberOfSession() != 1)
    {
        std::cerr << "TCP beacon did not register with its listener" << std::endl;
        return 1;
    }

    beacon.queueResult();
    bool resultReceived = false;
    for (int i = 0; i < 100 && !resultReceived; ++i)
    {
        beacon.poll();
        resultReceived = listener.getTaskResult(beacon.hash()).instruction() == "tcp-contract-result";
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!resultReceived)
    {
        std::cerr << "TCP beacon result did not reach its listener" << std::endl;
        return 1;
    }

    C2Message task;
    task.set_instruction("tcp-contract-task");
    listener.queueTask(beacon.hash(), task);
    for (int i = 0; i < 100 && beacon.taskCount() == 0; ++i)
    {
        beacon.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (beacon.taskCount() != 1)
    {
        std::cerr << "TCP listener task did not reach the beacon exactly once" << std::endl;
        return 1;
    }
    return 0;
}
