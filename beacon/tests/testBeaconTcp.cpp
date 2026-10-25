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
    void hostTestListener(std::unique_ptr<Listener> child)
    {
        addTestListener(std::move(child));
    }
    void queueResult()
    {
        C2Message result;
        result.set_instruction("tcp-contract-result");
        m_taskResult.push(result);
    }
    void queueChildResult()
    {
        C2Message result;
        result.set_instruction("pivot-contract-result");
        result.set_uuid("pivot-command-id");
        result.set_returnvalue("pivot-complete");
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

    int childPort = 0;
    {
        SocketServer reservation(0);
        reservation.launch();
        if (!reservation.isServerLaunched())
            return 1;
        childPort = reservation.getServerPort();
    }
    auto childListener = std::make_unique<TestListenerTcp>("127.0.0.1", childPort);
    if (childListener->init() != 1)
        return 1;
    const std::string childListenerHash = childListener->getListenerHash();
    nlohmann::json childConfigJson;
    childConfigJson["xorKey"] = childListener->key();
    childConfigJson["ModulesConfig"] = nlohmann::json::object();
    std::string childConfig = childConfigJson.dump();
    TestListenerTcp* hostedListener = childListener.get();
    beacon.hostTestListener(std::move(childListener));
    TestBeaconTcp child(childConfig, ip, childPort);

    for (int i = 0; i < 200 && hostedListener->getNumberOfSession() == 0; ++i)
    {
        child.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (hostedListener->getNumberOfSession() != 1)
    {
        std::cerr << "Child beacon did not register with the hosted TCP listener" << std::endl;
        return 1;
    }
    for (int i = 0; i < 200 && !listener.isSessionExist(child.hash(), childListenerHash); ++i)
    {
        beacon.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!listener.isSessionExist(child.hash(), childListenerHash))
    {
        std::cerr << "Child session did not traverse the parent beacon" << std::endl;
        return 1;
    }

    C2Message childTask;
    childTask.set_instruction("pivot-contract-task");
    childTask.set_uuid("pivot-command-id");
    if (!listener.queueTask(child.hash(), childListenerHash, childTask))
        return 1;
    for (int i = 0; i < 200 && child.taskCount() == 0; ++i)
    {
        beacon.poll();
        child.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (child.taskCount() != 1)
    {
        std::cerr << "Command did not traverse the parent TCP beacon" << std::endl;
        return 1;
    }

    child.queueChildResult();
    bool childResultReceived = false;
    for (int i = 0; i < 200 && !childResultReceived; ++i)
    {
        child.poll();
        beacon.poll();
        const auto result = listener.getTaskResult(child.hash(), childListenerHash);
        childResultReceived = result.uuid() == "pivot-command-id" && result.returnvalue() == "pivot-complete";
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!childResultReceived)
    {
        std::cerr << "Result did not traverse the parent TCP beacon" << std::endl;
        return 1;
    }
    return 0;
}
