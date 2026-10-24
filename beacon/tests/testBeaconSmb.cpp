#include "BeaconSmb.hpp"
#include "ListenerSmb.hpp"
#include <PipeHandler.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <thread>

class TestListenerSmb : public ListenerSmb
{
public:
    using ListenerSmb::ListenerSmb;
    std::string key() const { return m_key; }
};

class TestBeaconSmb : public BeaconSmb
{
public:
    using BeaconSmb::BeaconSmb;
    void poll() { checkIn(); }
    const std::string& hash() const { return m_beaconHash; }
    std::size_t taskCount() const { return m_tasks.size(); }
    void queueResult()
    {
        C2Message result;
        result.set_instruction("smb-contract-result");
        m_taskResult.push(result);
    }
};

int main()
{
    std::filesystem::create_directories("logs");
    const std::string pipe = "c2-smb-contract-" + std::to_string(GetCurrentProcessId());
    TestListenerSmb listener(".", pipe);
    if (listener.init() != 1)
        return 1;

    TestListenerSmb duplicate(".", pipe);
    if (duplicate.init() != -1)
    {
        std::cerr << "Duplicate SMB pipe was accepted" << std::endl;
        return 1;
    }

    // A disconnected client must not prevent the next beacon from connecting.
    {
        PipeHandler::Client abandoned(".", pipe);
        for (int i = 0; i < 100 && !abandoned.initConnection(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        abandoned.closeConnection();
    }

    // Reject a hostile length before allocating and keep serving new clients.
    {
        const std::string path = "\\\\.\\pipe\\" + pipe;
        HANDLE raw = INVALID_HANDLE_VALUE;
        for (int i = 0; i < 100 && raw == INVALID_HANDLE_VALUE; ++i)
        {
            raw = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (raw == INVALID_HANDLE_VALUE)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (raw == INVALID_HANDLE_VALUE)
            return 1;
        const std::int32_t oversized = 64 * 1024 * 1024 + 1;
        DWORD written = 0;
        if (!WriteFile(raw, &oversized, sizeof(oversized), &written, nullptr) ||
            written != sizeof(oversized))
            return 1;
        CloseHandle(raw);
    }

    nlohmann::json configJson;
    configJson["xorKey"] = listener.key();
    configJson["ModulesConfig"] = nlohmann::json::object();
    std::string config = configJson.dump();
    TestBeaconSmb beacon(config, ".", pipe);

    for (int i = 0; i < 100 && listener.getNumberOfSession() == 0; ++i)
    {
        beacon.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (listener.getNumberOfSession() != 1)
    {
        std::cerr << "SMB beacon did not register with its listener" << std::endl;
        return 1;
    }

    beacon.queueResult();
    bool resultReceived = false;
    for (int i = 0; i < 100 && !resultReceived; ++i)
    {
        beacon.poll();
        resultReceived = listener.getTaskResult(beacon.hash()).instruction() == "smb-contract-result";
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!resultReceived)
    {
        std::cerr << "SMB beacon result did not reach its listener" << std::endl;
        return 1;
    }

    C2Message task;
    task.set_instruction("smb-contract-task");
    listener.queueTask(beacon.hash(), task);
    for (int i = 0; i < 100 && beacon.taskCount() == 0; ++i)
    {
        beacon.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (beacon.taskCount() != 1)
    {
        std::cerr << "SMB listener task did not reach the beacon exactly once" << std::endl;
        return 1;
    }

    // Shutdown must interrupt a client that connected but never sent a frame.
    {
        auto idleListener = std::make_unique<TestListenerSmb>(".", pipe + "-idle");
        if (idleListener->init() != 1)
            return 1;
        PipeHandler::Client idleClient(".", pipe + "-idle");
        if (!idleClient.initConnection())
            return 1;
        const auto started = std::chrono::steady_clock::now();
        idleListener.reset();
        if (std::chrono::steady_clock::now() - started > std::chrono::seconds(1))
        {
            std::cerr << "SMB listener did not stop promptly with an idle client" << std::endl;
            return 1;
        }
    }
    return 0;
}
