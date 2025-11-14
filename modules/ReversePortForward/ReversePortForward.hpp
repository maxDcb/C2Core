#pragma once

#include "ModuleCmd.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

class ReversePortForward : public ModuleCmd
{
public:
    ReversePortForward();
    ~ReversePortForward();

    std::string getInfo() override;

    int init(std::vector<std::string>& splitedCmd, C2Message& c2Message) override;
    int process(C2Message& c2Message, C2Message& c2RetMessage) override;
    int followUp(const C2Message& c2RetMessage) override;
    int recurringExec(C2Message& c2RetMessage) override;
    int errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg) override;
    int osCompatibility() override
    {
        return OS_LINUX | OS_WINDOWS;
    }

private:
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    struct PendingChunk
    {
        int connectionId;
        std::string data;
        bool closeEvent;
    };

    using SocketHandle =
    #ifdef _WIN32
        SOCKET;
    #else
        int;
    #endif

    static constexpr SocketHandle InvalidSocket =
    #ifdef _WIN32
        INVALID_SOCKET;
    #else
        -1;
    #endif

    bool ensureSocketLayer();
    void shutdownSocketLayer();
    void closeSocket(SocketHandle socket) const;
    bool sendAll(SocketHandle socket, const std::string& data) const;
    std::string receiveAvailable(SocketHandle socket, bool& closed) const;
    void enqueueChunk(int connectionId, const std::string& data, bool closeEvent);
    void pollLocalConnections();

    std::string m_localHost;
    int m_localPort;
    int m_remotePort;
    bool m_socketLayerReady;
    std::mutex m_localMutex;
    std::unordered_map<int, SocketHandle> m_localConnections;
    std::mutex m_queueMutex;
    std::queue<PendingChunk> m_pendingChunks;
#else
    using SocketHandle =
    #ifdef _WIN32
        SOCKET;
    #else
        int;
    #endif

    static constexpr SocketHandle InvalidSocket =
    #ifdef _WIN32
        INVALID_SOCKET;
    #else
        -1;
    #endif

    struct PendingChunk
    {
        int connectionId;
        std::string data;
        bool closeEvent;
    };

    struct RemoteConnection
    {
        int id;
        SocketHandle socket;
        std::atomic<bool> active;
        std::thread reader;
    };

    bool ensureSocketLayer();
    void shutdownSocketLayer();
    SocketHandle createListener(int port);
    SocketHandle acceptClient(SocketHandle listener);
    void closeSocket(SocketHandle socket);
    void runListener();
    void handleClient(std::shared_ptr<RemoteConnection> connection);
    void enqueueChunk(int connectionId, const std::string& data, bool closeEvent);
    std::shared_ptr<RemoteConnection> getConnection(int connectionId);

    std::atomic<bool> m_running;
    std::atomic<bool> m_listenerActive;
    int m_remotePort;
    SocketHandle m_listenerSocket;
    std::thread m_listenerThread;
    std::atomic<int> m_nextConnectionId;
    std::mutex m_connectionsMutex;
    std::unordered_map<int, std::shared_ptr<RemoteConnection>> m_connections;
    std::mutex m_queueMutex;
    std::queue<PendingChunk> m_pendingChunks;
    std::condition_variable m_queueCv;
    bool m_socketLayerReady;
#endif
};

#ifdef _WIN32
extern "C" __declspec(dllexport) ReversePortForward* ReversePortForwardConstructor();
#else
extern "C" __attribute__((visibility("default"))) ReversePortForward* ReversePortForwardConstructor();
#endif
