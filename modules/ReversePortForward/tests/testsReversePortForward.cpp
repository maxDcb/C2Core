#include "../ReversePortForward.hpp"

#include "../../tests/TestHelpers.hpp"
#include "../../tests/local/MessageTestHelpers.hpp"

#include <chrono>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace test_helpers;

namespace
{
#ifdef _WIN32
    using SocketHandle = SOCKET;
    constexpr SocketHandle InvalidSocket = INVALID_SOCKET;
#else
    using SocketHandle = int;
    constexpr SocketHandle InvalidSocket = -1;
#endif

    void closeSocket(SocketHandle socket)
    {
#ifdef _WIN32
        if (socket != InvalidSocket)
            closesocket(socket);
#else
        if (socket != InvalidSocket)
            ::close(socket);
#endif
    }

    class SocketRuntime
    {
    public:
        SocketRuntime()
        {
#ifdef _WIN32
            WSADATA data;
            m_ready = WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
            m_ready = true;
#endif
        }

        ~SocketRuntime()
        {
#ifdef _WIN32
            if (m_ready)
                WSACleanup();
#endif
        }

        bool ready() const
        {
            return m_ready;
        }

    private:
        bool m_ready = false;
    };

    SocketHandle createLoopbackListener(int port, int& boundPort)
    {
        SocketHandle listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == InvalidSocket)
            return InvalidSocket;

        int enabled = 1;
#ifdef _WIN32
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&enabled), sizeof(enabled));
#else
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
#endif

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(static_cast<unsigned short>(port));

        if (::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
        {
            closeSocket(listener);
            return InvalidSocket;
        }

        if (::listen(listener, SOMAXCONN) != 0)
        {
            closeSocket(listener);
            return InvalidSocket;
        }

        sockaddr_in actual{};
#ifdef _WIN32
        int actualSize = sizeof(actual);
#else
        socklen_t actualSize = sizeof(actual);
#endif
        if (::getsockname(listener, reinterpret_cast<sockaddr*>(&actual), &actualSize) != 0)
        {
            closeSocket(listener);
            return InvalidSocket;
        }

        boundPort = ntohs(actual.sin_port);
        return listener;
    }

    int reserveLoopbackPort()
    {
        int port = 0;
        SocketHandle listener = createLoopbackListener(0, port);
        closeSocket(listener);
        return port;
    }

    bool sendAll(SocketHandle socket, const std::string& data)
    {
        size_t sentTotal = 0;
        while (sentTotal < data.size())
        {
            int sent = ::send(socket, data.data() + sentTotal, static_cast<int>(data.size() - sentTotal), 0);
            if (sent <= 0)
                return false;
            sentTotal += static_cast<size_t>(sent);
        }
        return true;
    }

    SocketHandle connectLoopback(int port, std::chrono::milliseconds timeout)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline)
        {
            SocketHandle socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (socket == InvalidSocket)
                return InvalidSocket;

            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_port = htons(static_cast<unsigned short>(port));

            if (::connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0)
                return socket;

            closeSocket(socket);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        return InvalidSocket;
    }

    std::string recvWithTimeout(SocketHandle socket, std::chrono::milliseconds timeout)
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(socket, &readSet);

        timeval tv{};
        tv.tv_sec = static_cast<long>(timeout.count() / 1000);
        tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);

        int ready = ::select(static_cast<int>(socket) + 1, &readSet, nullptr, nullptr, &tv);
        if (ready <= 0 || !FD_ISSET(socket, &readSet))
            return {};

        char buffer[4096];
        int received = ::recv(socket, buffer, sizeof(buffer), 0);
        if (received <= 0)
            return {};
        return std::string(buffer, received);
    }

    class EchoServer
    {
    public:
        EchoServer()
        {
            m_listener = createLoopbackListener(0, m_port);
            if (m_listener != InvalidSocket)
                m_thread = std::thread(&EchoServer::run, this);
        }

        ~EchoServer()
        {
            SocketHandle unblocker = connectLoopback(m_port, std::chrono::milliseconds(100));
            closeSocket(unblocker);
            if (m_listener != InvalidSocket)
                closeSocket(m_listener);
            if (m_client != InvalidSocket)
                closeSocket(m_client);
            if (m_thread.joinable())
                m_thread.join();
        }

        bool started() const
        {
            return m_listener != InvalidSocket && m_port > 0;
        }

        int port() const
        {
            return m_port;
        }

    private:
        void run()
        {
            m_client = ::accept(m_listener, nullptr, nullptr);
            if (m_client == InvalidSocket)
                return;

            char buffer[4096];
            int received = ::recv(m_client, buffer, sizeof(buffer), 0);
            if (received > 0)
            {
                std::string response = "echo:";
                response.append(buffer, received);
                sendAll(m_client, response);
            }
        }

        SocketHandle m_listener = InvalidSocket;
        SocketHandle m_client = InvalidSocket;
        int m_port = 0;
        std::thread m_thread;
    };

    bool waitForRecurring(ReversePortForward& module,
                          C2Message& message,
                          const std::function<bool(const C2Message&)>& predicate,
                          std::chrono::milliseconds timeout)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline)
        {
            C2Message candidate;
            if (module.recurringExec(candidate) == 1)
            {
                if (predicate(candidate))
                {
                    message = candidate;
                    return true;
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        return false;
    }

    bool testInit()
    {
        ReversePortForward module;
        std::vector<std::string> cmd = {"reversePortForward", "8080", "127.0.0.1", "80"};
        C2Message message;

        bool ok = true;
        ok &= expect(module.init(cmd, message) == 0, "valid init should succeed");
        ok &= expect(message.instruction() == cmd[0], "instruction should be set");
        ok &= expect(message.cmd() == "start", "start command should be packed");
        ok &= expect(message.args() == "8080 127.0.0.1 80", "forward parameters should be packed");
        return ok;
    }

    bool testInvalidArguments()
    {
        bool ok = true;
        ReversePortForward module;
        C2Message message;

        std::vector<std::string> cmd = {"reversePortForward", "invalid", "127.0.0.1", "80"};
        ok &= expect(module.init(cmd, message) == -1, "non-numeric port should be rejected");
        ok &= expect(message.returnvalue().find("Invalid port") != std::string::npos, "non-numeric port should explain the error");

        cmd = {"reversePortForward", "8080"};
        message = C2Message();
        ok &= expect(module.init(cmd, message) == -1, "missing arguments should be rejected");
        ok &= expect(message.returnvalue().find("reversePortForward") != std::string::npos, "missing arguments should return help");

        cmd = {"reversePortForward", "0", "127.0.0.1", "80"};
        message = C2Message();
        ok &= expect(module.init(cmd, message) == -1, "zero remote port should be rejected");
        ok &= expect(message.returnvalue().find("Ports must be between") != std::string::npos, "out-of-range port should explain the error");
        return ok;
    }

    bool testErrorMessages()
    {
        ReversePortForward module;
        bool ok = true;

        for (int code = 1; code <= 5; ++code)
        {
            std::string error;
            C2Message response;
            response.set_errorCode(code);
            ok &= expect(module.errorCodeToMsg(response, error) == 0, "errorCodeToMsg should return success");
            ok &= expect(!error.empty(), "known error code should map to text");
        }

        std::string unchanged = "unchanged";
        C2Message response;
        response.set_errorCode(0);
        ok &= expect(module.errorCodeToMsg(response, unchanged) == 0, "zero error code should return success");
        ok &= expect(unchanged.empty(), "zero error code should clear an earlier message");
        return ok;
    }

    bool testStartErrors()
    {
        ReversePortForward module;
        C2Message start;
        start.set_instruction("reversePortForward");
        start.set_cmd("start");
        start.set_args("0 127.0.0.1 1");

        C2Message ret;
        bool ok = true;
        ok &= expect(module.process(start, ret) == 0, "invalid start should return through C2Message");
        ok &= expect(ret.errorCode() == 3, "invalid start should set bind error");

        const int remotePort = reserveLoopbackPort();
        start.set_args(std::to_string(remotePort) + " 127.0.0.1 1");
        ret = C2Message();
        ok &= expect(module.process(start, ret) == 0, "first start should succeed");
        ok &= expect(ret.errorCode() == 0, "first start should set code zero");

        ret = C2Message();
        ok &= expect(module.process(start, ret) == 0, "duplicate start should return through C2Message");
        ok &= expect(ret.errorCode() == 1, "duplicate start should set already-running error");
        return ok;
    }

    bool testLoopbackForward()
    {
        EchoServer echo;
        bool ok = true;
        ok &= expect(echo.started(), "local echo server should start");
        if (!echo.started())
            return false;

        const int remotePort = reserveLoopbackPort();
        ok &= expect(remotePort > 0, "remote test port should be reservable");
        if (remotePort <= 0)
            return false;

        ReversePortForward preparer;
        ReversePortForward teamserver;
        ReversePortForward implant;
        C2Message start;
        std::vector<std::string> cmd = {
            "reversePortForward",
            std::to_string(remotePort),
            "127.0.0.1",
            std::to_string(echo.port())};

        ok &= expect(preparer.init(cmd, start) == 0, "teamserver init should pack start message");
        C2Message transportedStart = roundTripMessage(start);

        C2Message startRetRaw;
        ok &= expect(implant.process(transportedStart, startRetRaw) == 0, "implant start should return through C2Message");
        const C2Message startRet = roundTripMessage(startRetRaw);
        ok &= expect(startRet.errorCode() == 0, "implant start should set code zero");
        ok &= expect(startRet.returnvalue().find(std::to_string(remotePort)) != std::string::npos, "implant start should report remote port");
        if (!ok)
            return false;

        SocketHandle remoteClient = connectLoopback(remotePort, std::chrono::seconds(2));
        ok &= expect(remoteClient != InvalidSocket, "remote client should connect to forwarded port");
        if (remoteClient == InvalidSocket)
            return false;

        ok &= expect(sendAll(remoteClient, "ping"), "remote client should send data");

        C2Message toTeamserver;
        ok &= expect(waitForRecurring(
                         implant,
                         toTeamserver,
                         [](const C2Message& message)
                         {
                             return message.cmd() == "send"
                                 && message.args().find("data:") == 0
                                 && message.data() == "ping";
                         },
                         std::chrono::seconds(2)),
                     "implant recurringExec should emit remote data");

        const std::string dataArgs = toTeamserver.args();
        toTeamserver = roundTripMessage(toTeamserver);
        ok &= expect(toTeamserver.errorCode() == 0
            && teamserver.followUp(toTeamserver) == 0,
            "a separate teamserver receiver forwards serialized data to its local service");

        C2Message toImplant;
        ok &= expect(waitForRecurring(
                         teamserver,
                         toImplant,
                         [&](const C2Message& message)
                         {
                             return message.cmd() == "send"
                                 && message.args() == "response:" + dataArgs.substr(std::string("data:").size())
                                 && message.data() == "echo:ping";
                         },
                         std::chrono::seconds(2)),
                     "teamserver recurringExec should emit local service response");

        toImplant = roundTripMessage(toImplant);
        ok &= expect(toImplant.errorCode() == 0, "recurring local response should carry code zero");
        C2Message sendRet;
        ok &= expect(implant.process(toImplant, sendRet) == 0, "implant should send response to remote client");
        ok &= expect(sendRet.errorCode() == 0, "implant response send should set code zero");
        ok &= expect(recvWithTimeout(remoteClient, std::chrono::seconds(2)) == "echo:ping", "remote client should receive local service response");

#ifdef _WIN32
        shutdown(remoteClient, SD_BOTH);
#else
        shutdown(remoteClient, SHUT_RDWR);
#endif
        closeSocket(remoteClient);

        C2Message closeMessage;
        ok &= expect(waitForRecurring(
                         implant,
                         closeMessage,
                         [&](const C2Message& message)
                         {
                             return message.cmd() == "close"
                                 && message.args() == "close:" + dataArgs.substr(std::string("data:").size());
                         },
                         std::chrono::seconds(2)),
                     "implant should emit close event after remote disconnect");
        if (closeMessage.cmd() == "close")
            ok &= expect(teamserver.followUp(roundTripMessage(closeMessage)) == 0,
                "teamserver should close local connection from a serialized event");

        return ok;
    }
}

int main()
{
    SocketRuntime runtime;
    bool ok = true;

    ok &= expect(runtime.ready(), "socket runtime should initialise");
    if (!runtime.ready())
        return 1;

    ok &= testInit();
    ok &= testInvalidArguments();
    ok &= testErrorMessages();
    ok &= testStartErrors();
    ok &= testLoopbackForward();

    std::cout << (ok ? "[+]" : "[-]") << " reversePortForward tests" << std::endl;
    return ok ? 0 : 1;
}
