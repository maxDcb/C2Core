#include "../../Netstat.hpp"
#include "../../../tests/local/MessageTestHelpers.hpp"

#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

int main()
{
#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 1;
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET)
        return 1;
#else
    const int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0)
        return 1;
#endif
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    bool ok = bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0
        && listen(listener, 1) == 0;
#ifdef _WIN32
    int length = sizeof(address);
#else
    socklen_t length = sizeof(address);
#endif
    ok &= getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0;
    if (ok)
    {
        Netstat preparer;
        Netstat executor;
        Netstat receiver;
        std::vector<std::string> command{"netstat"};
        C2Message prepared;
        ok = preparer.init(command, prepared) == 0;
        C2Message request = test_helpers::roundTripMessage(prepared);
        C2Message raw;
        executor.process(request, raw);
        const C2Message response = test_helpers::roundTripMessage(raw);
        std::string error;
        receiver.errorCodeToMsg(response, error);
        const std::string endpoint = "127.0.0.1:" + std::to_string(ntohs(address.sin_port));
        ok &= response.instruction() == "netstat" && response.errorCode() == 0
            && error.empty() && response.returnvalue().find(endpoint) != std::string::npos;
        if (!ok)
            std::cerr << "netstat did not report the test listener at " << endpoint << '\n';
    }
#ifdef _WIN32
    closesocket(listener);
    WSACleanup();
#else
    close(listener);
#endif
    return ok ? 0 : 1;
}
