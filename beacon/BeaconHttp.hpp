#pragma once

#include "Beacon.hpp"

#include <memory>
#include <string>

#ifdef __linux__
namespace httplib
{
namespace ws
{
class WebSocketClient;
}
}
#elif _WIN32
#include <windows.h>
#include <WinHttp.h>

struct WsClient
{
    std::wstring host;
    int port = 0;
    std::wstring path;
    bool isHttps = false;

    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hWebSocket = nullptr;

    bool allowInsecureTls = true;
};
#endif

class BeaconHttp : public Beacon
{
public:
    BeaconHttp(std::string& config, std::string& ip, int port, bool https=false);
    ~BeaconHttp();

    void checkIn();

private:
    bool ensureWebSocketConnected();
    void resetWebSocketConnection();
    bool tryWebSocketCheckIn(const std::string& output, std::string& input);
    bool tryHttpCheckIn(const std::string& output, std::string& input);
    std::string pickRandomEndpoint(const char* key) const;

    std::string m_ip;
    int m_port;
    nlohmann::json m_beaconHttpConfig;
    bool m_isHttps;
    std::string m_wsEndpoint;

#ifdef __linux__
    std::unique_ptr<httplib::ws::WebSocketClient> m_wsClient;
#elif _WIN32
    WsClient m_ws;
#endif
};
