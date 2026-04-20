#pragma once

#include "Listener.hpp"

#include <memory>
#include <string>
#include <thread>
#include <vector>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

class ListenerHttp : public Listener
{
public:
    ListenerHttp(const std::string& ip, int localport, const nlohmann::json& config, bool isHttps=false);
    ~ListenerHttp();

    int init();

private:
    void launchHttpServ();
    bool isAllowedPath(const std::string& path) const;
    bool processPayload(const std::string& requestData, std::string& responseData);

    int HandleCheckIn(const httplib::Request& req, httplib::Response& res);
    int HandleCheckIn(const std::string& requestData, httplib::Response& res);

    std::string m_host;
    int m_port;
    bool m_isHttps;
    nlohmann::json m_listenerConfig;
    std::vector<std::string> m_uris;
    std::vector<std::string> m_wsUris;
    std::string m_uriFileDownload;
    std::string m_downloadFolder;
    std::size_t m_wsMaxMessageSize;

    std::unique_ptr<httplib::Server> m_svr;
    std::unique_ptr<std::thread> m_httpServ;
};
