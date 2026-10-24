#pragma once

#include "Listener.hpp"

#include <memory>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

class ListenerHttp : public Listener
{
public:
    ListenerHttp(const std::string& ip, int localport, const nlohmann::json& config, bool isHttps=false);
    ~ListenerHttp();

    int init();
    bool isRunning() const;

private:
    void launchHttpServ();
    void runHttpServ();
    bool isAllowedPath(const std::string& path) const;
    bool processPayload(const std::string& requestData, std::string& responseData);
    bool extractExchangeIdentity(const std::string& requestData,
                                 std::string& beaconHash,
                                 std::string& exchangeId) const;

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
    struct CachedExchange
    {
        std::string response;
        bool hasTasks = false;
    };
    std::mutex m_exchangeMutex;
    std::unordered_map<std::string, CachedExchange> m_exchangeCache;
    std::unordered_map<std::string, std::string> m_beaconExchange;
    std::atomic_bool m_running{false};
    std::atomic_bool m_threadExited{true};

    std::unique_ptr<httplib::Server> m_svr;
    std::unique_ptr<std::thread> m_httpServ;
};
