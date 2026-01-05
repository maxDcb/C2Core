#pragma once

#include "Listener.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <crow.h>


class ListenerHttp : public Listener
{

public:
        ListenerHttp(const std::string& ip, int localport, const nlohmann::json& config, bool isHttps=false);
        ~ListenerHttp();

    int init();

private:
    struct PathGuardConfig
    {
        std::vector<std::string> uris;
        std::vector<std::string> wsUris;
        std::string downloadPrefix;
    };

    struct PathGuardMiddleware
    {
        struct context
        {
        };

        void before_handle(crow::request& req, crow::response& res, context&);
        void after_handle(crow::request&, crow::response&, context&) {}

        void setConfig(std::shared_ptr<const PathGuardConfig> config)
        {
            m_config = std::move(config);
        }

    private:
        std::shared_ptr<const PathGuardConfig> m_config;
    };

    struct WebSocketSession
    {
        crow::websocket::connection* connection{nullptr};
        std::string id;
        std::string remoteIp;
        std::atomic<bool> open{true};
        std::chrono::steady_clock::time_point lastActivity{std::chrono::steady_clock::now()};
        bool lastBinary{false};
    };

    using CrowApp = crow::App<PathGuardMiddleware>;

private:
    void launchHttpServ();
    void setupHttpRoutes(const std::vector<std::string>& uri, const std::string& uriFileDownload, const std::string& downloadFolder);
    void setupWebSocketRoutes(const std::vector<std::string>& wsUris);
    void startWebSocketMaintenance();
    void stopWebSocketMaintenance();

    int HandleCheckIn(const crow::request& req, crow::response& res);
    int HandleCheckIn(const std::string& requestData, crow::response& res);
    bool processPayload(const std::string& input, std::string& output);

    void registerWebSocket(crow::websocket::connection& conn, const std::string& endpoint);
    void unregisterWebSocket(crow::websocket::connection& conn, const std::string& reason, uint16_t code);
    void forwardWebSocketPayload(crow::websocket::connection& conn, const std::string& payload, bool isBinary);

    std::string m_host;
    int m_port;
        bool m_isHttps;
        nlohmann::json m_listenerConfig;

    CrowApp m_app;
    std::unique_ptr<std::thread> m_httpServ;

    std::atomic<bool> m_stopRequested{false};

    std::unordered_map<crow::websocket::connection*, std::shared_ptr<WebSocketSession>> m_wsSessions;
    std::mutex m_wsMutex;
    std::unique_ptr<std::thread> m_wsMaintenanceThread;
    std::chrono::seconds m_wsIdleTimeout{std::chrono::seconds{0}};
    std::chrono::seconds m_wsPingInterval{std::chrono::seconds{15}};
    uint64_t m_wsMaxMessageSize{1024 * 1024};
};
