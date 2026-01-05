#include "ListenerHttp.hpp"

#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstdio>

#include <openssl/md5.h>

using namespace std;
using json = nlohmann::json;

namespace
{
std::string computeBufferMd5(const std::string& buffer)
{
        if (buffer.empty()) return "";

        unsigned char result[MD5_DIGEST_LENGTH];
        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx, buffer.data(), buffer.size());
        MD5_Final(result, &ctx);

        std::ostringstream oss;
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];

        return oss.str();
}
} // namespace


void ListenerHttp::PathGuardMiddleware::before_handle(crow::request& req, crow::response& res, context&)
{
        if (!m_config)
                return;

        const std::string& path = req.url;
        bool isUri = false;

        for (const auto& value : m_config->uris)
        {
                if (path == value)
                {
                        isUri = true;
                        break;
                }
        }

        if (!isUri && !m_config->downloadPrefix.empty() && path.find(m_config->downloadPrefix) != std::string::npos)
                isUri = true;

        if (!isUri)
        {
                for (const auto& wsUri : m_config->wsUris)
                {
                        if (path == wsUri)
                        {
                                isUri = true;
                                break;
                        }
                }
        }

        if (!isUri)
        {
                res.code = 401;
                res.end();
        }
}


ListenerHttp::ListenerHttp(const std::string& ip, int localPort, const nlohmann::json& config, bool isHttps)
        : Listener(ip, std::to_string(localPort), (isHttps==true) ? ListenerHttpsType : ListenerHttpType)
        , m_isHttps(isHttps)
        , m_listenerConfig(nlohmann::json::object())
{
        m_host=ip;
        m_port=localPort;

        std::string type;
        if(isHttps)
                type = ListenerHttpsType;
        else
                type = ListenerHttpType;

        const std::string configKey = isHttps ? "ListenerHttpsConfig" : "ListenerHttpConfig";
        auto itConfig = config.find(configKey);
        if(itConfig != config.end() && itConfig->is_object())
                m_listenerConfig = *itConfig;

        m_listenerHash = random_string(SizeListenerHash);

        json metadata;
    metadata["1"] = type;
    metadata["2"] = m_host;
    metadata["3"] = std::to_string(m_port);
        m_metadata = metadata.dump();

#ifdef BUILD_TEAMSERVER
        // Logger
        std::vector<spdlog::sink_ptr> sinks;

        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto logLevel = resolveLogLevel(config, &m_listenerConfig);
        console_sink->set_level(logLevel);
    sinks.push_back(console_sink);


        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/Listener_"+type+"_"+std::to_string(localPort)+"_"+m_listenerHash+".txt", 1024*1024*10, 3);
        file_sink->set_level(spdlog::level::trace);
        sinks.push_back(file_sink);

    m_logger = std::make_shared<spdlog::logger>("Listener_"+type+"_"+std::to_string(localPort)+"_"+m_listenerHash.substr(0,8), begin(sinks), end(sinks));
        m_logger->set_level(logLevel);
        m_logger->info("Initializing {} listener on {}:{}", type, m_host, m_port);
#endif

        // Configure middleware guard
        auto guardConfig = std::make_shared<PathGuardConfig>();
        m_app.get_middleware<PathGuardMiddleware>().setConfig(guardConfig);
}


int ListenerHttp::init()
{
        try
        {
                m_httpServ = std::make_unique<std::thread>(&ListenerHttp::launchHttpServ, this);
        }
        catch (const std::exception& ex)
        {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                        m_logger->error("Failed to initialize {} listener: {}", m_isHttps ? "HTTPS" : "HTTP", ex.what());
#endif
                return -1;
        }

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("{} listener started on {}:{}", m_isHttps ? "HTTPS" : "HTTP", m_host, m_port);
#endif

        return 1;
}

ListenerHttp::~ListenerHttp()
{
        m_stopRequested = true;
        stopWebSocketMaintenance();
        m_app.stop();

        if(m_httpServ && m_httpServ->joinable())
                m_httpServ->join();

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("{} listener stopped on {}:{}", m_isHttps ? "HTTPS" : "HTTP", m_host, m_port);
#endif
}


void ListenerHttp::launchHttpServ()
{
        json uri = json::array();
        std::string uriFileDownload = m_listenerConfig.value("uriFileDownload", std::string{});
        std::string downloadFolder = m_listenerConfig.value("downloadFolder", std::string{});
        std::vector<std::string> wsUris;

        auto itUri = m_listenerConfig.find("uri");
        if(itUri == m_listenerConfig.end() || !itUri->is_array())
        {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                        m_logger->error("No URI configured for {} listener on {}:{}", m_isHttps ? "HTTPS" : "HTTP", m_host, m_port);
#endif
                return;
        }
        uri = *itUri;

        if (auto itWs = m_listenerConfig.find("wsUri"); itWs != m_listenerConfig.end() && itWs->is_array())
        {
                for (const auto& value : *itWs)
                {
                        if (value.is_string())
                                wsUris.emplace_back(value.get<std::string>());
                }
        }

        m_wsMaxMessageSize = m_listenerConfig.value("wsMaxMessageSize", static_cast<uint64_t>(1024 * 1024));
        auto wsIdleTimeoutSec = m_listenerConfig.value("wsIdleTimeoutSec", 0);
        if (wsIdleTimeoutSec > 0)
                m_wsIdleTimeout = std::chrono::seconds(wsIdleTimeoutSec);

        auto guardConfig = std::make_shared<PathGuardConfig>();
        guardConfig->uris.clear();
        for (const auto& value : uri)
        {
                if (value.is_string())
                        guardConfig->uris.emplace_back(value.get<std::string>());
        }
        guardConfig->wsUris = wsUris;
        guardConfig->downloadPrefix = uriFileDownload;
        m_app.get_middleware<PathGuardMiddleware>().setConfig(guardConfig);

#ifdef BUILD_TEAMSERVER
        if(m_logger)
        {
                if(!uriFileDownload.empty())
                        m_logger->debug("File download endpoint: {}", uriFileDownload);
                if(!downloadFolder.empty())
                        m_logger->debug("Download folder: {}", downloadFolder);
                for (const auto& value : guardConfig->uris)
                        m_logger->debug("Registered URI: {}", value);
                for (const auto& value : wsUris)
                        m_logger->debug("Registered WS URI: {}", value);
        }
#endif

        setupHttpRoutes(guardConfig->uris, uriFileDownload, downloadFolder);
        setupWebSocketRoutes(wsUris);

        m_app.websocket_max_payload(m_wsMaxMessageSize);

        if (wsUris.empty())
                m_wsPingInterval = std::chrono::seconds(0);

        startWebSocketMaintenance();

        try
        {
                auto& app = m_app.port(static_cast<uint16_t>(m_port)).bindaddr(m_host).concurrency(1);

#ifdef CROW_ENABLE_SSL
                if (m_isHttps)
                {
                        std::string servCrtFile = m_listenerConfig.value("ServHttpsListenerCrtFile", std::string{});
                        std::string servKeyFile = m_listenerConfig.value("ServHttpsListenerKeyFile", std::string{});
                        if(servCrtFile.empty() || servKeyFile.empty())
                        {
#ifdef BUILD_TEAMSERVER
                                if(m_logger)
                                        m_logger->error("Missing HTTPS certificate configuration for listener on {}:{}", m_host, m_port);
#endif
                                return;
                        }
                        app.ssl_file(servCrtFile, servKeyFile);
                }
                else
                {
                        // nothing to configure
                }
#else
                if (m_isHttps)
                {
#ifdef BUILD_TEAMSERVER
                        if(m_logger)
                                m_logger->error("HTTPS requested but CROW_ENABLE_SSL is not defined");
#endif
                        return;
                }
#endif

                app.run();
        }
        catch (const std::exception& ex)
        {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                        m_logger->error("Exception while running {} listener: {}", m_isHttps ? "HTTPS" : "HTTP", ex.what());
#endif
        }
        catch (...)
        {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                        m_logger->error("Unknown exception while running {} listener", m_isHttps ? "HTTPS" : "HTTP");
#endif
        }
}


void ListenerHttp::setupHttpRoutes(const std::vector<std::string>& uri, const std::string& uriFileDownload, const std::string& downloadFolder)
{
        // Post handle
        for (const auto& endpointStr : uri)
        {
                m_app.route_dynamic(endpointStr).methods(crow::HTTPMethod::Post)([this](const crow::request& req, crow::response& res)
                {
                        try
                        {
#ifdef BUILD_TEAMSERVER
                                if(m_logger && m_logger->should_log(spdlog::level::debug))
                                        m_logger->debug("Post connection: {}", req.url);
#endif
                                this->HandleCheckIn(req, res);
                                res.code = 200;
                                res.end();
                        }
                        catch(const std::exception& ex)
                        {
#ifdef BUILD_TEAMSERVER
                                if(m_logger)
                                        m_logger->warn("Exception while handling POST {}: {}", req.url, ex.what());
#endif
                                res.code = 401;
                                res.end();
                        }
                        catch (...)
                        {
#ifdef BUILD_TEAMSERVER
                                if(m_logger)
                                        m_logger->warn("Unknown failure occurred while handling POST {}", req.url);
#endif
                                res.code = 401;
                                res.end();
                        }
                });
        }

        // Get handle
        for (const auto& endpointStr : uri)
        {
                m_app.route_dynamic(endpointStr).methods(crow::HTTPMethod::Get)([this](const crow::request& req, crow::response& res)
                {
                        try
                        {
                                auto authIt = req.headers.find("Authorization");
                                if (authIt != req.headers.end())
                                {
                                        std::string jwt = authIt->second;

                                        std::string data;
                                        char delimiter = '.';
                                        size_t pos = jwt.find_last_of(delimiter);
                                        if (pos != std::string::npos)
                                                data = jwt.substr(pos + 1);

                                        if(!data.empty())
                                        {
                                                this->HandleCheckIn(data, res);
                                                res.code = 200;
                                                res.end();
                                        }
                                        else
                                        {
#ifdef BUILD_TEAMSERVER
                                                if(m_logger)
                                                        m_logger->warn("Get: invalid JWT provided");
#endif
                                                res.code = 401;
                                                res.end();
                                        }
                                }
                                else
                                {
#ifdef BUILD_TEAMSERVER
                                        if(m_logger)
                                                m_logger->warn("Get: no Authorization header");
#endif
                                        res.code = 401;
                                        res.end();
                                }
                        }
                        catch(const std::exception& ex)
                        {
#ifdef BUILD_TEAMSERVER
                                if(m_logger)
                                        m_logger->warn("Exception while handling GET {}: {}", req.url, ex.what());
#endif
                                res.code = 401;
                                res.end();
                        }
                        catch (...)
                        {
#ifdef BUILD_TEAMSERVER
                                if(m_logger)
                                        m_logger->warn("Unknown failure occurred while handling GET {}", req.url);
#endif
                                res.code = 401;
                                res.end();
                        }
                });
        }

        // File Server
        if(!uriFileDownload.empty())
        {
                std::string fileDownloadReg = uriFileDownload + "<string>";
                m_app.route_dynamic(fileDownloadReg).methods(crow::HTTPMethod::Get)([this, downloadFolder](const crow::request& req, crow::response& res)
                {
                        bool deleteFile=false;
                        if (req.headers.find("OneTimeDownload") != req.headers.end())
                                deleteFile=true;

#ifdef BUILD_TEAMSERVER
                        if(m_logger && m_logger->should_log(spdlog::level::debug))
                                m_logger->debug("File server connection: {}, OneTimeDownload {}", req.url, deleteFile);
#endif

                        std::string filename;
                        if (!req.url_params.empty())
                                filename = req.url_params.get("1");
                        if (filename.empty() && req.url.size() > 0)
                        {
                                // fallback: extract trailing segment
                                auto pos = req.url.find_last_of('/');
                                if (pos != std::string::npos && pos + 1 < req.url.size())
                                        filename = req.url.substr(pos + 1);
                        }

                        std::string filePath = downloadFolder;
                        if(!filePath.empty() && filePath.back() != '/')
                                filePath += "/";
                        filePath+=filename;
                        std::ifstream file(filePath, std::ios::binary);

                        if (file)
                        {
                                std::string buffer;
                                buffer.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());

#ifdef BUILD_TEAMSERVER
                                std::string md5 = computeBufferMd5(buffer);
                                m_logger->info(
                                        "File served: '{}' | size={} bytes | MD5={}",
                                        filePath,
                                        buffer.size(),
                                        md5
                                );
#endif

                                res.add_header("Content-Type", "application/x-binary");
                                res.body = buffer;

                                file.close();
                                if(deleteFile)
                                {
#ifdef BUILD_TEAMSERVER
                                        if(m_logger)
                                                m_logger->info("Delete file {}", filePath);
#endif
                                        std::remove(filePath.data());
                                }
                        }
                        else
                        {
#ifdef BUILD_TEAMSERVER
                                if(m_logger)
                                        m_logger->warn("File server: File not found at {}", filePath);
#endif
                                res.code = 404;
                        }

                        res.end();
                });
        }
}


void ListenerHttp::setupWebSocketRoutes(const std::vector<std::string>& wsUris)
{
        for (const auto& endpoint : wsUris)
        {
                m_app.websocket(endpoint)
                        .max_payload(m_wsMaxMessageSize)
                        .onopen([this, endpoint](crow::websocket::connection& conn)
                        {
                                registerWebSocket(conn, endpoint);
                        })
                        .onclose([this](crow::websocket::connection& conn, const std::string& reason, uint16_t code)
                        {
                                unregisterWebSocket(conn, reason, code);
                        })
                        .onmessage([this](crow::websocket::connection& conn, const std::string& data, bool isBinary)
                        {
                                forwardWebSocketPayload(conn, data, isBinary);
                        });
        }
}


void ListenerHttp::startWebSocketMaintenance()
{
        if (m_wsIdleTimeout.count() == 0 && m_wsPingInterval.count() == 0)
                return;

        if (m_wsMaintenanceThread)
                return;

        m_wsMaintenanceThread = std::make_unique<std::thread>([this]()
        {
                while (!m_stopRequested)
                {
                        auto waitDuration = m_wsPingInterval.count() > 0 ? m_wsPingInterval : std::chrono::seconds(1);
                        std::this_thread::sleep_for(waitDuration);

                        const auto now = std::chrono::steady_clock::now();
                        std::vector<std::shared_ptr<WebSocketSession>> sessionsCopy;

                        {
                                std::lock_guard<std::mutex> lock(m_wsMutex);
                                for (auto& kv : m_wsSessions)
                                {
                                        if (kv.second)
                                                sessionsCopy.push_back(kv.second);
                                }
                        }

                        for (auto& session : sessionsCopy)
                        {
                                if (!session->open.load())
                                        continue;

                                if (m_wsIdleTimeout.count() > 0)
                                {
                                        auto idle = std::chrono::duration_cast<std::chrono::seconds>(now - session->lastActivity);
                                        if (idle >= m_wsIdleTimeout)
                                        {
                                                session->connection->close("idle timeout");
                                                session->open = false;
                                                continue;
                                        }
                                }

                                if (m_wsPingInterval.count() > 0)
                                {
                                        session->connection->send_ping("");
                                }
                        }
                }
        });
}


void ListenerHttp::stopWebSocketMaintenance()
{
        if (m_wsMaintenanceThread && m_wsMaintenanceThread->joinable())
                m_wsMaintenanceThread->join();
        m_wsMaintenanceThread.reset();
}


int ListenerHttp::HandleCheckIn(const crow::request& req, crow::response& res)
{
    string input = req.body;

#ifdef BUILD_TEAMSERVER
        if(m_logger)
        {
                m_logger->trace("m_isHttps {}", std::to_string(m_isHttps));
                m_logger->trace("input.size {}", std::to_string(input.size()));
        }
#endif

        string output;
        bool ret = handleMessages(input, output);

        json httpHeaders;
        try
        {
                httpHeaders = m_listenerConfig.at("server").at("headers");
        }
        catch (const json::exception& ex)
        {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                        m_logger->error("No server headers in config: {}", ex.what());
#endif
                return -1;
        }

        for (auto& it : httpHeaders.items())
                res.add_header((it).key(), (it).value());

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->trace("output.size {}", std::to_string(output.size()));
#endif

        if(ret)
                res.body = output;

    return 0;
}


int ListenerHttp::HandleCheckIn(const std::string& requestData, crow::response& res)
{
#ifdef BUILD_TEAMSERVER
        if(m_logger)
        {
                m_logger->trace("m_isHttps {}", std::to_string(m_isHttps));
                m_logger->trace("requestData.size {}", std::to_string(requestData.size()));
        }
#endif

        string output;
        bool ret = handleMessages(requestData, output);

        json httpHeaders;
        try
        {
                httpHeaders = m_listenerConfig.at("server").at("headers");
        }
        catch (const json::exception& ex)
        {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                        m_logger->error("No server headers in config: {}", ex.what());
#endif
                return -1;
        }

        for (auto& it : httpHeaders.items())
                res.add_header((it).key(), (it).value());

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->trace("output.size {}", std::to_string(output.size()));
#endif

        if(ret)
                res.body = output;

    return 0;
}


void ListenerHttp::registerWebSocket(crow::websocket::connection& conn, const std::string& endpoint)
{
        auto session = std::make_shared<WebSocketSession>();
        session->connection = &conn;
        session->id = random_string(8);
        session->remoteIp = conn.get_remote_ip();
        session->lastActivity = std::chrono::steady_clock::now();
        session->lastBinary = false;

        {
                std::lock_guard<std::mutex> lock(m_wsMutex);
                m_wsSessions[&conn] = session;
        }

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("WebSocket connection opened on {} from {} (id={})", endpoint, session->remoteIp, session->id);
#endif
}


void ListenerHttp::unregisterWebSocket(crow::websocket::connection& conn, const std::string& reason, uint16_t code)
{
        std::shared_ptr<WebSocketSession> session;
        {
                std::lock_guard<std::mutex> lock(m_wsMutex);
                auto it = m_wsSessions.find(&conn);
                if (it != m_wsSessions.end())
                {
                        session = it->second;
                        m_wsSessions.erase(it);
                }
        }

        if (session)
                session->open = false;

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("WebSocket connection closed (id={}, code={}, reason={})", session ? session->id : "", code, reason);
#endif
}


void ListenerHttp::forwardWebSocketPayload(crow::websocket::connection& conn, const std::string& payload, bool isBinary)
{
        std::shared_ptr<WebSocketSession> session;
        {
                std::lock_guard<std::mutex> lock(m_wsMutex);
                auto it = m_wsSessions.find(&conn);
                if (it != m_wsSessions.end())
                        session = it->second;
        }

        if (!session)
                return;

        session->lastActivity = std::chrono::steady_clock::now();
        session->lastBinary = isBinary;

        std::string output;
        bool ret = handleMessages(payload, output);

        if (ret)
        {
                if (isBinary)
                        conn.send_binary(output);
                else
                        conn.send_text(output);
        }
}
