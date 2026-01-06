#define CROW_ENABLE_SSL
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
        if(m_app)
                m_app->stop();

        if(m_httpServ && m_httpServ->joinable())
                m_httpServ->join();

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("{} listener stopped on {}:{}", m_isHttps ? "HTTPS" : "HTTP", m_host, m_port);
#endif
}


void ListenerHttp::launchHttpServ()
{
        crow::App<PathGuardMiddleware> app;

        json uri = json::array();
        std::string uriFileDownload = m_listenerConfig.value("uriFileDownload", std::string{});
        std::string downloadFolder = m_listenerConfig.value("downloadFolder", std::string{});
        
        
        if (auto itUri = m_listenerConfig.find("uri"); itUri != m_listenerConfig.end() && itUri->is_array())
        {
                for (const auto& value : *itUri)
                {
                        if (value.is_string())
                                m_uris.emplace_back(value.get<std::string>());
                }
        }

        if (auto itWs = m_listenerConfig.find("wsUri"); itWs != m_listenerConfig.end() && itWs->is_array())
        {
                for (const auto& value : *itWs)
                {
                        if (value.is_string())
                                m_wsUris.emplace_back(value.get<std::string>());
                }
        }

        m_wsMaxMessageSize = m_listenerConfig.value("wsMaxMessageSize", static_cast<uint64_t>(1024 * 1024));

        auto guardConfig = std::make_shared<PathGuardConfig>();
        guardConfig->uris = m_uris;
        guardConfig->wsUris = m_wsUris;
        guardConfig->downloadPrefix = uriFileDownload;
        app.get_middleware<PathGuardMiddleware>().setConfig(guardConfig);

#ifdef BUILD_TEAMSERVER
        if(m_logger)
        {
                if(!uriFileDownload.empty())
                        m_logger->info("File download endpoint: {}", uriFileDownload);
                if(!downloadFolder.empty())
                        m_logger->info("Download folder: {}", downloadFolder);
                for (const auto& value : m_uris)
                        m_logger->info("Registered URI: {}", value);
                for (const auto& value : m_wsUris)
                        m_logger->info("Registered WS URI: {}", value);
        }
#endif

        // Post handle
        for (const auto& endpointStr : m_uris)
        {
                app.route_dynamic(endpointStr).methods(crow::HTTPMethod::Post)([this](const crow::request& req, crow::response& res)
                {
                        try
                        {
#ifdef BUILD_TEAMSERVER
                                if(m_logger && m_logger->should_log(spdlog::level::debug))
                                        m_logger->debug("Post connection: {}", req.url);
#endif
                                
                                HandleCheckIn(req, res);
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

        // File Server
        if (!uriFileDownload.empty())
        {
                // Ensure exactly one slash between base and param
                std::string fileDownloadReg = uriFileDownload;
                if (!fileDownloadReg.empty() && fileDownloadReg.back() != '/')
                        fileDownloadReg += '/';

                // Capture filename from the path
                fileDownloadReg += "<string>";

                app.route_dynamic(fileDownloadReg)
                        .methods(crow::HTTPMethod::Get)
                        ([this, downloadFolder](const crow::request& req,
                                                crow::response& res,
                                                std::string filename)   // <-- this is the <string>
                        {
                        const bool deleteFile = (req.headers.find("OneTimeDownload") != req.headers.end());

#ifdef BUILD_TEAMSERVER
                        if (m_logger && m_logger->should_log(spdlog::level::debug))
                                m_logger->info("File server connection: {}, OneTimeDownload {}, filename={}",
                                        req.url, deleteFile, filename);
#endif

                        // DO NOT redeclare `filename` and DO NOT use req.url_params for path params.
                        // `filename` is already populated from "<string>".

                        std::string filePath = downloadFolder;
                        if (!filePath.empty() && filePath.back() != '/')
                                filePath += '/';
                        filePath += filename;

                        std::ifstream file(filePath, std::ios::binary);
                        if (file)
                        {
                                std::string buffer((std::istreambuf_iterator<char>(file)),
                                                std::istreambuf_iterator<char>());

#ifdef BUILD_TEAMSERVER
                                if (m_logger)
                                {
                                std::string md5 = computeBufferMd5(buffer);
                                m_logger->info("File served: '{}' | size={} bytes | MD5={}",
                                                filePath, buffer.size(), md5);
                                }
#endif

                                res.code = 200;
                                res.add_header("Content-Type", "application/x-binary");
                                res.body = std::move(buffer);
                                res.end();

                                if (deleteFile)
                                {
#ifdef BUILD_TEAMSERVER
                                if (m_logger)
                                        m_logger->info("Delete file {}", filePath);
#endif
                                std::remove(filePath.c_str());
                                }
                        }
                        else
                        {
#ifdef BUILD_TEAMSERVER
                                if (m_logger)
                                m_logger->warn("File server: File not found at {}", filePath);
#endif
                                res.code = 404;
                                res.end();
                        }
                        });
        }       

        // websockets
        app.websocket_max_payload(m_wsMaxMessageSize);

        for (const auto& endpoint : m_wsUris)
        {
                app.route_dynamic(endpoint)
                        .websocket(&app)
                        .onopen([this](crow::websocket::connection& conn)
                        {
                                m_logger->info("Websocket server: new connection");
                                registerWebSocket(conn);
                        })
                        .onclose([this](crow::websocket::connection& conn, const std::string& reason, uint16_t code)
                        {
                                m_logger->info("Websocket server: closed connection");
                                unregisterWebSocket(conn, reason, code);
                        })
                        .onmessage([this](crow::websocket::connection& conn, const std::string& data, bool isBinary)
                        {
                                forwardWebSocketPayload(conn, data, isBinary);
                        });
        }

        try
        {
                m_app = &app;
                auto& _app_ = app.port(static_cast<uint16_t>(m_port)).bindaddr(m_host).concurrency(1);

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
                        _app_.ssl_file(servCrtFile, servKeyFile);
                }
                else
                {
                        // nothing to configure
                }
                
                _app_.run();
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

        if (isBinary)
                conn.send_binary(output);
        else
                conn.send_text(output);
}
