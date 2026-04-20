#include "ListenerHttp.hpp"

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <openssl/md5.h>
#include <sstream>

using namespace std;
using namespace httplib;
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

ListenerHttp::ListenerHttp(const std::string& ip, int localPort, const nlohmann::json& config, bool isHttps)
    : Listener(ip, std::to_string(localPort), (isHttps==true) ? ListenerHttpsType : ListenerHttpType)
    , m_isHttps(isHttps)
    , m_listenerConfig(nlohmann::json::object())
    , m_wsMaxMessageSize(1024 * 1024)
{
    m_host = ip;
    m_port = localPort;

    std::string type = isHttps ? ListenerHttpsType : ListenerHttpType;
    const std::string configKey = isHttps ? "ListenerHttpsConfig" : "ListenerHttpConfig";
    auto itConfig = config.find(configKey);
    if(itConfig != config.end() && itConfig->is_object())
        m_listenerConfig = *itConfig;

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

    m_uriFileDownload = m_listenerConfig.value("uriFileDownload", std::string{});
    m_downloadFolder = m_listenerConfig.value("downloadFolder", std::string{});
    m_wsMaxMessageSize = m_listenerConfig.value("wsMaxMessageSize", static_cast<std::size_t>(1024 * 1024));

    m_listenerHash = random_string(SizeListenerHash);

    json metadata;
    metadata["1"] = type;
    metadata["2"] = m_host;
    metadata["3"] = std::to_string(m_port);
    m_metadata = metadata.dump();

#ifdef BUILD_TEAMSERVER
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
        if(m_isHttps)
        {
            std::string servCrtFile = m_listenerConfig.value("ServHttpsListenerCrtFile", std::string{});
            std::string servKeyFile = m_listenerConfig.value("ServHttpsListenerKeyFile", std::string{});
            if(servCrtFile.empty() || servKeyFile.empty())
            {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                    m_logger->error("Missing HTTPS certificate configuration for listener on {}:{}", m_host, m_port);
#endif
                return -1;
            }
            m_svr = std::make_unique<httplib::SSLServer>(servCrtFile.c_str(), servKeyFile.c_str());
        }
        else
        {
            m_svr = std::make_unique<httplib::Server>();
        }
    }
    catch (const std::exception& ex)
    {
#ifdef BUILD_TEAMSERVER
        if(m_logger)
            m_logger->error("Failed to initialize {} listener: {}", m_isHttps ? "HTTPS" : "HTTP", ex.what());
#endif
        return -1;
    }

    m_httpServ = std::make_unique<std::thread>(&ListenerHttp::launchHttpServ, this);

#ifdef BUILD_TEAMSERVER
    if(m_logger)
        m_logger->info("{} listener started on {}:{}", m_isHttps ? "HTTPS" : "HTTP", m_host, m_port);
#endif

    return 1;
}

ListenerHttp::~ListenerHttp()
{
    if(m_svr)
        m_svr->stop();
    if(m_httpServ && m_httpServ->joinable())
        m_httpServ->join();

#ifdef BUILD_TEAMSERVER
    if(m_logger)
        m_logger->info("{} listener stopped on {}:{}", m_isHttps ? "HTTPS" : "HTTP", m_host, m_port);
#endif
}

bool ListenerHttp::isAllowedPath(const std::string& path) const
{
    for (const auto& value : m_uris)
    {
        if (path == value)
            return true;
    }

    for (const auto& value : m_wsUris)
    {
        if (path == value)
            return true;
    }

    if (!m_uriFileDownload.empty() && path.find(m_uriFileDownload) != std::string::npos)
        return true;

    return false;
}

void ListenerHttp::launchHttpServ()
{
    if (!m_svr)
        return;

#ifdef BUILD_TEAMSERVER
    if(m_logger)
    {
        if(!m_uriFileDownload.empty())
            m_logger->debug("File download endpoint: {}", m_uriFileDownload);
        if(!m_downloadFolder.empty())
            m_logger->debug("Download folder: {}", m_downloadFolder);
        for (const auto& value : m_uris)
            m_logger->debug("Registered URI: {}", value);
        for (const auto& value : m_wsUris)
            m_logger->debug("Registered WS URI: {}", value);
    }
#endif

    m_svr->set_pre_routing_handler([this](const Request& req, Response& res)
    {
        if (isAllowedPath(req.path))
            return Server::HandlerResponse::Unhandled;

#ifdef BUILD_TEAMSERVER
        if(m_logger)
            m_logger->warn("Unauthorized connection {}", req.path);
#endif
        res.status = 401;
        return Server::HandlerResponse::Handled;
    });

    for (const auto& endpoint : m_uris)
    {
        m_svr->Post(endpoint, [this](const Request& req, Response& res)
        {
            try
            {
#ifdef BUILD_TEAMSERVER
                if(m_logger && m_logger->should_log(spdlog::level::debug))
                    m_logger->debug("Post connection: {}", req.path);
#endif
                HandleCheckIn(req, res);
                if (res.status <= 0)
                    res.status = 200;
            }
            catch(const std::exception& ex)
            {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                    m_logger->warn("Exception while handling POST {}: {}", req.path, ex.what());
#endif
                res.status = 401;
            }
            catch (...)
            {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                    m_logger->warn("Unknown failure occurred while handling POST {}", req.path);
#endif
                res.status = 401;
            }
        });

        m_svr->Get(endpoint, [this](const Request& req, Response& res)
        {
            try
            {
                if (req.has_header("Authorization"))
                {
                    std::string jwt = req.get_header_value("Authorization");
                    std::string data;
                    size_t pos = jwt.find_last_of('.');
                    if (pos != std::string::npos)
                        data = jwt.substr(pos + 1);

                    if(!data.empty())
                    {
                        HandleCheckIn(data, res);
                        if (res.status <= 0)
                            res.status = 200;
                    }
                    else
                    {
#ifdef BUILD_TEAMSERVER
                        if(m_logger)
                            m_logger->warn("Get: invalid JWT provided");
#endif
                        res.status = 401;
                    }
                }
                else
                {
#ifdef BUILD_TEAMSERVER
                    if(m_logger)
                        m_logger->warn("Get: no Authorization header");
#endif
                    res.status = 401;
                }
            }
            catch(const std::exception& ex)
            {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                    m_logger->warn("Exception while handling GET {}: {}", req.path, ex.what());
#endif
                res.status = 401;
            }
            catch (...)
            {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                    m_logger->warn("Unknown failure occurred while handling GET {}", req.path);
#endif
                res.status = 401;
            }
        });
    }

    if(!m_uriFileDownload.empty())
    {
        std::string fileDownloadReg = m_uriFileDownload;
        fileDownloadReg += ":filename";
        m_svr->Get(fileDownloadReg, [this](const Request& req, Response& res)
        {
            bool deleteFile = req.headers.find("OneTimeDownload") != req.headers.end();

#ifdef BUILD_TEAMSERVER
            if(m_logger && m_logger->should_log(spdlog::level::debug))
                m_logger->debug("File server connection: {}, OneTimeDownload {}", req.path, deleteFile);
#endif

            std::string filename = req.path_params.at("filename");
            std::string filePath = m_downloadFolder;
            filePath += "/";
            filePath += filename;
            std::ifstream file(filePath, std::ios::binary);

            if (file)
            {
                std::string buffer;
                buffer.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());

#ifdef BUILD_TEAMSERVER
                if (m_logger)
                {
                    std::string md5 = computeBufferMd5(buffer);
                    m_logger->info("File served: '{}' | size={} bytes | MD5={}", filePath, buffer.size(), md5);
                }
#endif

                res.set_content(buffer, "application/x-binary");

                file.close();
                if(deleteFile)
                {
#ifdef BUILD_TEAMSERVER
                    if(m_logger)
                        m_logger->info("Delete file {}", filePath);
#endif
                    std::remove(filePath.c_str());
                }
            }
            else
            {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                    m_logger->warn("File server: File not found at {}", filePath);
#endif
                res.status = 404;
            }
        });
    }

    for (const auto& endpoint : m_wsUris)
    {
        m_svr->WebSocket(endpoint, [this, endpoint](const Request& req, httplib::ws::WebSocket& ws)
        {
#ifdef BUILD_TEAMSERVER
            if (m_logger)
                m_logger->info("WebSocket connection opened on {} from {}", endpoint, req.remote_addr);
#endif
            std::string input;
            while (true)
            {
                const auto readResult = ws.read(input);
                if (readResult == httplib::ws::Fail)
                    break;

                if (input.size() > m_wsMaxMessageSize)
                {
#ifdef BUILD_TEAMSERVER
                    if (m_logger)
                        m_logger->warn("WebSocket payload exceeded configured limit on {} ({} bytes)", endpoint, input.size());
#endif
                    ws.close(httplib::ws::CloseStatus::MessageTooBig, "payload too large");
                    break;
                }

                httplib::Response res;
                HandleCheckIn(input, res);

                if (res.body.size() > m_wsMaxMessageSize)
                {
#ifdef BUILD_TEAMSERVER
                    if (m_logger)
                        m_logger->warn("WebSocket response exceeded configured limit on {} ({} bytes)", endpoint, res.body.size());
#endif
                    ws.close(httplib::ws::CloseStatus::MessageTooBig, "response too large");
                    break;
                }

                if (readResult == httplib::ws::Binary)
                    ws.send(res.body.data(), res.body.size());
                else
                    ws.send(res.body);
            }

#ifdef BUILD_TEAMSERVER
            if (m_logger)
                m_logger->info("WebSocket connection closed on {} from {}", endpoint, req.remote_addr);
#endif
        });
    }

    m_svr->listen(m_host.c_str(), m_port);
}

bool ListenerHttp::processPayload(const std::string& requestData, std::string& responseData)
{
#ifdef BUILD_TEAMSERVER
    if(m_logger)
    {
        m_logger->trace("m_isHttps {}", std::to_string(m_isHttps));
        m_logger->trace("requestData.size {}", std::to_string(requestData.size()));
    }
#endif

    bool ret = handleMessages(requestData, responseData);

#ifdef BUILD_TEAMSERVER
    if(m_logger)
        m_logger->trace("output.size {}", std::to_string(responseData.size()));
#endif

    return ret;
}

int ListenerHttp::HandleCheckIn(const httplib::Request& req, httplib::Response& res)
{
#ifdef BUILD_TEAMSERVER
    if(m_logger)
    {
        m_logger->trace("m_isHttps {}", std::to_string(m_isHttps));
        m_logger->trace("input.size {}", std::to_string(req.body.size()));
    }
#endif

    std::string output;
    bool ret = handleMessages(req.body, output);

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

    httplib::Headers httpServerHeaders;
    for (auto& it : httpHeaders.items())
        httpServerHeaders.insert({it.key(), it.value()});
    res.headers = httpServerHeaders;

#ifdef BUILD_TEAMSERVER
    if(m_logger)
        m_logger->trace("output.size {}", std::to_string(output.size()));
#endif

    if(ret)
        res.body = output;
    else
        res.status = 200;

    return 0;
}

int ListenerHttp::HandleCheckIn(const std::string& requestData, httplib::Response& res)
{
    std::string output;
    bool ret = processPayload(requestData, output);

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

    httplib::Headers httpServerHeaders;
    for (auto& it : httpHeaders.items())
        httpServerHeaders.insert({it.key(), it.value()});
    res.headers = httpServerHeaders;

    if(ret)
        res.body = output;
    else
        res.status = 200;

    return 0;
}
