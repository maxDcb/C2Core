#include "ListenerHttp.hpp"
#include <openssl/md5.h>

using namespace std;
using namespace httplib;
using json = nlohmann::json;


static std::string computeBufferMd5(const std::string& buffer)
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
                        m_svr = std::make_unique<httplib::Server>();
        }
        catch (const std::exception& ex)
        {
#ifdef BUILD_TEAMSERVER
                if(m_logger)
                        m_logger->error("Failed to initialize {} listener: {}", m_isHttps ? "HTTPS" : "HTTP", ex.what());
#endif
                return -1;
        }

        this->m_httpServ = std::make_unique<std::thread>(&ListenerHttp::launchHttpServ, this);

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


void ListenerHttp::launchHttpServ()
{
	httplib::Response res;

        json uri = json::array();
        std::string uriFileDownload = m_listenerConfig.value("uriFileDownload", std::string{});
        std::string downloadFolder = m_listenerConfig.value("downloadFolder", std::string{});

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

#ifdef BUILD_TEAMSERVER
        if(m_logger)
        {
                if(!uriFileDownload.empty())
                        m_logger->debug("File download endpoint: {}", uriFileDownload);
                if(!downloadFolder.empty())
                        m_logger->debug("Download folder: {}", downloadFolder);
                for (const auto& value : uri)
                {
                        if(value.is_string())
                                m_logger->debug("Registered URI: {}", value.get<std::string>());
                }
        }
#endif

	// Filter to match the URI of the config file or the file download URI
        m_svr->set_post_routing_handler([&, uriFileDownload](const auto& req, auto& res)
        {
                bool isUri = false;
                for (const auto& value : uri)
                {
                        if(value.is_string() && req.path == value.get<std::string>())
                        {
                                isUri=true;
                                break;
                        }
                }

                if (!uriFileDownload.empty() && req.path.find(uriFileDownload) != std::string::npos)
                        isUri=true;

                if ( isUri )
                {
                        return Server::HandlerResponse::Unhandled;
                }
                else
                {
#ifdef BUILD_TEAMSERVER
                        if(m_logger)
                                m_logger->warn("Unauthorized connection {}", req.path);
#endif
                        res.status = 401;
                        return Server::HandlerResponse::Handled;
                }
        });

        // Post handle
        for (const auto& endpoint : uri)
        {
                if(!endpoint.is_string())
                        continue;
                const std::string endpointStr = endpoint.get<std::string>();
                m_svr->Post(endpointStr, [&](const auto& req, auto& res)
                {
                        try
                        {
#ifdef BUILD_TEAMSERVER
                                if(m_logger && m_logger->should_log(spdlog::level::debug))
                                        m_logger->debug("Post connection: {}", req.path);
#endif
                                this->HandleCheckIn(req, res);
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
        }

        // Get handle
        for (const auto& endpoint : uri)
        {
                if(!endpoint.is_string())
                        continue;
                const std::string endpointStr = endpoint.get<std::string>();
                m_svr->Get(endpointStr, [&](const auto& req, auto& res)
                {
                        try
                        {
#ifdef BUILD_TEAMSERVER
                                // m_logger->info("Get connection: {0}", req.path);
#endif
				if (req.has_header("Authorization")) 
				{
					// jwt should contained Bearer b64data.b6data.beaconData
					std::string jwt = req.get_header_value("Authorization");

					std::string data;
					char delimiter = '.';
					size_t pos = jwt.find_last_of(delimiter);
					if (pos != std::string::npos) 
						data = jwt.substr(pos + 1);

                                        if(!data.empty())
                                        {
                                                this->HandleCheckIn(data, res);
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

	// File Server
	if(!uriFileDownload.empty())
	{
		std::string fileDownloadReg = uriFileDownload;
		fileDownloadReg+=":filename";
		m_svr->Get(fileDownloadReg, [&](const Request& req, Response& res) 
		{
			bool deleteFile=false;
			auto it = req.headers.find("OneTimeDownload");
			if (it != req.headers.end()) 
			{
				std::string header_value = it->second;
				deleteFile=true;
			} 

#ifdef BUILD_TEAMSERVER
                        if(m_logger && m_logger->should_log(spdlog::level::debug))
                                m_logger->debug("File server connection: {}, OneTimeDownload {}", req.path, deleteFile);
#endif

			std::string filename = req.path_params.at("filename");
			std::string filePath = downloadFolder;
			filePath+="/";
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

				res.set_content(buffer, "application/x-binary");

				file.close();
				if(deleteFile)
				{
#ifdef BUILD_TEAMSERVER
                                        if(m_logger)
                                                m_logger->info("Delete file {}", filePath);
#endif
					// std::string backUpFile = filePath+".DELETED";
					// std::rename(filePath.data(), backUpFile.data());
					std::remove(filePath.data());
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

	m_svr->listen(m_host.c_str(), m_port);
}


int ListenerHttp::HandleCheckIn(const httplib::Request& req, httplib::Response& res)
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

	httplib::Headers httpServerHeaders;
	for (auto& it : httpHeaders.items())
		httpServerHeaders.insert({(it).key(), (it).value()});
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

	httplib::Headers httpServerHeaders;
	for (auto& it : httpHeaders.items())
		httpServerHeaders.insert({(it).key(), (it).value()});
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
