#include "ListenerHttp.hpp"

using namespace std;
using namespace httplib;
using json = nlohmann::json;


ListenerHttp::ListenerHttp(const std::string& ip, int localPort, const nlohmann::json& config, bool isHttps)
	: Listener(ip, std::to_string(localPort), (isHttps==true) ? ListenerHttpsType : ListenerHttpType)
	, m_isHttps(isHttps)
	, m_config(config)
{	
	m_host=ip;
	m_port=localPort;

	std::string type;
	if(isHttps)
		type = ListenerHttpsType;
	else
		type = ListenerHttpType;

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
	console_sink->set_level(spdlog::level::info);
    sinks.push_back(console_sink);


	auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/Listener_"+type+"_"+std::to_string(localPort)+"_"+m_listenerHash+".txt", 1024*1024*10, 3);
	file_sink->set_level(spdlog::level::debug);
	sinks.push_back(file_sink);

    m_logger = std::make_shared<spdlog::logger>("Listener_"+type+"_"+std::to_string(localPort)+"_"+m_listenerHash.substr(0,8), begin(sinks), end(sinks));
	m_logger->set_level(spdlog::level::debug);
#endif
}


int ListenerHttp::init()
{
	try
	{
		if(m_isHttps)
		{
			std::string servCrtFile = m_config["ServHttpsListenerCrtFile"].get<std::string>();
			std::string servKeyFile = m_config["ServHttpsListenerKeyFile"].get<std::string>();
			m_svr = std::make_unique<httplib::SSLServer>(servCrtFile.c_str(), servKeyFile.c_str());
		}
		else
			m_svr = std::make_unique<httplib::Server>();
	}
	catch (const json::out_of_range)
	{
		return -1;
	}		

	this->m_httpServ = std::make_unique<std::thread>(&ListenerHttp::launchHttpServ, this);

	return 1;
}

ListenerHttp::~ListenerHttp()
{
	m_svr->stop();
	m_httpServ->join();

#ifdef BUILD_TEAMSERVER
		m_logger->info("Server stoped on port {0}", m_port);
#endif
}


void ListenerHttp::launchHttpServ()
{
	httplib::Response res;

	json uri;
	std::string uriFileDownload;
	std::string downloadFolder;
	try
	{
		uri = m_config["uri"];

		auto it = m_config.find("uriFileDownload");
		if(it != m_config.end())
			uriFileDownload = m_config["uriFileDownload"].get<std::string>();;

		it = m_config.find("downloadFolder");
		if(it != m_config.end())
			downloadFolder = m_config["downloadFolder"].get<std::string>();;

#ifdef BUILD_TEAMSERVER
		m_logger->info("uriFileDownload {0}", uriFileDownload);
		m_logger->info("downloadFolder {0}", downloadFolder);
#endif

		for (json::iterator it = uri.begin(); it != uri.end(); ++it)
		{
			std::string uriTmp = *it;
#ifdef BUILD_TEAMSERVER
			m_logger->info("uri {0}", uriTmp);
#endif
		}
	}
	catch (const json::out_of_range)
	{
#ifdef BUILD_TEAMSERVER
		m_logger->critical("No uri in config.");
#endif
		return;
	}

	// Filter to match the URI of the config file or the file download URI
	m_svr->set_post_routing_handler([&](const auto& req, auto& res) 
	{
		bool isUri = false;
		for (json::iterator it = uri.begin(); it != uri.end(); ++it)
			if(req.path ==std::string(*it))
				isUri=true;

		if (req.path.find(uriFileDownload) != std::string::npos) 
			isUri=true;

		if ( isUri ) 
		{
			return Server::HandlerResponse::Unhandled;
		}
		else
		{
#ifdef BUILD_TEAMSERVER
			m_logger->info("Unauthorized connection {0}", req.path);
#endif
			res.status = 401;
			return Server::HandlerResponse::Handled;
		}
	});

	// Post handle
	for (json::iterator it = uri.begin(); it != uri.end(); ++it)
		m_svr->Post(*it, [&](const auto& req, auto& res)
		{
			try 
			{
#ifdef BUILD_TEAMSERVER
				m_logger->trace("Post connection: {0}", req.path);
#endif
				this->HandleCheckIn(req, res);
				res.status = 200;
			} 
			catch(const std::exception& ex)
			{
#ifdef BUILD_TEAMSERVER
				m_logger->warn("Execption {0}", ex.what());
#endif
				res.status = 401;
			}
			catch (...) 
			{
#ifdef BUILD_TEAMSERVER
				m_logger->warn("Unknown failure occurred.");
#endif
				res.status = 401;
			}
		});

	// Get handle
	for (json::iterator it = uri.begin(); it != uri.end(); ++it)
		m_svr->Get(*it, [&](const auto& req, auto& res)
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
						m_logger->info("Get: invalide JWT");
#endif
						res.status = 401;
					}
				}
				else
				{
#ifdef BUILD_TEAMSERVER
					m_logger->info("Get: no Authorization header");
#endif
					res.status = 401;
				}
			} 
			catch(const std::exception& ex)
			{
#ifdef BUILD_TEAMSERVER
				m_logger->warn("Execption {0}", ex.what());
#endif
				res.status = 401;
			}
			catch (...) 
			{
#ifdef BUILD_TEAMSERVER
				m_logger->warn("Unknown failure occurred.");
#endif
				res.status = 401;
			}
		});

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
			m_logger->info("File server connection: {0}, OneTimeDownload {1}", req.path, deleteFile);
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

				res.set_content(buffer, "application/x-binary");

				file.close();
				if(deleteFile)
				{
#ifdef BUILD_TEAMSERVER
					m_logger->info("Delete file {0}", filePath);
#endif
					// std::string backUpFile = filePath+".DELETED";
					// std::rename(filePath.data(), backUpFile.data());
					std::remove(filePath.data());
				}
			} 
			else 
			{
#ifdef BUILD_TEAMSERVER
				m_logger->info("File server: File not found.");
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
	m_logger->trace("m_isHttps {0}", std::to_string(m_isHttps));
	m_logger->trace("input.size {0}", std::to_string(input.size()));
#endif

	string output;
	bool ret = handleMessages(input, output);


	json httpHeaders;
	try
	{
		httpHeaders = m_config["server"]["headers"];
	}
	catch (const json::out_of_range)
	{
#ifdef BUILD_TEAMSERVER
		m_logger->error("No server headers in config.");
#endif
		return -1;
	}

	httplib::Headers httpServerHeaders;
	for (auto& it : httpHeaders.items())
		httpServerHeaders.insert({(it).key(), (it).value()});
	res.headers = httpServerHeaders;

#ifdef BUILD_TEAMSERVER
	m_logger->trace("output.size {0}", std::to_string(output.size()));
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
	m_logger->trace("m_isHttps {0}", std::to_string(m_isHttps));
	m_logger->trace("requestData.size {0}", std::to_string(requestData.size()));
#endif

	string output;
	bool ret = handleMessages(requestData, output);


	json httpHeaders;
	try
	{
		httpHeaders = m_config["server"]["headers"];
	}
	catch (const json::out_of_range)
	{
#ifdef BUILD_TEAMSERVER
		m_logger->error("No server headers in config.");
#endif
		return -1;
	}

	httplib::Headers httpServerHeaders;
	for (auto& it : httpHeaders.items())
		httpServerHeaders.insert({(it).key(), (it).value()});
	res.headers = httpServerHeaders;

#ifdef BUILD_TEAMSERVER
	m_logger->trace("output.size {0}", std::to_string(output.size()));
#endif

	if(ret)
		res.body = output;
	else
		res.status = 200;

	return 0;
}
