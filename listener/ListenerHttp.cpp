#include "ListenerHttp.hpp"

using namespace std;
using namespace httplib;
using json = nlohmann::json;


ListenerHttp::ListenerHttp(const std::string& ip, int localPort, const nlohmann::json& config, bool isHttps)
	: Listener(ip, std::to_string(localPort), (isHttps==true) ? ListenerHttpsType : ListenerHttpType)
	, m_isHttps(isHttps)
	, m_config(config)
{	
#ifdef __linux__

	bool isPortInUse = port_in_use(localPort);
	if(isPortInUse)
		throw std::runtime_error("Port Already Used.");
		
#elif _WIN32
#endif

	m_host=ip;
	m_port=localPort;

	m_listenerHash = random_string(SizeListenerHash);
	m_listenerHash += '\x60';
	if(isHttps)
		m_listenerHash += ListenerHttpsType;
	else
		m_listenerHash += ListenerHttpType;
	m_listenerHash += '\x60';
	m_listenerHash += m_hostname;
	m_listenerHash += '\x60';
	m_listenerHash += ip;
	m_listenerHash += '\x60';
	m_listenerHash += std::to_string(localPort);

	if(m_isHttps)
	{
		try
    	{
			std::string servCrtFile = m_config[0]["ServHttpsListenerCrtFile"].get<std::string>();
			std::string servKeyFile = m_config[0]["ServHttpsListenerKeyFile"].get<std::string>();
			m_svr = std::make_unique<httplib::SSLServer>(servCrtFile.c_str(), servKeyFile.c_str());
		}
		catch (const json::out_of_range)
		{
			SPDLOG_CRITICAL("No ServHttpsListenerCrtFile or ServHttpsListenerKeyFile in config.");
			return;
		}		
	}
	else
		m_svr = std::make_unique<httplib::Server>();

	this->m_httpServ = std::make_unique<std::thread>(&ListenerHttp::lauchHttpServ, this);
}


ListenerHttp::~ListenerHttp()
{
	m_svr->stop();
	m_httpServ->join();
}


void ListenerHttp::lauchHttpServ()
{
	httplib::Response res;

	json uri;
	std::string uriFileDownload;
	std::string downloadFolder;
	try
	{
		uri = m_config[0]["uri"];

		auto it = m_config[0].find("uriFileDownload");
		if(it != m_config[0].end())
			uriFileDownload = m_config[0]["uriFileDownload"].get<std::string>();;

		it = m_config[0].find("downloadFolder");
		if(it != m_config[0].end())
			downloadFolder = m_config[0]["downloadFolder"].get<std::string>();;

		SPDLOG_INFO("uriFileDownload {0}", uriFileDownload);
		SPDLOG_INFO("downloadFolder {0}", downloadFolder);
		for (json::iterator it = uri.begin(); it != uri.end(); ++it)
		{
			std::string uriTmp = *it;
			SPDLOG_INFO("uri {0}", uriTmp);
		}
	}
	catch (const json::out_of_range)
	{
		SPDLOG_CRITICAL("No uri in config.");
		return;
	}

	// Filter to match the URI of the config file
	m_svr->set_post_routing_handler([&](const auto& req, auto& res) 
	{
		bool isUri = false;
		for (json::iterator it = uri.begin(); it != uri.end(); ++it)
			if(req.path ==*it)
				isUri=true;

		if (req.path.find(uriFileDownload) != std::string::npos) 
			isUri=true;

		if ( isUri ) 
		{
			return Server::HandlerResponse::Unhandled;
		}
		else
		{
			SPDLOG_INFO("Unauthorized connection {0}", req.path);
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
				// SPDLOG_INFO("Post connection: {0}", req.path);
				this->HandleCheckIn(req, res);
				res.status = 200;
			} 
			catch(const std::exception& ex)
			{
				SPDLOG_INFO("Execption {0}", ex.what());
				res.status = 401;
			}
			catch (...) 
			{
				SPDLOG_INFO("Unknown failure occurred.");
				res.status = 401;
			}
		});

	// Get handle
	for (json::iterator it = uri.begin(); it != uri.end(); ++it)
		m_svr->Get(*it, [&](const auto& req, auto& res)
		{
			try 
			{
				SPDLOG_INFO("Get connection: {0}", req.path);
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
						SPDLOG_INFO("Get: invalide JWT");
						res.status = 401;
					}
				}
				else
				{
					SPDLOG_INFO("Get: no Authorization header");
					res.status = 401;
				}
			} 
			catch(const std::exception& ex)
			{
				SPDLOG_INFO("Execption {0}", ex.what());
				res.status = 401;
			}
			catch (...) 
			{
				SPDLOG_INFO("Unknown failure occurred.");
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
			SPDLOG_INFO("File server connection: {0}", req.path);

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
			} 
			else 
			{
				SPDLOG_INFO("File server: File not found.");
				res.status = 404;
			}
		});
	}

	m_svr->listen(m_host.c_str(), m_port);
}


int ListenerHttp::HandleCheckIn(const httplib::Request& req, httplib::Response& res)
{
	string input = req.body;

	// SPDLOG_TRACE("m_isHttps {0}", std::to_string(m_isHttps));
	// SPDLOG_TRACE("input.size {0}", std::to_string(input.size()));

	string output;
	bool ret = handleMessages(input, output);


	json httpHeaders;
	try
	{
		httpHeaders = m_config[0]["server"][0]["headers"][0];
	}
	catch (const json::out_of_range)
	{
		SPDLOG_CRITICAL("No server headers in config.");
		return -1;
	}

	httplib::Headers httpServerHeaders;
	for (auto& it : httpHeaders.items())
		httpServerHeaders.insert({(it).key(), (it).value()});
	res.headers = httpServerHeaders;

	// SPDLOG_TRACE("output.size {0}", std::to_string(output.size()));

	if(ret)
		res.body = output;
	else
		res.status = 200;

	return 0;
}


int ListenerHttp::HandleCheckIn(const std::string& requestData, httplib::Response& res)
{
	// SPDLOG_TRACE("m_isHttps {0}", std::to_string(m_isHttps));
	// SPDLOG_TRACE("requestData.size {0}", std::to_string(requestData.size()));

	string output;
	bool ret = handleMessages(requestData, output);


	json httpHeaders;
	try
	{
		httpHeaders = m_config[0]["server"][0]["headers"][0];
	}
	catch (const json::out_of_range)
	{
		SPDLOG_CRITICAL("No server headers in config.");
		return -1;
	}

	httplib::Headers httpServerHeaders;
	for (auto& it : httpHeaders.items())
		httpServerHeaders.insert({(it).key(), (it).value()});
	res.headers = httpServerHeaders;

	// SPDLOG_TRACE("output.size {0}", std::to_string(output.size()));

	if(ret)
		res.body = output;
	else
		res.status = 200;

	return 0;
}
