#include "ListenerHttp.hpp"

#include "Config.hpp"


using namespace std;
using namespace httplib;


const httplib::Headers httpServerHeaders = {
  { "Accept-Encoding", "gzip, deflate" },
  { "User-Agent", "http server agent" }
};


const httplib::Headers httpsServerHeaders = {
  { "Accept-Encoding", "gzip, deflate" },
  { "User-Agent", "https server agent" }
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
		m_svr->Post(HttpsEndPoint, [&](const httplib::Request& req, httplib::Response& res)
		{
			this->HandleCheckIn(req, res);
		});
	}
	else
	{
		m_svr->Post(HttpEndPoint, [&](const httplib::Request& req, httplib::Response& res)
		{
			this->HandleCheckIn(req, res);
		});
	}

	m_svr->listen(m_host.c_str(), m_port);
}


int ListenerHttp::HandleCheckIn(const httplib::Request& req, httplib::Response& res)
{
	string input = req.body;

	string output;
	bool ret = handleMessages(input, output);

	if(m_isHttps)
		res.headers = httpsServerHeaders;
	else
		res.headers = httpServerHeaders;

	if(ret)
		res.body = output;
	else
		res.status = 200;

	return 0;
}
