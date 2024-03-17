#include "ListenerDns.hpp"



using namespace std;


ListenerDns::ListenerDns(const std::string& domainToResolve, int port)
	: Listener("127.0.0.1", 911, ListenerDnsType)
	, m_serverDns(port, domainToResolve)
{
	m_listenerHash = random_string(SizeListenerHash);
	m_listenerHash += "-";
	m_listenerHash += ListenerDnsType;
	m_listenerHash += "/";
	m_listenerHash += domainToResolve;
	m_listenerHash += "/";
	m_listenerHash += std::to_string(port);

	m_serverDns.launch();

	m_stopThread=false;
	m_dnsListener = std::make_unique<std::thread>(&ListenerDns::lauchDnsListener, this);
}


ListenerDns::~ListenerDns()
{
	m_serverDns.stop();

	m_stopThread=true;
	m_dnsListener->join();
}


void ListenerDns::lauchDnsListener()
{
	try 
    {
		while(1)
		{
			if(m_stopThread)
				return;

			DEBUG("receiving");
	
			string input = m_serverDns.getMsg();

			DEBUG("received input.size " << std::to_string(input.size()));

			string output;
			bool ret = handleMessages(input, output);

			DEBUG("sending output.size " << std::to_string(output.size()));

			if(!output.empty())
				m_serverDns.setMsg(output);
			
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
	}
    catch (...)
    {
        return;
    }

	return;
}

