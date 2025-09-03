#include "ListenerDns.hpp"
#include <server.hpp>
#include <client.hpp>


using namespace std;
using json = nlohmann::json;


ListenerDns::ListenerDns(const std::string& domainToResolve, int port)
	: Listener(domainToResolve, std::to_string(port), ListenerDnsType)
{
	m_serverDns = new dns::Server(port, domainToResolve);

	m_listenerHash = random_string(SizeListenerHash);

	json metadata;
    metadata["1"] = ListenerDnsType;
    metadata["2"] = domainToResolve;
    metadata["3"] = std::to_string(port);
	m_metadata = metadata.dump();

	m_serverDns->launch();

	m_stopThread=false;
	m_dnsListener = std::make_unique<std::thread>(&ListenerDns::launchDnsListener, this);
}


ListenerDns::~ListenerDns()
{
	m_serverDns->stop();

	m_stopThread=true;
	m_dnsListener->join();

	delete m_serverDns;
}


void ListenerDns::launchDnsListener()
{
	try 
    {
		while(1)
		{
			if(m_stopThread)
				return;

			SPDLOG_DEBUG("receiving");
	
			string input = m_serverDns->getMsg();

			SPDLOG_DEBUG("received input.size {0}",std::to_string(input.size()));

			if(!input.empty())
			{
				string output;
				bool ret = handleMessages(input, output);

				SPDLOG_DEBUG("sending output.size {0}", std::to_string(output.size()));

				if(!output.empty())
					m_serverDns->setMsg(output);
			}
			
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
	}
    catch (...)
    {
        return;
    }

	return;
}

