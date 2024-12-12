#pragma once

#include <PipeHandler.hpp>
#include "Beacon.hpp"


class BeaconSmb : public Beacon
{

public:
	BeaconSmb(std::string& config, const std::string& pipeName);
	~BeaconSmb();

private:
	void checkIn();

	PipeHandler::Client* m_clientSmb;

};
