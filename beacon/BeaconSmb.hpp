#pragma once

#include <PipeHandler.hpp>
#include "Beacon.hpp"


class BeaconSmb : public Beacon
{

public:
	BeaconSmb(const std::string& pipeName);
	~BeaconSmb();

private:
	void checkIn();

	PipeHandler::Client* m_clientSmb;

};
