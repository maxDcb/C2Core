#pragma once

#include <SocketHandler.hpp>
#include "Beacon.hpp"


class BeaconTcp : public Beacon
{

public:
	BeaconTcp(std::string& ip, int port);
	~BeaconTcp();

private:
	void checkIn();

};
