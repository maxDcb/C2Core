#pragma once

#include <SocketClient.hpp>
#include "Beacon.hpp"


class BeaconTcp : public Beacon
{

public:
	BeaconTcp(std::string& ip, int port);
	~BeaconTcp();

private:
	void checkIn();

	int splitInPacket(const std::string& input, std::vector<std::string>& output);

	SocketTunnelClient* m_client;
};
