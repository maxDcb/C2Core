#pragma once

#include <client.hpp>
#include "Beacon.hpp"


class BeaconDns : public Beacon
{

public:
	BeaconDns(std::string& config, const std::string& dnsServer, const std::string& domain);
	~BeaconDns();

private:
	void checkIn();

	dns::Client* m_client;
};
