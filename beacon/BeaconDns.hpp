#pragma once

#include <client.hpp>
#include "Beacon.hpp"


class BeaconDns : public Beacon
{

public:
	BeaconDns(const std::string& dnsServer, const std::string& domain);
	~BeaconDns();

private:
	void checkIn();

	dns::Client* m_client;
};
