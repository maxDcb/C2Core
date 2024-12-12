#pragma once

#include "Beacon.hpp"


class BeaconHttp : public Beacon
{

public:
	BeaconHttp(std::string& config, std::string& ip, int port, bool https=false);
	~BeaconHttp();

	void checkIn();

private:
	std::string m_ip;
	int m_port;

	nlohmann::json m_beaconHttpConfig;
	bool m_isHttps;

};
