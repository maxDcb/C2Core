#pragma once

#include "Beacon.hpp"


class BeaconHttp : public Beacon
{

public:
	BeaconHttp(std::string& ip, int port, bool https=false);
	~BeaconHttp();

	void checkIn();

private:
	bool m_isHttps;

};
