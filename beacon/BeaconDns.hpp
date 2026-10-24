#pragma once

#include "Beacon.hpp"

namespace dns
{
    class Client;
}

class BeaconDns : public Beacon
{

public:
    BeaconDns(std::string& config, const std::string& dnsServer,
              const std::string& domain, int port = 53);
    ~BeaconDns();

protected:
    void checkIn() override;

private:
    dns::Client* m_client;
    std::string m_pendingOutput;
};
