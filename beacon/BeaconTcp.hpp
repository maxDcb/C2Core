#pragma once

#include "Beacon.hpp"

class SocketTunnelClient;


class BeaconTcp : public Beacon
{

public:
    BeaconTcp(std::string& config, std::string& ip, int port);
    ~BeaconTcp();

private:
    std::string m_ip;
    int m_port;

    void checkIn();

    int splitInPacket(const std::string& input, std::vector<std::string>& output);

    SocketTunnelClient* m_client;
};
