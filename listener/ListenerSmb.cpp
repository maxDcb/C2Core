#include "ListenerSmb.hpp"


using namespace std;
using json = nlohmann::json;


// Initializes an SMB listener that can be contacted at the specified IP address or domain and named pipe.
// - Generates a random listener hash for identification.
// - Prepares metadata containing the listener type, IP, and pipe name, serialized as a JSON string.
// - Creates a named pipe server using the specified pipe name to handle SMB communication.
// - Launches the SMB server handler in a separate thread to listen for incoming connections.
ListenerSmb::ListenerSmb(const std::string& ip, const std::string& pipeName)
	: Listener(ip, pipeName, ListenerSmbType)
{
	m_listenerHash = random_string(SizeListenerHash);

	json metadata;
    metadata["1"] = ListenerSmbType;
    metadata["2"] = ip;
    metadata["3"] = pipeName;
	m_metadata = metadata.dump();

	m_serverSmb = new PipeHandler::Server(pipeName);

	m_stopThread=false;
	m_smbServ = std::make_unique<std::thread>(&ListenerSmb::launchSmbServ, this);
}


ListenerSmb::~ListenerSmb()
{
	m_stopThread=true;
	m_smbServ->join();

	delete m_serverSmb;
}


void ListenerSmb::launchSmbServ()
{
	try 
    {
		while(1)
		{
			if(m_stopThread)
				return;

			m_serverSmb->initServer();

			SPDLOG_DEBUG("receiving");
	
			bool res = false;
			string input;
			while(input.empty())
			{
				res = m_serverSmb->receiveData(input);
				std::this_thread::sleep_for(std::chrono::milliseconds(50));		
			}

			SPDLOG_DEBUG("received input.size {0}", std::to_string(input.size()));

			if(res && !input.empty())
			{
				string output;
				bool ret = handleMessages(input, output);

				SPDLOG_DEBUG("sending output.size {0}", std::to_string(output.size()));

				res = m_serverSmb->sendData(output);	
				if(res)
				{
					SPDLOG_DEBUG("sent");
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

