#include "ListenerSmb.hpp"


using namespace std;


ListenerSmb::ListenerSmb(const std::string& ip, int localPort)
	: Listener(ip, localPort, ListenerSmbType)
{
	std::string pipeName = "mynamedpipe";
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
		m_serverSmb->init();

		while(1)
		{
			if(m_stopThread)
				return;

			DEBUG("receiving");

			string input;
			m_serverSmb->receiveData(input);

			DEBUG("received input.size " << std::to_string(input.size()));

			string output;
			bool ret = handleMessages(input, output);

			if (output.empty())
				output = "{}";

			DEBUG("sending output.size " << std::to_string(output.size()));

			m_serverSmb->sendData(output);	

			DEBUG("sent");

			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
	}
    catch (...)
    {
        return;
    }

	return;
}

