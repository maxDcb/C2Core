#include "../ModuleCmd.hpp"

#include <queue>

int multiTests()
{
	std::queue<C2Message> m_tasks;

	//
	// MultiBundleC2Message
	//
	std::cout << "MultiBundleC2Message" << std::endl;
	MultiBundleC2Message multiBundleC2Message;

	//
	// BundleC2Message
	//
	std::cout << "BundleC2Message" << std::endl;
	BundleC2Message* bundleC2Message = multiBundleC2Message.add_bundlec2messages();

	std::string beaconHash = "SUPERHASH6589852-df";
	std::string hostname = "848565-hostn";
	std::string username = "Admin";
	std::string arch = "toto-85x65";
	std::string privilege = "ADMINISTRATOR";
	std::string os = "linux-574f87_gogo";

	bundleC2Message->set_beaconhash(beaconHash);
	bundleC2Message->set_hostname(hostname);
	bundleC2Message->set_username(username);
	bundleC2Message->set_arch(arch);
	bundleC2Message->set_privilege(privilege);
	bundleC2Message->set_os(os);


	std::cout << "BundleC2Message x 10" << std::endl;
	for(int i=0; i<10; i++)
	{

		BundleC2Message* bundleC2Message = multiBundleC2Message.add_bundlec2messages();

		std::string beaconHash = "SUPERHASH6589852-df";
		std::string hostname = "848565-hostn";
		std::string username = "Admin";
		std::string arch = "toto-85x65";
		std::string privilege = "ADMINISTRATOR";
		std::string os = "linux-574f87_gogo";

		bundleC2Message->set_beaconhash(beaconHash);
		bundleC2Message->set_hostname(hostname);
		bundleC2Message->set_username(username);
		bundleC2Message->set_arch(arch);
		bundleC2Message->set_privilege(privilege);
		bundleC2Message->set_os(os);
	}

	//
	// C2Message
	//
	std::cout << "C2Message" << std::endl;
	{
		C2Message* c2Message = bundleC2Message->add_c2messages();

		std::string cmd = "run ls /tmp";
		// std::string inputFile = "C:\\Users\\CyberVuln\\Desktop\\Project\\ExplorationC2\\build\\bin\\ListDirectory.dll";
		// std::ifstream input(inputFile, std::ios::binary);
		// std::string buffer(std::istreambuf_iterator<char>(input), {});

		std::string buffer = "sddfsgvdfhgdfgdf";

		c2Message->set_cmd(cmd);
		c2Message->set_data(buffer.data(), buffer.size());

		std::string stringSerialized;
		c2Message->SerializeToString(&stringSerialized);

		C2Message c2MessageNew;
		c2MessageNew.ParseFromArray(stringSerialized.data(), stringSerialized.size());

		if (c2Message->data() == buffer && buffer == c2MessageNew.data())
			std::cout << "[+] OK" << std::endl;
		else
			std::cout << "[-] KO" << std::endl;
	}
	
	std::cout << "C2Message x 10" << std::endl;
	for(int i=0; i<10; i++)
	{
		C2Message* c2Message = bundleC2Message->add_c2messages();

		std::string cmd = "run ls /tmp";
		std::string buffer = "sddfsgvdfhgdfgdf";

		c2Message->set_cmd(cmd);
		c2Message->set_data(buffer.data(), buffer.size());

		std::cout << "bundleC2Message.c2messages(i).cmd() " << bundleC2Message->c2messages(i).cmd() << std::endl;
		std::cout << "multiBundleC2Message.bundleC2Message(0)->c2messages(i).cmd() " << multiBundleC2Message.bundlec2messages(0)->c2messages(i).cmd() << std::endl;

		C2Message c2Message2 = bundleC2Message->c2messages(i);
		m_tasks.push(c2Message2);
	}

	//
	// BundleC2Message
	//
	std::cout << "[+] BundleC2Message SerializeToString" << std::endl;
	std::string stringSerialized;
	bundleC2Message->SerializeToString(&stringSerialized);

	std::cout << "[+] BundleC2Message ParseFromArray" << std::endl;
	BundleC2Message bundleC2Message2;
	bundleC2Message2.ParseFromArray(stringSerialized.data(), stringSerialized.size());

	//
	// MultiBundleC2Message
	//
	std::cout << "[+] MultiBundleC2Message SerializeToString" << std::endl;
	std::string stringSerialized2;
	multiBundleC2Message.SerializeToString(&stringSerialized2);

	std::cout << "[+] MultiBundleC2Message ParseFromArray" << std::endl;
	MultiBundleC2Message multiBundleC2Message2;
	multiBundleC2Message2.ParseFromArray(stringSerialized2.data(), stringSerialized2.size());
	
	//
	// checker
	//
	std::cout << "bundlec2messages_size " << multiBundleC2Message.bundlec2messages_size() << std::endl;
	std::cout << "bundlec2messages_size " << multiBundleC2Message2.bundlec2messages_size() << std::endl;

	std::cout << "bundlec2messages(0).beaconhash() " << multiBundleC2Message2.bundlec2messages(0)->beaconhash() << std::endl;
	std::cout << "bundlec2messages(0).c2messages(0).cmd() " << multiBundleC2Message2.bundlec2messages(0)->c2messages(0).cmd() << std::endl;

	return 0;
}


int unitTests()
{
	//
	// MultiBundleC2Message
	//
	std::cout << "MultiBundleC2Message" << std::endl;
	MultiBundleC2Message multiBundleC2Message;

	//
	// BundleC2Message
	//
	std::cout << "BundleC2Message" << std::endl;
	BundleC2Message* bundleC2Message = multiBundleC2Message.add_bundlec2messages();

	std::string beaconHash = "SUPERHASH6589852-df";
	std::string hostname = "848565-hostn";
	std::string username = "Admin";
	std::string arch = "toto-85x65";
	std::string privilege = "ADMINISTRATOR";
	std::string os = "linux-574f87_gogo";

	bundleC2Message->set_beaconhash(beaconHash);
	bundleC2Message->set_hostname(hostname);
	bundleC2Message->set_username(username);
	bundleC2Message->set_arch(arch);
	bundleC2Message->set_privilege(privilege);
	bundleC2Message->set_os(os);

	C2Message* c2Message = bundleC2Message->add_c2messages();

	std::string cmd = "testCmd";
	std::string buffer = "";

#ifdef __linux__
        std::ifstream input("/bin/cat", std::ios::binary);
#elif _WIN32
        std::ifstream input("C:\\Windows\\System32\\calc.exe", std::ios::binary);
#endif
	
	if( input ) 
	{
		std::string fileContent(std::istreambuf_iterator<char>(input), {});
		buffer=fileContent;
	}

	c2Message->set_cmd(cmd);
	c2Message->set_data(buffer.data(), buffer.size());

	//
	// c2Message
	//
	std::cout << "[+] c2Message" << std::endl;
	std::string stringSerialized;
	std::cout << "[+] c2Message SerializeToString" << std::endl;
	c2Message->SerializeToString(&stringSerialized);

	C2Message c2Message2;
	std::cout << "[+] c2Message ParseFromArray" << std::endl;
	c2Message2.ParseFromArray(stringSerialized.data(), stringSerialized.size());

	std::string stringSerialized2;
	c2Message2.SerializeToString(&stringSerialized2);

	if(stringSerialized!=stringSerialized2)
	{
		std::cout << "[-] c2Message" << std::endl;
		exit(0);
	}

	//
	// BundleC2Message
	//
	std::cout << "[+] BundleC2Message" << std::endl;
	std::cout << "[+] BundleC2Message SerializeToString" << std::endl;
	bundleC2Message->SerializeToString(&stringSerialized);

	std::cout << "[+] BundleC2Message ParseFromArray" << std::endl;
	BundleC2Message bundleC2Message2;
	bundleC2Message2.ParseFromArray(stringSerialized.data(), stringSerialized.size());

	bundleC2Message2.SerializeToString(&stringSerialized2);

	if(stringSerialized!=stringSerialized2)
	{
		std::cout << "[-] BundleC2Message" << std::endl;
		exit(0);
	}

	//
	// MultiBundleC2Message
	//
	std::cout << "[+] MultiBundleC2Message" << std::endl;
	std::cout << "[+] MultiBundleC2Message SerializeToString" << std::endl;
	multiBundleC2Message.SerializeToString(&stringSerialized);

	std::cout << "[+] MultiBundleC2Message ParseFromArray" << std::endl;
	MultiBundleC2Message multiBundleC2Message2;
	multiBundleC2Message2.ParseFromArray(stringSerialized.data(), stringSerialized.size());

	multiBundleC2Message2.SerializeToString(&stringSerialized2);

	if(stringSerialized!=stringSerialized2)
	{
		std::cout << "[-] MultiBundleC2Message" << std::endl;
		exit(0);
	}

	std::cout << "[+] Data" << std::endl;
	for (int k = 0; k < multiBundleC2Message2.bundlec2messages_size(); k++) 
	{
		BundleC2Message* bundleC2Message = multiBundleC2Message.bundlec2messages(k);
		for (int j = 0; j < bundleC2Message->c2messages_size(); j++) 
		{
			const C2Message& c2Message = bundleC2Message->c2messages(j);

			if(c2Message.data()!=buffer)
			{
				std::cout << "[-] Data" << std::endl;
				exit(0);
			}
		}
	}

	return 0;
}


int unitTestsC2Message()
{
	
	{
		C2Message c2Message;
		c2Message.set_instruction("instruction");
		c2Message.set_cmd("cmd");
		c2Message.set_returnvalue("returnValue");
		c2Message.set_inputfile("inputFile");
		c2Message.set_outputfile("outputFile");
		std::string buffer = "buffer";
		c2Message.set_data(buffer.data(), buffer.size());
		c2Message.set_args("args");
		c2Message.set_pid(158);

		std::string stringSerialized;
		c2Message.SerializeToString(&stringSerialized);
	}

	{
		C2Message c2Message;

		c2Message.set_instruction("sleep");
		int sleepTimeSec=5;
		c2Message.set_cmd(std::to_string(sleepTimeSec));	
		c2Message.set_returnvalue(std::to_string(sleepTimeSec));	

		std::string stringSerialized;
		std::cout << "2" << std::endl;
		c2Message.SerializeToString(&stringSerialized);

		C2Message c2Message2;
		std::cout << "3" << std::endl;
		c2Message2.ParseFromArray(stringSerialized.data(), stringSerialized.size());

		std::cout << stringSerialized << std::endl;
	}

	return 0;
}


int unitTestsMultiBundleC2Message()
{
	//
	// MultiBundleC2Message
	//
	std::cout << "MultiBundleC2Message" << std::endl;
	MultiBundleC2Message multiBundleC2Message;

	//
	// BundleC2Message
	//
	std::cout << "BundleC2Message" << std::endl;
	BundleC2Message* bundleC2Message = multiBundleC2Message.add_bundlec2messages();

	std::string beaconHash = "SUPERHASH6589852-df";
	std::string hostname = "848565-hostn";
	std::string username = "Admin";
	std::string arch = "toto-85x65";
	std::string privilege = "ADMINISTRATOR";
	std::string os = "linux-574f87_gogo";

	bundleC2Message->set_beaconhash(beaconHash);
	bundleC2Message->set_hostname(hostname);
	bundleC2Message->set_username(username);
	bundleC2Message->set_arch(arch);
	bundleC2Message->set_privilege(privilege);
	bundleC2Message->set_os(os);

	C2Message* c2Message = bundleC2Message->add_c2messages();

	std::string cmd = "testCmd";
	std::string buffer = "buffer";

	c2Message->set_cmd(cmd);
	c2Message->set_data(buffer.data(), buffer.size());

	//
	// c2Message
	//
	std::string stringSerialized;
	c2Message->SerializeToString(&stringSerialized);

	C2Message c2Message2;
	c2Message2.ParseFromArray(stringSerialized.data(), stringSerialized.size());

	std::string stringSerialized2;
	c2Message2.SerializeToString(&stringSerialized2);


	//
	// BundleC2Message
	//
	bundleC2Message->SerializeToString(&stringSerialized);

	BundleC2Message bundleC2Message2;
	bundleC2Message2.ParseFromArray(stringSerialized.data(), stringSerialized.size());


	//
	// MultiBundleC2Message
	//
	multiBundleC2Message.SerializeToString(&stringSerialized);

	std::cout << stringSerialized << std::endl;

	std::cout << "[+] C++" << std::endl;
	{
		MultiBundleC2Message multiBundleC2MessageTest;
		std::string test = stringSerialized;
		
		json my_json = json::parse(test);

		std::cout << "my_json" << my_json << std::endl;

		std::cout << "Iterator" << std::endl;

		for (json::iterator it = my_json.begin(); it != my_json.end(); ++it)
		{
			std::string json_str = (*it).dump();	

			auto bundleC2MessageJson = json::parse(json_str);
			// std::string m_beaconHash = bundleC2MessageJson["beaconHash"].get<std::string>();
			// std::string m_listenerHash = bundleC2MessageJson["listenerHash"].get<std::string>();
			// std::string m_username = bundleC2MessageJson["username"].get<std::string>();
			// std::string m_hostname = bundleC2MessageJson["hostname"].get<std::string>();
			// std::string m_arch = bundleC2MessageJson["arch"].get<std::string>();
			// std::string m_privilege = bundleC2MessageJson["privilege"].get<std::string>();
			// std::string m_os = bundleC2MessageJson["os"].get<std::string>();
			// auto sessions = bundleC2MessageJson["sessions"];
		}

		std::cout << "For" << std::endl;

		for(int i=0; i<my_json.size(); i++)
		{
			std::string json_str = my_json[i].dump();	
			auto bundleC2MessageJson = json::parse(json_str);

			// std::string m_beaconHash = bundleC2MessageJson["beaconHash"].get<std::string>();
			// std::string m_listenerHash = bundleC2MessageJson["listenerHash"].get<std::string>();
			// std::string m_username = bundleC2MessageJson["username"].get<std::string>();
			// std::string m_hostname = bundleC2MessageJson["hostname"].get<std::string>();
			// std::string m_arch = bundleC2MessageJson["arch"].get<std::string>();
			// std::string m_privilege = bundleC2MessageJson["privilege"].get<std::string>();
			// std::string m_os = bundleC2MessageJson["os"].get<std::string>();
			// auto sessions = bundleC2MessageJson["sessions"];
		}

		std::cout << "ParseFromArray" << std::endl;

		multiBundleC2MessageTest.ParseFromArray(test.data(), test.size());
		for (int k = 0; k < multiBundleC2MessageTest.bundlec2messages_size(); k++) 
		{
			BundleC2Message* bundleC2Message = multiBundleC2Message.bundlec2messages(k);
			for (int j = 0; j < bundleC2Message->c2messages_size(); j++) 
			{
				const C2Message& c2Message = bundleC2Message->c2messages(j);
			}
		}

	}

	//
	// Nim
	//
	std::cout << "[+] nim" << std::endl;
	{
		MultiBundleC2Message multiBundleC2MessageTest;
		std::string test = "[{\"arch\":\"x64\",\"beaconHash\":\"CakWQnqmA3b22u1tYCwhXBkTY828nINz\",\"hostname\":\"toto\",\"listenerHash\":\"\",\"os\":\"Linux\",\"privilege\":\"MEDIUM\",\"sessions\":[{\"args\":\"\",\"cmd\":\"\",\"data\":\"\",\"inputFile\":\"\",\"instruction\":\"\",\"outputFile\":\"\",\"pid\":-1,\"returnValue\":\"\"}],\"username\":\"nim\"}]";

		json my_json = json::parse(test);

		std::cout << my_json.size() << std::endl;
		std::cout << my_json << std::endl;

		std::cout << "Iterator" << std::endl;

		for (json::iterator it = my_json.begin(); it != my_json.end(); ++it)
		{
			std::string json_str = (*it).dump();	

			std::cout << "json_str " << json_str << std::endl;

			auto bundleC2MessageJson = json::parse(json_str);

			std::cout << "bundleC2MessageJson " << bundleC2MessageJson << std::endl;

			std::string m_beaconHash = bundleC2MessageJson["beaconHash"].get<std::string>();
			std::cout << "m_beaconHash " << m_beaconHash << std::endl;

			std::string m_listenerHash = bundleC2MessageJson["listenerHash"].get<std::string>();
			std::string m_username = bundleC2MessageJson["username"].get<std::string>();
			std::string m_hostname = bundleC2MessageJson["hostname"].get<std::string>();
			std::string m_arch = bundleC2MessageJson["arch"].get<std::string>();
			std::string m_privilege = bundleC2MessageJson["privilege"].get<std::string>();
			std::string m_os = bundleC2MessageJson["os"].get<std::string>();
			auto sessions = bundleC2MessageJson["sessions"];
		}

		std::cout << "For" << std::endl;

		for(int i=0; i<my_json.size(); i++)
		{
			std::string json_str = my_json[i].dump();	

			std::cout << "json_str " << json_str << std::endl;

			auto bundleC2MessageJson = json::parse(json_str);

			std::cout << "bundleC2MessageJson " << bundleC2MessageJson << std::endl;

			std::string m_beaconHash = bundleC2MessageJson["beaconHash"].get<std::string>();
			std::cout << "m_beaconHash " << m_beaconHash << std::endl;

			std::string m_listenerHash = bundleC2MessageJson["listenerHash"].get<std::string>();
			std::string m_username = bundleC2MessageJson["username"].get<std::string>();
			std::string m_hostname = bundleC2MessageJson["hostname"].get<std::string>();
			std::string m_arch = bundleC2MessageJson["arch"].get<std::string>();
			std::string m_privilege = bundleC2MessageJson["privilege"].get<std::string>();
			std::string m_os = bundleC2MessageJson["os"].get<std::string>();
			auto sessions = bundleC2MessageJson["sessions"];
		}

		std::cout << "ParseFromArray" << std::endl;

		multiBundleC2MessageTest.ParseFromArray(test.data(), test.size());

		std::cout << "bundlec2messages_size " << multiBundleC2MessageTest.bundlec2messages_size() << std::endl;

		for (int k = 0; k < multiBundleC2MessageTest.bundlec2messages_size(); k++) 
		{
			std::cout << "c2messages_size " << bundleC2Message->c2messages_size() << std::endl;

			BundleC2Message* bundleC2Message = multiBundleC2Message.bundlec2messages(k);

			std::cout << "beaconhash " << bundleC2Message->beaconhash() << std::endl;

			for (int j = 0; j < bundleC2Message->c2messages_size(); j++) 
			{
				const C2Message& c2Message = bundleC2Message->c2messages(j);

			}
		}

	}

	return 0;
}
	

int main()
{
	std::cout << "unitTestsC2Message " << std::endl;
	unitTestsC2Message(); 

	std::cout << "unitTests " << std::endl;
	unitTests();

	std::cout << "unitTestsMultiBundleC2Message " << std::endl;
	unitTestsMultiBundleC2Message();
	
	std::cout << "multiTests " << std::endl;
	multiTests();
}