#pragma once

#include <string>
#include <vector>
#include <random>

#include "ModuleCmd.hpp"


#define ERROR_GENERIC 10000
#define ERROR_LISTENER_EXIST 10001
#define ERROR_PORT_FORMAT 10002
#define ERROR_HASH_NOT_FOUND 10003
#define ERROR_LOAD_LIBRARY 10004
#define ERROR_GET_PROC_ADDRESS 10005
#define ERROR_MODULE_NOT_FOUND 10006
#define ERROR_MODULE_ALREADY_LOADED 10007


// TODO set an enum
const std::string ListenerHttpType = "http";
const std::string ListenerHttpsType = "https";
const std::string ListenerTcpType = "tcp";
const std::string ListenerSmbType = "smb";
const std::string ListenerGithubType = "github";
const std::string ListenerDnsType = "dns";


// should only be use by the listener and beacon to communicate, could take any values
const std::string SleepCmd = "SL";
const std::string ListenerCmd = "LIS";
const std::string ListenerPollCmd = "LISP";
const std::string LoadC2ModuleCmd = "LM";
const std::string UnloadC2ModuleCmd = "ULM";
const std::string Socks5Cmd = "SO5";
const std::string InitCmd = "IN";
const std::string RunCmd = "RU";
const std::string EndCmd = "EN";
const std::string StartCmd = "STA";
const std::string StopCmd = "STO";
const std::string StopSocksCmd = "SSO";

const std::string CmdStatusSuccess = "Success";
const std::string CmdStatusFail = "Fail";
const std::string CmdModuleNotFound = "Module not loaded";


#ifdef BUILD_TEAMSERVER

// real instructions strings not present in the beacon
const std::string SleepInstruction = "sleep";
const std::string EndInstruction = "end";
const std::string ListenerInstruction = "listener";
const std::string LoadModuleInstruction = "loadModule";
const std::string UnloadModuleInstruction = "unloadModule";

const std::string StartInstruction = "start";
const std::string StopInstruction = "stop";


class CommonCommands
{
	public:
	CommonCommands()
	{
		m_commonCommands.push_back(EndInstruction);
		m_commonCommands.push_back(ListenerInstruction);
		m_commonCommands.push_back(LoadModuleInstruction);
		m_commonCommands.push_back(UnloadModuleInstruction);
		m_commonCommands.push_back(SleepInstruction);
	}

	int getNumberOfCommand()
	{
		return m_commonCommands.size();
	}

	std::string getCommand(int idx)
	{
		if(idx<m_commonCommands.size())
			return m_commonCommands[idx];
		else 
			return "";
	}

	std::string translateCmdToInstruction(const std::string& cmd)
	{
		std::string output;

		if(cmd==SleepCmd)
			return SleepInstruction;
		else if(cmd==EndCmd)
			return EndInstruction;		
		else if(cmd==ListenerCmd)
			return ListenerInstruction;
		else if(cmd==LoadC2ModuleCmd)
			return LoadModuleInstruction;
		else if(cmd==UnloadC2ModuleCmd)
			return UnloadModuleInstruction;
		return "";
	}

	std::string getHelp(std::string cmd)
{
	std::string output;

	if (cmd == SleepCmd)
	{
		output = "sleep:\n";
		output += "  Set the sleep interval (in seconds) for the beacon.\n";
		output += "  Example:\n";
		output += "    - sleep 0.5\n";
	}
	else if (cmd == EndCmd)
	{
		output = "end:\n";
		output += "  Terminates the beacon process.\n";
		output += "  Example:\n";
		output += "    - end\n";
	}
	else if (cmd == ListenerCmd)
	{
		output = "listener:\n";
		output += "  Starts a TCP or SMB listener on the beacon.\n" 
		output += "  The IP or hostname given to the listener is only in case of dropper use, to know where to connect to. It will show in the GUI.\n";
		output += "  Examples:\n";
		output += "    - listener start tcp <IP> <port>\n";
		output += "    - listener start tcp 10.2.4.8 4444\n";
		output += "    - listener start smb <IP/hostname> <pipename>\n";
		output += "    - listener start smb pipename\n";
	}
	else if (cmd == LoadC2ModuleCmd)
	{
		output = "loadModule:\n";
		output += "  Loads a module DLL into the beacon's memory, extending its capabilities.\n";
		output += "  Attempts to load from the specified path; if not found, falls back to the default '../Modules/' directory.\n";
		output += "  Example:\n";
		output += "    - loadModule assemblyexec\n";
		output += "    - loadModule /tools/PrintWorkingDirectory.dll\n";
	}
	else if (cmd == UnloadC2ModuleCmd)
	{
		output = "unloadModule:\n";
		output += "  Unloads a module DLL that was previously loaded via loadModule.\n";
		output += "  Example:\n";
		output += "    - unloadModule assemblyExec\n";
	}

	return output;
}


	// if an error ocurre:
	// set_returnvalue(errorMsg) && return -1
	int init(std::vector<std::string> &splitedCmd, C2Message &c2Message, bool isWindows=true)
	{
		std::string instruction = splitedCmd[0];

		//
		// Sleep
		//
		if(instruction==SleepInstruction)
		{
			if(splitedCmd.size()==2)
			{
				float sleepTimeSec=5;
				try 
				{
					sleepTimeSec = atof(splitedCmd[1].c_str());
				}
				catch (const std::invalid_argument& ia) 
				{
					std::cerr << "Invalid argument: " << ia.what() << '\n';
					return -1;
				}
				c2Message.set_instruction(SleepCmd);
				c2Message.set_cmd(std::to_string(sleepTimeSec));	
			}
			else
			{
				std::string errorMsg = getHelp(SleepCmd);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		//
		// End
		//
		else if(instruction==EndInstruction)
		{
			c2Message.set_instruction(EndCmd);
			c2Message.set_cmd("");	
		}
		//
		// Listener
		//
		else if(instruction==ListenerInstruction)
		{
			if(splitedCmd.size()>=3)
			{
				if(splitedCmd[1]==StartInstruction && splitedCmd[2]==ListenerTcpType)
				{
					if(splitedCmd.size()>=5)
					{
						std::string host = splitedCmd[3];
						int port=-1;
						try 
						{
							port = std::atoi(splitedCmd[4].c_str());
						}
						catch (const std::invalid_argument& ia) 
						{
							std::cerr << "Invalid argument: " << ia.what() << '\n';
							return -1;
						}

						std::string cmd = StartCmd;
						cmd+=" ";
						cmd+=ListenerTcpType;
						cmd+=" ";
						cmd+=host;
						cmd+=" ";
						cmd+=std::to_string(port);
						c2Message.set_instruction(ListenerCmd);
						c2Message.set_cmd(cmd);	
					}
					else
					{
						std::string errorMsg = "listener tcp start: not enough arguments";
						c2Message.set_returnvalue(errorMsg);	
						return -1;
					}
				}
				else if(splitedCmd[1]==StartInstruction && splitedCmd[2]==ListenerSmbType)
				{
					if(splitedCmd.size()==5)
					{
						std::string host = splitedCmd[3];
						std::string pipeName = splitedCmd[4];
						std::string cmd = StartCmd;
						cmd+=" ";
						cmd+=ListenerSmbType;
						cmd+=" ";
						cmd+=host;
						cmd+=" ";
						cmd+=pipeName;
						c2Message.set_instruction(ListenerCmd);
						c2Message.set_cmd(cmd);	
					}
					else
					{
						std::string errorMsg = "listener smb start: not enough arguments";
						c2Message.set_returnvalue(errorMsg);	
						return -1;
					}
				}
				else if(splitedCmd[1]==StopInstruction)
				{
					std::string hash = splitedCmd[2];
					std::string cmd = StopCmd;
					cmd+=" ";
					cmd+=hash;
					c2Message.set_instruction(ListenerCmd);
					c2Message.set_cmd(cmd);	
				}				
			}
			else
			{
				std::string errorMsg = getHelp(ListenerCmd);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		//
		// Load Memory Module
		//
		else if(instruction==LoadModuleInstruction)
		{
			if (splitedCmd.size() == 2)
			{
				std::string inputFile = splitedCmd[1];

				// check if it's a Path
				std::ifstream input;
				input.open(inputFile, std::ios::binary);

				// if not check if it's a filename present in the linux or windows directory
				if(!input && !isWindows)
				{
					std::string newInputFile = m_linuxModulesDirectoryPath;
					newInputFile+=inputFile;
					input.open(newInputFile, std::ios::binary);
				}
				else if(!input && isWindows)
				{
					std::string newInputFile = m_windowsModulesDirectoryPath;
					newInputFile+=inputFile;
					input.open(newInputFile, std::ios::binary);
				}

				if( input ) 
				{
					std::string buffer(std::istreambuf_iterator<char>(input), {});

					c2Message.set_instruction(LoadC2ModuleCmd);
					c2Message.set_inputfile(inputFile);
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
				std::string errorMsg = getHelp(LoadC2ModuleCmd);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		else if(instruction==UnloadModuleInstruction)
		{
			if (splitedCmd.size() == 2)
			{
				std::string moduleName = splitedCmd[1];

				c2Message.set_instruction(UnloadC2ModuleCmd);
				c2Message.set_cmd(moduleName);
			}
			else
			{
				std::string errorMsg = getHelp(UnloadC2ModuleCmd);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		return 0;
	}


	int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg) 
	{
		int errorCode = c2RetMessage.errorCode();
		if(errorCode>0)
		{
			if(errorCode==ERROR_GENERIC)
				errorMsg = "Error";
			else if(errorCode==ERROR_LISTENER_EXIST)
				errorMsg = "Error: Listener already exist";
			else if(errorCode==ERROR_PORT_FORMAT)
				errorMsg = "Error: Port format";
			else if(errorCode==ERROR_HASH_NOT_FOUND)
				errorMsg = "Error: Hash not found";
			else if(errorCode==ERROR_LOAD_LIBRARY)
				errorMsg = "Error: MemoryLoadLibrary";
			else if(errorCode==ERROR_GET_PROC_ADDRESS)
				errorMsg = "Error: MemoryGetProcAddress";
			else if(errorCode==ERROR_MODULE_NOT_FOUND)
				errorMsg = "Error: Module not found";
			else if(errorCode==ERROR_MODULE_ALREADY_LOADED)
				errorMsg = "Error: Module already loaded";
		}
		return 0;
	}

	int setDirectories( const std::string& teamServerModulesDirectoryPath,
						const std::string& linuxModulesDirectoryPath,
						const std::string& windowsModulesDirectoryPath,
						const std::string& linuxBeaconsDirectoryPath,
						const std::string& windowsBeaconsDirectoryPath,
						const std::string& toolsDirectoryPath,
						const std::string& scriptsDirectoryPath)
	{
		m_teamServerModulesDirectoryPath=teamServerModulesDirectoryPath;
		m_linuxModulesDirectoryPath=linuxModulesDirectoryPath;
		m_windowsModulesDirectoryPath=windowsModulesDirectoryPath;
		m_linuxBeaconsDirectoryPath=linuxBeaconsDirectoryPath;
		m_windowsBeaconsDirectoryPath=windowsBeaconsDirectoryPath;
		m_toolsDirectoryPath=toolsDirectoryPath;
		m_scriptsDirectoryPath=scriptsDirectoryPath;

		return 0;
	};

private:
	std::vector<std::string> m_commonCommands;

	std::string m_teamServerModulesDirectoryPath;
    std::string m_linuxModulesDirectoryPath;
    std::string m_windowsModulesDirectoryPath;
    std::string m_linuxBeaconsDirectoryPath;
    std::string m_windowsBeaconsDirectoryPath;
    std::string m_toolsDirectoryPath;
    std::string m_scriptsDirectoryPath;
};


#endif
