#pragma once

#include <string>
#include <vector>
#include <random>

#include "ModuleCmd.hpp"


const std::string HelpCmd = "help";
const std::string SleepCmd = "sleep";
const std::string EndCmd = "end";
const std::string ListenerCmd = "listener";
const std::string ListenerPolCmd = "listenerPol";
const std::string LoadC2Module = "loadModule";
const std::string UnloadC2Module = "unloadModule";

#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
const std::string ModulesDirectoryFromTeamServer = "../Modules/";
#endif

const std::string StartCmd = "start";
const std::string StopCmd = "stop";

const std::string CmdStatusSuccess = "Success";
const std::string CmdStatusFail = "Fail";


class CommonCommands
{
	public:
	CommonCommands()
	{
		m_commonCommands.push_back(SleepCmd);
		m_commonCommands.push_back(EndCmd);
		m_commonCommands.push_back(ListenerCmd);
		m_commonCommands.push_back(LoadC2Module);
		m_commonCommands.push_back(UnloadC2Module);
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

	std::string getHelp(std::string cmd)
	{
		// OPSEC remove getHelp and getInfo strings from the beacon compilation
		std::string output;
#ifdef BUILD_TEAMSERVER
		if(cmd==SleepCmd)
		{
			output = "sleep: \n";
			output += "Set the sleep time in sec for the beacon.\n";
			output += "exemple:\n";
			output += " - sleep 1\n";
		}
		else if(cmd==EndCmd)
		{
			output = "end: \n";
			output += "Stop the beacon.\n";
			output += "exemple:\n";
			output += " - end\n";
		}
		else if(cmd==ListenerCmd)
		{
			output = "listener: \n";
			output += "Start a tcp or smb listener on the beacon.\n";
			output += "exemple:\n";
			output += " - listener start tcp 0.0.0.0 4444\n";
			output += " - listener start smb pipename\n";
			output += " - listener stop uAgXVQny0o1GVoIHf0Jaed4xl5lYpHKU\n";
		}
		else if(cmd==LoadC2Module)
		{
			output = "loadModule: \n";
			output += "Load module DLL file on the memory of the beacon, giving the beacon this capability.\n";
			output += "Load the DLL from the given path, if it's not found try the default ../Modules/ path.";
			output += "exemple:\n";
			output += " - loadModule /tools/PrintWorkingDirectory.dll \n";
		}
		else if(cmd==UnloadC2Module)
		{
			output = "unloadModule: \n";
			output += "Unload module DLL loaded by loadModule.\n";
			output += "exemple:\n";
			output += " - unloadModule assemblyExec \n";
		}
#endif
		return output;
	}

	// if an error ocurre:
	// set_returnvalue(errorMsg) && return -1
	int init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
	{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
		std::string instruction = splitedCmd[0];

		if(instruction==SleepCmd)
		{
			if(splitedCmd.size()==2)
			{
				int sleepTimeSec=5;
				try 
				{
					sleepTimeSec = atoi(splitedCmd[1].c_str());
				}
				catch (const std::invalid_argument& ia) 
				{
					std::cerr << "Invalid argument: " << ia.what() << '\n';
					return -1;
				}
				c2Message.set_instruction(instruction);
				c2Message.set_cmd(std::to_string(sleepTimeSec));	
			}
			else
			{
				std::string errorMsg = getHelp(instruction);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		else if(instruction==EndCmd)
		{
			c2Message.set_instruction(instruction);
			c2Message.set_cmd("");	
		}
		else if(instruction==ListenerCmd)
		{
			if(splitedCmd.size()>=3)
			{
				if(splitedCmd[1]==StartCmd && splitedCmd[2]=="tcp")
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

						std::string cmd = splitedCmd[1];
						cmd+=" ";
						cmd+="tcp";
						cmd+=" ";
						cmd+=host;
						cmd+=" ";
						cmd+=std::to_string(port);
						c2Message.set_instruction(instruction);
						c2Message.set_cmd(cmd);	
					}
					else
					{
						std::string errorMsg = "listener start: not enough arguments";
						c2Message.set_returnvalue(errorMsg);	
						return -1;
					}
				}
				else if(splitedCmd[1]==StartCmd && splitedCmd[2]=="smb")
				{
					if(splitedCmd.size()>=4)
					{
						std::string pipeName = splitedCmd[3];
						std::string cmd = splitedCmd[1];
						cmd+=" ";
						cmd+="smb";
						cmd+=" ";
						cmd+=pipeName;
						c2Message.set_instruction(instruction);
						c2Message.set_cmd(cmd);	
					}
					else
					{
						std::string errorMsg = "listener start: not enough arguments";
						c2Message.set_returnvalue(errorMsg);	
						return -1;
					}
				}
				else if(splitedCmd[1]==StopCmd)
				{
					std::string hash = splitedCmd[2];
					std::string cmd = splitedCmd[1];
					cmd+=" ";
					cmd+=hash;
					c2Message.set_instruction(instruction);
					c2Message.set_cmd(cmd);	
				}				
			}
			else
			{
				std::string errorMsg = getHelp(instruction);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		else if(instruction==LoadC2Module)
		{
			if (splitedCmd.size() == 2)
			{
				std::string inputFile = splitedCmd[1];
				
				std::ifstream input;
				input.open(inputFile, std::ios::binary);
				if(!input)
				{
					std::string newInputFile = ModulesDirectoryFromTeamServer;
					newInputFile+=inputFile;
					input.open(newInputFile, std::ios::binary);
				}

				if( input ) 
				{
					std::string buffer(std::istreambuf_iterator<char>(input), {});

					c2Message.set_instruction(splitedCmd[0]);
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
				std::string errorMsg = getHelp(instruction);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		else if(instruction==UnloadC2Module)
		{
			if (splitedCmd.size() == 2)
			{
				std::string moduleName = splitedCmd[1];

				c2Message.set_instruction(splitedCmd[0]);
				c2Message.set_cmd(moduleName);
			}
			else
			{
				std::string errorMsg = getHelp(instruction);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
#endif
		return 0;
	}

private:
	std::vector<std::string> m_commonCommands;
};




