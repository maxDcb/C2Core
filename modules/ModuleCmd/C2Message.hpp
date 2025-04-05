
#include <base64.h>
#include "nlohmann/json.hpp"

// C2Message tags
const std::string InstructionMsgTag = "INS";
const std::string UuidMsgTag = "UID";
const std::string CmdMsgTag = "CM";
const std::string ReturnValueTag = "RV";
const std::string InputFileTag = "IF";
const std::string OutputFileTag = "OF";
const std::string DataTag = "DA";
const std::string ArgsTag = "AR";
const std::string PidTag = "PI";
const std::string ErrorCodeTag = "EC";

// BundleC2Message tags
const std::string BeaconHashMsgTag = "BH";
const std::string ListenerHashMsgTag = "LH";
const std::string UsernameMsgTag = "UN";
const std::string HostnameMsgTag = "HN";
const std::string ArchMsgTag = "ARC";
const std::string PrivilegeMsgTag = "PR";
const std::string OsMsgTag = "OS";
const std::string LastProofOfLifeMsgTag = "POF";
const std::string SessionsMsgTag = "SS";



//
// C2Message
//
class C2Message
{
public:

	C2Message()
	{
		m_instruction = "";
		m_cmd = "";
		m_returnValue = "";
		m_inputFile = "";
		m_outputFile = "";
		m_data = "";	
		m_args = "";
		m_pid = -100;
		m_errorCode = -1;
		m_uuid = "";
	}

	~C2Message()
	{
	}

	void CopyFrom(C2Message& c2Message)
	{
		m_instruction = c2Message.instruction();
		m_cmd = c2Message.cmd();
		m_returnValue = c2Message.returnvalue();
		m_inputFile = c2Message.inputfile();
		m_outputFile = c2Message.outputfile();
		m_data = c2Message.data();
		m_args = c2Message.args();
		m_pid = c2Message.pid();
		m_errorCode = c2Message.errorCode();
		m_uuid = c2Message.uuid();
	}

	void operator=(const C2Message& c2Message)
	{
		m_instruction = c2Message.instruction();
		m_cmd = c2Message.cmd();
		m_returnValue = c2Message.returnvalue();
		m_inputFile = c2Message.inputfile();
		m_outputFile = c2Message.outputfile();
		m_data = c2Message.data();
		m_args = c2Message.args();
		m_pid = c2Message.pid();
		m_errorCode = c2Message.errorCode();
		m_uuid = c2Message.uuid();
	}

	void ParseFromArray(const char* data, int size)
	{
		std::string input(data, size);
		nlohmann::json my_json;;
		try
		{
			my_json = nlohmann::json::parse(input);
		} 
		catch (...)
		{
			return;
		}

		auto it = my_json.find(InstructionMsgTag);
		if(it != my_json.end())
			m_instruction = my_json[InstructionMsgTag].get<std::string>();

		it = my_json.find(CmdMsgTag);
		if(it != my_json.end())
			m_cmd = my_json[CmdMsgTag].get<std::string>();
		
		it = my_json.find(ReturnValueTag);
		if(it != my_json.end())
		{
			std::string returnValueB64 = my_json[ReturnValueTag].get<std::string>();
			m_returnValue = base64_decode(returnValueB64);
		}
		
		it = my_json.find(InputFileTag);
		if(it != my_json.end())
		{
			std::string inputFileB64 = my_json[InputFileTag].get<std::string>();
			m_inputFile = base64_decode(inputFileB64);
		}
		
		it = my_json.find(OutputFileTag);
		if(it != my_json.end())
		{
			std::string outputFileB64 = my_json[OutputFileTag].get<std::string>();
			m_outputFile = base64_decode(outputFileB64);
		}
		
		it = my_json.find(DataTag);
		if(it != my_json.end())
		{
			std::string dataB64 = my_json[DataTag].get<std::string>();
			m_data = base64_decode(dataB64);
		}
		
		it = my_json.find(ArgsTag);
		if(it != my_json.end())
			m_args = my_json[ArgsTag].get<std::string>();
		
		it = my_json.find(PidTag);
		if(it != my_json.end())
			m_pid = my_json[PidTag].get<int>();

		it = my_json.find(ErrorCodeTag);
		if(it != my_json.end())
			m_errorCode = my_json[ErrorCodeTag].get<int>();

		it = my_json.find(UuidMsgTag);
		if(it != my_json.end())
			m_uuid = my_json[UuidMsgTag].get<std::string>();
	}

	void SerializeToString(std::string* output)
	{
		std::string dataB64 = base64_encode(m_data);
		std::string inputFileB64 = base64_encode(m_inputFile);
		std::string outputFileB64 = base64_encode(m_outputFile);
		std::string returnValueB64 = base64_encode(m_returnValue);

		nlohmann::json finalJson;
		if(!m_instruction.empty())
			finalJson += nlohmann::json::object_t::value_type(InstructionMsgTag, m_instruction);
		if(!m_cmd.empty())
			finalJson += nlohmann::json::object_t::value_type(CmdMsgTag, m_cmd);
		if(!returnValueB64.empty())
			finalJson += nlohmann::json::object_t::value_type(ReturnValueTag, returnValueB64);
		if(!inputFileB64.empty())
			finalJson += nlohmann::json::object_t::value_type(InputFileTag, inputFileB64);
		if(!outputFileB64.empty())
			finalJson += nlohmann::json::object_t::value_type(OutputFileTag, outputFileB64);
		if(!dataB64.empty())
			finalJson += nlohmann::json::object_t::value_type(DataTag, dataB64);
		if(!m_args.empty())
			finalJson += nlohmann::json::object_t::value_type(ArgsTag, m_args);
		if(m_pid!=-100)
			finalJson += nlohmann::json::object_t::value_type(PidTag, m_pid);
		if(m_errorCode!=-1)
			finalJson += nlohmann::json::object_t::value_type(ErrorCodeTag, m_errorCode);
		if(!m_uuid.empty())
			finalJson += nlohmann::json::object_t::value_type(UuidMsgTag, m_uuid);

		std::string json_str = finalJson.dump();
		*output = json_str;
	}

	const std::string& instruction() const
	{
		return m_instruction;
	}
	const std::string& cmd() const
	{
		return m_cmd;
	}
	const std::string& returnvalue() const
	{
		return m_returnValue;
	}
	const std::string& inputfile() const
	{
		return m_inputFile;
	}
	const std::string& outputfile() const
	{
		return m_outputFile;
	}
	const std::string& data() const
	{
		return m_data;
	}
	int pid() const
	{
		return m_pid;
	}
	int errorCode() const
	{
		return m_errorCode;
	}
	const std::string& args() const
	{
		return m_args;
	}
	const std::string& uuid() const
	{
		return m_uuid;
	}

	void set_instruction(const std::string& instruction)
	{
		m_instruction = instruction;
	};
	void set_cmd(const std::string& cmd)
	{
		m_cmd = cmd;
	};
	void set_returnvalue(const std::string& returnValue)
	{
		m_returnValue = returnValue;
	};
	void set_inputfile(const std::string& inputFile)
	{
		m_inputFile = inputFile;
	};
	void set_outputfile(const std::string& outputFile)
	{
		m_outputFile = outputFile;
	};
	void set_data(const char* data, int size)
	{
		m_data.assign(data, size);
	};
	void set_data(const std::string& data)
	{
		m_data.assign(data);
	};
	void set_data(std::string&& data)                                                                                                                    
	{                                                                                                                                                    
			m_data = std::move(data);                                                                                                                    
	}  
	void set_pid(int pid)
	{
		m_pid = pid;
	}; 
	void set_errorCode(int errorCode)
	{
		m_errorCode = errorCode;
	}; 
	void set_args(const std::string& args)
	{
		m_args = args;
	};
	void set_uuid(const std::string& uuid)
	{
		m_uuid = uuid;
	};


private:
	std::string m_instruction;
	std::string m_cmd;
	std::string m_returnValue;
	std::string m_inputFile;
	std::string m_outputFile;
	std::string m_data;	
	std::string m_args;
	int m_pid;
	int m_errorCode;
	std::string m_uuid;
};


//
// BundleC2Message
//
class BundleC2Message
{
public:
	BundleC2Message()
	{
	}

	~BundleC2Message()
	{
		m_c2Messages.clear();
	}


	void ParseFromArray(const char* data, int size)
	{
		std::string input(data, size);
		nlohmann::json bundleC2MessageJson;
		try
		{
			bundleC2MessageJson = nlohmann::json::parse(input);
		} 
		catch (...)
		{
			return;
		}

		auto it = bundleC2MessageJson.find(BeaconHashMsgTag);
		if(it != bundleC2MessageJson.end())
			m_beaconHash = bundleC2MessageJson[BeaconHashMsgTag].get<std::string>();

		it = bundleC2MessageJson.find(ListenerHashMsgTag);
		if(it != bundleC2MessageJson.end())
			m_listenerHash = bundleC2MessageJson[ListenerHashMsgTag].get<std::string>();

		it = bundleC2MessageJson.find(UsernameMsgTag);
		if(it != bundleC2MessageJson.end())
			m_username = bundleC2MessageJson[UsernameMsgTag].get<std::string>();

		it = bundleC2MessageJson.find(HostnameMsgTag);
		if(it != bundleC2MessageJson.end())
			m_hostname = bundleC2MessageJson[HostnameMsgTag].get<std::string>();

		it = bundleC2MessageJson.find(ArchMsgTag);
		if(it != bundleC2MessageJson.end())
			m_arch = bundleC2MessageJson[ArchMsgTag].get<std::string>();

		it = bundleC2MessageJson.find(PrivilegeMsgTag);
		if(it != bundleC2MessageJson.end())
			m_privilege = bundleC2MessageJson[PrivilegeMsgTag].get<std::string>();

		it = bundleC2MessageJson.find(OsMsgTag);
		if(it != bundleC2MessageJson.end())
			m_os = bundleC2MessageJson[OsMsgTag].get<std::string>();

		it = bundleC2MessageJson.find(LastProofOfLifeMsgTag);
		if(it != bundleC2MessageJson.end())
			m_lastProofOfLife = bundleC2MessageJson[LastProofOfLifeMsgTag].get<std::string>();

		auto sessions = bundleC2MessageJson[SessionsMsgTag];
	
		for (nlohmann::json::iterator it = sessions.begin(); it != sessions.end(); ++it)
		{
			std::unique_ptr<C2Message> c2Message = std::make_unique<C2Message>();
			m_c2Messages.push_back(std::move(c2Message));

			std::string json_str = (*it).dump();
			m_c2Messages.back()->ParseFromArray(json_str.data(), json_str.size());
		}
		
	}

	void SerializeToString(std::string* output)
	{
		nlohmann::json sessions;
		for (int i = 0; i < m_c2Messages.size(); i++)
		{
			std::string json_str;
			m_c2Messages[i]->SerializeToString(&json_str);

			nlohmann::json tmp;
			try
			{
				tmp = nlohmann::json::parse(json_str);
			} 
			catch (...)
			{
				continue;
			}

			sessions.push_back(tmp);
		}

		nlohmann::json bundleC2MessageJson ;
		if(!m_beaconHash.empty())
			bundleC2MessageJson += nlohmann::json::object_t::value_type(BeaconHashMsgTag, m_beaconHash);
		if(!m_listenerHash.empty())
			bundleC2MessageJson += nlohmann::json::object_t::value_type(ListenerHashMsgTag, m_listenerHash);
		if(!m_username.empty())
			bundleC2MessageJson += nlohmann::json::object_t::value_type(UsernameMsgTag, m_username);
		if(!m_hostname.empty())
			bundleC2MessageJson += nlohmann::json::object_t::value_type(HostnameMsgTag, m_hostname);
		if(!m_arch.empty())
			bundleC2MessageJson += nlohmann::json::object_t::value_type(ArchMsgTag, m_arch);
		if(!m_privilege.empty())
			bundleC2MessageJson += nlohmann::json::object_t::value_type(PrivilegeMsgTag, m_privilege);
		if(!m_os.empty())
			bundleC2MessageJson += nlohmann::json::object_t::value_type(OsMsgTag, m_os);
		if(!m_lastProofOfLife.empty())
			bundleC2MessageJson += nlohmann::json::object_t::value_type(LastProofOfLifeMsgTag, m_lastProofOfLife);
		if(!sessions.empty())
			bundleC2MessageJson += nlohmann::json::object_t::value_type(SessionsMsgTag, sessions);

		*output = bundleC2MessageJson.dump();
	}

	int c2messages_size()
	{
		return m_c2Messages.size();
	}
	
	C2Message c2messages(int id)
	{
		if(id<m_c2Messages.size())
		{
			C2Message c2Message;
			c2Message=(*m_c2Messages[id]);
			return c2Message;
		}
		else
		{
			C2Message c2Message;
			return c2Message;
		}
	}

	C2Message* add_c2messages()
	{
		std::unique_ptr<C2Message> c2Message = std::make_unique<C2Message>();
		m_c2Messages.push_back(std::move(c2Message));
		return m_c2Messages.back().get();
	}

	C2Message* add_c2messages(C2Message& c2Message)                       
	{                                                                     
			m_c2Messages.emplace_back(std::make_unique<C2Message>(std::move(c2Message)));                                                                
			return m_c2Messages.back().get();                                                                                                            
	}  

	const std::string&  beaconhash() const
	{
		return m_beaconHash;
	}
	const std::string&  listenerhash() const
	{
		return m_listenerHash;
	}
	const std::string&  username() const
	{
		return m_username;
	}
	const std::string&  hostname() const
	{
		return m_hostname;
	}
	const std::string&  arch() const
	{
		return m_arch;
	}
	const std::string&  privilege() const
	{
		return m_privilege;
	}
	const std::string&  os() const
	{
		return m_os;
	}
	const std::string&  lastProofOfLife() const
	{
		return m_lastProofOfLife;
	}

	void set_beaconhash(const std::string& beaconHash)
	{
		m_beaconHash = beaconHash;
	}
	void set_listenerhash(const std::string& listenerHash)
	{
		m_listenerHash = listenerHash;
	}
	void set_username(const std::string& username)
	{
		m_username = username;
	}
	void set_hostname(const std::string& hostname)
	{
		m_hostname = hostname;
	}
	void set_arch(const std::string& arch)
	{
		m_arch = arch;
	}
	void set_privilege(const std::string& privilege)
	{
		m_privilege = privilege;
	}
	void set_os(const std::string& os)
	{
		m_os = os;
	}
	void set_lastProofOfLife(const std::string& lastProofOfLife)
	{
		m_lastProofOfLife = lastProofOfLife;
	}

private:
	std::vector<std::unique_ptr<C2Message>> m_c2Messages;

	std::string m_beaconHash;
	std::string m_listenerHash;
	std::string m_username;
	std::string m_hostname;
	std::string m_arch;
	std::string m_privilege;
	std::string m_os;
	std::string m_lastProofOfLife;
};


//
// MultiBundleC2Message
//
class MultiBundleC2Message
{
public:
	MultiBundleC2Message()
	{
	}
	~MultiBundleC2Message()
	{
		m_bundleC2Messages.clear();
	}

	void ParseFromArray(const char* data, int size)
	{
		std::string input(data, size);
		nlohmann::json my_json;
		try
		{
			my_json = nlohmann::json::parse(input);
		} 
		catch (...)
		{
			return;
		}

		for (nlohmann::json::iterator it = my_json.begin(); it != my_json.end(); ++it)
		{
			std::unique_ptr<BundleC2Message> bundleC2Message = std::make_unique<BundleC2Message>();
			m_bundleC2Messages.push_back(std::move(bundleC2Message));

			std::string json_str = (*it).dump();	
			m_bundleC2Messages.back()->ParseFromArray(json_str.data(), json_str.size());
		}
	}

	void SerializeToString(std::string* output)
	{
		nlohmann::json agregator;
		for (int i = 0; i < m_bundleC2Messages.size(); i++)
		{
			std::string json_str;
			m_bundleC2Messages[i]->SerializeToString(&json_str);

			nlohmann::json tmp ;
			try
			{
				tmp = nlohmann::json::parse(json_str);
			} 
			catch (...)
			{
				continue;
			}

			agregator.push_back(tmp);
		}
		*output = agregator.dump();
	}

	int bundlec2messages_size()
	{
		return m_bundleC2Messages.size();
	}

	BundleC2Message* bundlec2messages(int id)
	{
		if(id<m_bundleC2Messages.size())
			return m_bundleC2Messages[id].get();
		else
		{
			return nullptr;
		}
	}

	BundleC2Message* add_bundlec2messages()
	{
		std::unique_ptr<BundleC2Message> bundleC2Message = std::make_unique<BundleC2Message>();
		m_bundleC2Messages.push_back(std::move(bundleC2Message));
		return m_bundleC2Messages.back().get();
	}

private:
	std::vector<std::unique_ptr<BundleC2Message>> m_bundleC2Messages;

};
