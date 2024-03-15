#pragma once

#include <iostream>
#include <fstream>
#include <memory>
#include <chrono>
#include <random>
#include <vector>
#include <thread>

#include <base64.h>
#include <json.hpp>


using json = nlohmann::json;


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
	}

	void ParseFromArray(const char* data, int size)
	{
		std::string input(data, size);
		auto my_json = json::parse(input);

		auto it = my_json.find("instruction");
		if(it != my_json.end())
			m_instruction = my_json["instruction"].get<std::string>();

		it = my_json.find("cmd");
		if(it != my_json.end())
			m_cmd = my_json["cmd"].get<std::string>();
		
		it = my_json.find("returnValue");
		if(it != my_json.end())
		{
			std::string returnValueB64 = my_json["returnValue"].get<std::string>();
			m_returnValue = base64_decode(returnValueB64);
		}
		
		it = my_json.find("inputFile");
		if(it != my_json.end())
		{
			std::string inputFileB64 = my_json["inputFile"].get<std::string>();
			m_inputFile = base64_decode(inputFileB64);
		}
		
		it = my_json.find("outputFile");
		if(it != my_json.end())
		{
			std::string outputFileB64 = my_json["outputFile"].get<std::string>();
			m_outputFile = base64_decode(outputFileB64);
		}
		
		it = my_json.find("data");
		if(it != my_json.end())
		{
			std::string dataB64 = my_json["data"].get<std::string>();
			m_data = base64_decode(dataB64);
		}
		
		it = my_json.find("args");
		if(it != my_json.end())
			m_args = my_json["args"].get<std::string>();
		
		it = my_json.find("pid");
		if(it != my_json.end())
			m_pid = my_json["pid"].get<int>();
	}
	void SerializeToString(std::string* output)
	{
		std::string dataB64 = base64_encode(m_data);
		std::string inputFileB64 = base64_encode(m_inputFile);
		std::string outputFileB64 = base64_encode(m_outputFile);
		std::string returnValueB64 = base64_encode(m_returnValue);

		json finalJson;
		if(!m_instruction.empty())
			finalJson += json::object_t::value_type("instruction", m_instruction);
		if(!m_cmd.empty())
			finalJson += json::object_t::value_type("cmd", m_cmd);
		if(!returnValueB64.empty())
			finalJson += json::object_t::value_type("returnValue", returnValueB64);
		if(!inputFileB64.empty())
			finalJson += json::object_t::value_type("inputFile", inputFileB64);
		if(!outputFileB64.empty())
			finalJson += json::object_t::value_type("outputFile", outputFileB64);
		if(!dataB64.empty())
			finalJson += json::object_t::value_type("data", dataB64);
		if(!m_args.empty())
			finalJson += json::object_t::value_type("args", m_args);
		if(m_pid!=-100)
			finalJson += json::object_t::value_type("pid", m_pid);

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
	const std::string& args() const
	{
		return m_args;
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
	void set_pid(int pid)
	{
		m_pid = pid;
	}; 
	void set_args(const std::string& args)
	{
		m_args = args;
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
};


class BundleC2Message
{
public:
	BundleC2Message()
	{
	}
	~BundleC2Message()
	{
		for (auto p : m_c2Messages)
		{
			delete p;
		} 
		m_c2Messages.clear();
	}


	void ParseFromArray(const char* data, int size)
	{
		std::string input(data, size);
		auto bundleC2MessageJson = json::parse(input);

		auto it = bundleC2MessageJson.find("beaconHash");
		if(it != bundleC2MessageJson.end())
			m_beaconHash = bundleC2MessageJson["beaconHash"].get<std::string>();

		it = bundleC2MessageJson.find("listenerHash");
		if(it != bundleC2MessageJson.end())
			m_listenerHash = bundleC2MessageJson["listenerHash"].get<std::string>();

		it = bundleC2MessageJson.find("username");
		if(it != bundleC2MessageJson.end())
			m_username = bundleC2MessageJson["username"].get<std::string>();

		it = bundleC2MessageJson.find("hostname");
		if(it != bundleC2MessageJson.end())
			m_hostname = bundleC2MessageJson["hostname"].get<std::string>();

		it = bundleC2MessageJson.find("arch");
		if(it != bundleC2MessageJson.end())
			m_arch = bundleC2MessageJson["arch"].get<std::string>();

		it = bundleC2MessageJson.find("privilege");
		if(it != bundleC2MessageJson.end())
			m_privilege = bundleC2MessageJson["privilege"].get<std::string>();

		it = bundleC2MessageJson.find("os");
		if(it != bundleC2MessageJson.end())
			m_os = bundleC2MessageJson["os"].get<std::string>();

		it = bundleC2MessageJson.find("lastProofOfLife");
		if(it != bundleC2MessageJson.end())
			m_lastProofOfLife = bundleC2MessageJson["lastProofOfLife"].get<std::string>();

		auto sessions = bundleC2MessageJson["sessions"];
	
		for (json::iterator it = sessions.begin(); it != sessions.end(); ++it)
		{
			C2Message* c2Message = new C2Message();
			m_c2Messages.push_back(std::move(c2Message));

			std::string json_str = (*it).dump();
			m_c2Messages.back()->ParseFromArray(json_str.data(), json_str.size());
		}
		
	}
	void SerializeToString(std::string* output)
	{
		json sessions;
		for (int i = 0; i < m_c2Messages.size(); i++)
		{
			std::string json_str;
			m_c2Messages[i]->SerializeToString(&json_str);

			json tmp = json::parse(json_str);

			sessions.push_back(tmp);
		}

		json bundleC2MessageJson ;
		if(!m_beaconHash.empty())
			bundleC2MessageJson += json::object_t::value_type("beaconHash", m_beaconHash);
		if(!m_listenerHash.empty())
			bundleC2MessageJson += json::object_t::value_type("listenerHash", m_listenerHash);
		if(!m_username.empty())
			bundleC2MessageJson += json::object_t::value_type("username", m_username);
		if(!m_hostname.empty())
			bundleC2MessageJson += json::object_t::value_type("hostname", m_hostname);
		if(!m_arch.empty())
			bundleC2MessageJson += json::object_t::value_type("arch", m_arch);
		if(!m_privilege.empty())
			bundleC2MessageJson += json::object_t::value_type("privilege", m_privilege);
		if(!m_os.empty())
			bundleC2MessageJson += json::object_t::value_type("os", m_os);
		if(!m_lastProofOfLife.empty())
			bundleC2MessageJson += json::object_t::value_type("lastProofOfLife", m_lastProofOfLife);
		if(!sessions.empty())
			bundleC2MessageJson += json::object_t::value_type("sessions", sessions);

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
		C2Message* c2Message = new C2Message();
		m_c2Messages.push_back(std::move(c2Message));
		return m_c2Messages.back();
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
	std::vector<C2Message*> m_c2Messages;

	std::string m_beaconHash;
	std::string m_listenerHash;
	std::string m_username;
	std::string m_hostname;
	std::string m_arch;
	std::string m_privilege;
	std::string m_os;
	std::string m_lastProofOfLife;
};


class MultiBundleC2Message
{
public:
	MultiBundleC2Message()
	{
	}
	~MultiBundleC2Message()
	{
		for (auto p : m_bundleC2Messages)
		{
			delete p;
		} 
		m_bundleC2Messages.clear();
	}

	void ParseFromArray(const char* data, int size)
	{
		std::string input(data, size);
		json my_json = json::parse(input);

		for (json::iterator it = my_json.begin(); it != my_json.end(); ++it)
		{
			BundleC2Message* bundleC2Message = new BundleC2Message();
			m_bundleC2Messages.push_back(std::move(bundleC2Message));

			std::string json_str = (*it).dump();	
			m_bundleC2Messages.back()->ParseFromArray(json_str.data(), json_str.size());
		}
	}
	void SerializeToString(std::string* output)
	{
		json agregator;
		for (int i = 0; i < m_bundleC2Messages.size(); i++)
		{
			std::string json_str;
			m_bundleC2Messages[i]->SerializeToString(&json_str);

			json tmp = json::parse(json_str);

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
			return m_bundleC2Messages[id];
		else
		{
			return nullptr;
		}
	}

	BundleC2Message* add_bundlec2messages()
	{
		BundleC2Message* bundleC2Message = new BundleC2Message();
		m_bundleC2Messages.push_back(std::move(bundleC2Message));
		return m_bundleC2Messages.back();
	}

private:
	std::vector<BundleC2Message*> m_bundleC2Messages;

};


class ModuleCmd
{
	
public:
	ModuleCmd(const std::string& name);
	~ModuleCmd();

	std::string getName()
	{
		return m_name;
	}

	virtual std::string getInfo() = 0;

	// if an error ocurre:
	// set_returnvalue(errorMsg) && return -1
	virtual int init(std::vector<std::string>& splitedCmd, C2Message& c2Message) = 0;
	virtual int process(C2Message& c2Message, C2Message& c2RetMessage) = 0;
	virtual int followUp(const C2Message &c2RetMessage) {return 0;};

protected:
	std::string m_name;

private:
	
};
