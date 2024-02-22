#pragma once

#include "Beacon.hpp"


class BeaconGithub : public Beacon
{

public:
	BeaconGithub(const std::string& project, const std::string& token);
	~BeaconGithub();

	void checkIn();

private:	
	std::string m_project;
	std::string m_token;

#ifdef _WIN32
	int GithubPost(const std::string& domain, const std::string& url, const std::string& data);
	int GithubGet(const std::string& domain, const std::string& url);
#endif

};
