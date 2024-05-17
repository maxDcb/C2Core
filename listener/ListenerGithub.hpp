#pragma once

#include "Listener.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"


class ListenerGithub : public Listener
{

public:
	ListenerGithub(const std::string& project, const std::string& token);
	~ListenerGithub();

private:
	void checkGithubIssues();
	int HandleCheckIn(const std::string& req, std::string& res);

	std::string m_project;
	std::string m_token;

	bool m_isRunning;
	std::unique_ptr<std::thread> m_githubFetcher;
};
