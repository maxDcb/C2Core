#include "SshExec.hpp"

#include "Common.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <libssh2.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <netdb.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

using namespace std;

constexpr std::string_view moduleNameSshExec = "sshExec";
constexpr unsigned long long moduleHashSshExec = djb2(moduleNameSshExec);

#ifdef _WIN32
extern "C" __declspec(dllexport) SshExec* SshExecConstructor()
{
    return new SshExec();
}
#else
extern "C" __attribute__((visibility("default"))) SshExec* SshExecConstructor()
{
    return new SshExec();
}
#endif

namespace
{
#ifdef _WIN32
    using SocketHandle = SOCKET;
    constexpr SocketHandle InvalidSocket = INVALID_SOCKET;

    std::string formatWindowsError(int errorCode)
    {
        LPVOID lpMsgBuf = nullptr;
        DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
        DWORD lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
        DWORD size = FormatMessageA(flags, nullptr, static_cast<DWORD>(errorCode), lang, reinterpret_cast<LPSTR>(&lpMsgBuf), 0, nullptr);
        std::string message;
        if (size && lpMsgBuf)
        {
            message.assign(static_cast<LPSTR>(lpMsgBuf), size);
            LocalFree(lpMsgBuf);
        }
        else
        {
            message = "error code " + std::to_string(errorCode);
        }
        return message;
    }

    std::string lastSocketError()
    {
        return formatWindowsError(WSAGetLastError());
    }

    void closeSocket(SocketHandle socket)
    {
        if (socket != InvalidSocket)
        {
            closesocket(socket);
        }
    }

    class WsaInitializer
    {
    public:
        WsaInitializer()
        {
            int rc = WSAStartup(MAKEWORD(2, 2), &m_data);
            m_success = (rc == 0);
            if (!m_success)
            {
                m_error = formatWindowsError(rc);
            }
        }

        ~WsaInitializer()
        {
            if (m_success)
            {
                WSACleanup();
            }
        }

        bool ok() const
        {
            return m_success;
        }

        const std::string& error() const
        {
            return m_error;
        }

    private:
        WSADATA m_data{};
        bool m_success = false;
        std::string m_error;
    };
#else
    using SocketHandle = int;
    constexpr SocketHandle InvalidSocket = -1;

    std::string lastSocketError()
    {
        return std::strerror(errno);
    }

    void closeSocket(SocketHandle socket)
    {
        if (socket != InvalidSocket)
        {
            ::close(socket);
        }
    }
#endif

    class Libssh2Initializer
    {
    public:
        Libssh2Initializer()
        {
            m_result = libssh2_init(0);
        }

        ~Libssh2Initializer()
        {
            if (m_result == 0)
            {
                libssh2_exit();
            }
        }

        bool ok() const
        {
            return m_result == 0;
        }

        int errorCode() const
        {
            return m_result;
        }

    private:
        int m_result;
    };

    std::string makeHex(const unsigned char* data, size_t length)
    {
        if (!data || length == 0)
        {
            return {};
        }
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < length; ++i)
        {
            oss << std::setw(2) << static_cast<unsigned int>(data[i]);
        }
        return oss.str();
    }

    std::string lastLibssh2Error(LIBSSH2_SESSION* session, int code)
    {
        if (!session)
        {
            return "libssh2 error code " + std::to_string(code);
        }
        char* msg = nullptr;
        int len = 0;
        libssh2_session_last_error(session, &msg, &len, 0);
        if (msg && len > 0)
        {
            return std::string(msg, len);
        }
        return "libssh2 error code " + std::to_string(code);
    }
}

SshExec::SshExec()
#ifdef BUILD_TEAMSERVER
    : ModuleCmd(std::string(moduleNameSshExec), moduleHashSshExec)
#else
    : ModuleCmd("", moduleHashSshExec)
#endif
{
}

SshExec::~SshExec() = default;

std::string SshExec::getInfo()
{
    std::ostringstream oss;
#ifdef BUILD_TEAMSERVER
    oss << "SSH Exec Module:\n";
    oss << "Execute a command on a remote SSH server using username/password authentication.\n";
    oss << "Works against both Linux and Windows SSH servers.\n";
    oss << "Options:\n";
    oss << "  -h, --host <host>         Target hostname or IP.\n";
    oss << "  -P, --port <port>         SSH port (default 22).\n";
    oss << "  -u, --user <user>         Username.\n";
    oss << "  -p, --password <pass>     Password.\n";
    oss << "  -c, --command <cmd>       Command to execute.\n";
    oss << "  --                        Treat the rest of the line as the command.\n";
    oss << "Example:\n";
    oss << "  sshExec -h 10.0.0.5 -u admin -p Passw0rd! -c \"ipconfig /all\"\n";
    oss << "  sshExec -h server -- user pass -- \"/bin/echo hello\"\n";
#endif
    return oss.str();
}

std::string SshExec::packParameters(const Parameters& params) const
{
    std::string packed;
    auto append = [&packed](const std::string& value)
    {
        packed.append(value);
        packed.push_back('\0');
    };

    append(params.host);
    append(params.port);
    append(params.username);
    append(params.password);
    append(params.command);
    return packed;
}

SshExec::Parameters SshExec::unpackParameters(const std::string& data) const
{
    Parameters params;
    std::vector<std::string> parts;
    size_t start = 0;
    while (start < data.size())
    {
        size_t end = data.find('\0', start);
        if (end == std::string::npos)
        {
            break;
        }
        parts.emplace_back(data.substr(start, end - start));
        start = end + 1;
    }

    if (parts.size() >= 5)
    {
        params.host = parts[0];
        params.port = parts[1];
        params.username = parts[2];
        params.password = parts[3];
        params.command = parts[4];
    }
    return params;
}

int SshExec::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    std::vector<std::string> args = regroupStrings(splitedCmd);
    if (args.size() < 2)
    {
        c2Message.set_returnvalue(getInfo());
        return -1;
    }

    Parameters params;
    bool collectCommandTail = false;

    for (size_t i = 1; i < args.size(); ++i)
    {
        const std::string& token = args[i];
        if (collectCommandTail)
        {
            if (!params.command.empty())
            {
                params.command += " ";
            }
            params.command += token;
            continue;
        }

        if (token == "--")
        {
            collectCommandTail = true;
            continue;
        }

        if ((token == "-h" || token == "--host") && i + 1 < args.size())
        {
            params.host = args[++i];
        }
        else if ((token == "-P" || token == "--port") && i + 1 < args.size())
        {
            params.port = args[++i];
        }
        else if ((token == "-u" || token == "--user") && i + 1 < args.size())
        {
            params.username = args[++i];
        }
        else if ((token == "-p" || token == "--password") && i + 1 < args.size())
        {
            params.password = args[++i];
        }
        else if ((token == "-c" || token == "--command") && i + 1 < args.size())
        {
            params.command = args[++i];
        }
        else if (!token.empty() && token.front() != '-')
        {
            if (params.host.empty())
            {
                params.host = token;
            }
            else if (params.username.empty())
            {
                params.username = token;
            }
            else if (params.password.empty())
            {
                params.password = token;
            }
            else
            {
                if (!params.command.empty())
                {
                    params.command += " ";
                }
                params.command += token;
            }
        }
    }

    if (params.host.empty() || params.username.empty() || params.password.empty() || params.command.empty())
    {
        c2Message.set_returnvalue("Missing required parameters.\n" + getInfo());
        return -1;
    }

    c2Message.set_instruction(splitedCmd[0]);
    c2Message.set_cmd(packParameters(params));
#endif
    return 0;
}

int SshExec::process(C2Message& c2Message, C2Message& c2RetMessage)
{
    c2RetMessage.set_instruction(c2Message.instruction());
    c2RetMessage.set_cmd(c2Message.cmd());

    Parameters params = unpackParameters(c2Message.cmd());
    std::string result;
    int error = executeSshCommand(params, result);

    if (error != 0)
    {
        c2RetMessage.set_errorCode(error);
    }

    c2RetMessage.set_returnvalue(result);
    return 0;
}

int SshExec::errorCodeToMsg(const C2Message& c2RetMessage, std::string& errorMsg)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) || defined(C2CORE_BUILD_TESTS)
    int errorCode = c2RetMessage.errorCode();
    if (errorCode > 0)
    {
        errorMsg = c2RetMessage.returnvalue();
    }
#endif
    return 0;
}

int SshExec::executeSshCommand(const Parameters& params, std::string& result) const
{
    result.clear();

    if (params.host.empty() || params.username.empty() || params.password.empty() || params.command.empty())
    {
        result = "Invalid parameters.";
        return ErrorExecute;
    }

#ifdef _WIN32
    WsaInitializer wsa;
    if (!wsa.ok())
    {
        result = "WSAStartup failed: " + wsa.error();
        return ErrorSocketInit;
    }
#endif

    Libssh2Initializer sshInit;
    if (!sshInit.ok())
    {
        result = "Failed to initialize libssh2 (" + std::to_string(sshInit.errorCode()) + ").";
        return ErrorLibssh2Init;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* rawInfo = nullptr;
    int addrRc = getaddrinfo(params.host.c_str(), params.port.c_str(), &hints, &rawInfo);
    if (addrRc != 0)
    {
#ifdef _WIN32
        result = "getaddrinfo failed: " + std::string(gai_strerrorA(addrRc));
#else
        result = "getaddrinfo failed: " + std::string(gai_strerror(addrRc));
#endif
        return ErrorResolve;
    }

    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addrList(rawInfo, freeaddrinfo);

    SocketHandle socket = InvalidSocket;
    for (addrinfo* ptr = addrList.get(); ptr != nullptr; ptr = ptr->ai_next)
    {
        SocketHandle candidate = static_cast<SocketHandle>(::socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol));
        if (candidate == InvalidSocket)
        {
            continue;
        }

        if (::connect(candidate, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)) == 0)
        {
            socket = candidate;
            break;
        }

        closeSocket(candidate);
    }

    if (socket == InvalidSocket)
    {
        result = "Unable to connect to " + params.host + ":" + params.port + " (" + lastSocketError() + ").";
        return ErrorConnect;
    }

    LIBSSH2_SESSION* session = libssh2_session_init();
    if (!session)
    {
        closeSocket(socket);
        result = "Failed to create SSH session.";
        return ErrorSessionInit;
    }

    bool handshakeDone = false;
    libssh2_session_set_blocking(session, 1);

    int rc = libssh2_session_handshake(session, socket);
    if (rc != 0)
    {
        std::string message = lastLibssh2Error(session, rc);
        libssh2_session_free(session);
        closeSocket(socket);
        result = "SSH handshake failed: " + message;
        return ErrorHandshake;
    }
    handshakeDone = true;

    rc = libssh2_userauth_password(session, params.username.c_str(), params.password.c_str());
    if (rc != 0)
    {
        std::string message = lastLibssh2Error(session, rc);
        if (handshakeDone)
        {
            libssh2_session_disconnect(session, "Authentication failed");
        }
        libssh2_session_free(session);
        closeSocket(socket);
        result = "Authentication failed: " + message;
        return ErrorAuthentication;
    }

    LIBSSH2_CHANNEL* channel = libssh2_channel_open_session(session);
    if (!channel)
    {
        libssh2_session_disconnect(session, "Failed to open channel");
        libssh2_session_free(session);
        closeSocket(socket);
        result = "Failed to open SSH channel.";
        return ErrorChannelOpen;
    }

    rc = libssh2_channel_exec(channel, params.command.c_str());
    if (rc != 0)
    {
        std::string message = lastLibssh2Error(session, rc);
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        libssh2_session_disconnect(session, "Command execution failed");
        libssh2_session_free(session);
        closeSocket(socket);
        result = "Failed to execute command: " + message;
        return ErrorExecute;
    }

    std::string stdoutData;
    std::string stderrData;
    std::array<char, 4096> buffer{};

    while (true)
    {
        ssize_t bytes = libssh2_channel_read(channel, buffer.data(), buffer.size());
        if (bytes > 0)
        {
            stdoutData.append(buffer.data(), static_cast<size_t>(bytes));
        }
        else if (bytes == LIBSSH2_ERROR_EAGAIN)
        {
            continue;
        }
        else
        {
            break;
        }
    }

    while (true)
    {
        ssize_t bytes = libssh2_channel_read_ex(channel, SSH_EXTENDED_DATA_STDERR, buffer.data(), buffer.size());
        if (bytes > 0)
        {
            stderrData.append(buffer.data(), static_cast<size_t>(bytes));
        }
        else if (bytes == LIBSSH2_ERROR_EAGAIN)
        {
            continue;
        }
        else
        {
            break;
        }
    }

    libssh2_channel_close(channel);
    libssh2_channel_wait_closed(channel);
    int exitStatus = libssh2_channel_get_exit_status(channel);
    libssh2_channel_free(channel);

    const unsigned char* fingerprint = reinterpret_cast<const unsigned char*>(libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256));
    std::string fingerprintHex = makeHex(fingerprint, fingerprint ? 32 : 0);

    libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    closeSocket(socket);

    std::ostringstream oss;
    if (!fingerprintHex.empty())
    {
        oss << "HostKey SHA256: " << fingerprintHex << "\n";
    }
    oss << "STDOUT:\n" << stdoutData;
    if (!stdoutData.empty() && stdoutData.back() != '\n')
    {
        oss << '\n';
    }
    if (!stderrData.empty())
    {
        oss << "STDERR:\n" << stderrData;
        if (stderrData.back() != '\n')
        {
            oss << '\n';
        }
    }
    oss << "ExitCode: " << exitStatus << "\n";

    result = oss.str();
    return 0;
}
