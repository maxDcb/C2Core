#include "ListenerTcp.hpp"

#include <SocketClient.hpp>
#include <SocketServer.hpp>
#include "../../TcpFrameBuffer.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

class TestListenerTcp : public ListenerTcp
{
public:
    using ListenerTcp::ListenerTcp;

    std::string encode(MultiBundleC2Message& message)
    {
        std::string data;
        message.SerializeToString(&data);
        XOR(data, m_key);
        return base64_encode(data);
    }

    bool preservesTaskAfterFailedSend(const std::string& request, const std::string& beaconHash)
    {
        std::string response;
        handleMessages(request, response); // Register the session.

        C2Message task;
        task.set_instruction("tcp-retry-task");
        queueTask(beaconHash, task);

        std::vector<PendingTask> firstAttempt;
        handleMessages(request, response, &firstAttempt);
        if (firstAttempt.size() != 1 || firstAttempt.front().second.instruction() != "tcp-retry-task")
            return false;

        restoreTasks(firstAttempt); // Simulate a failed socket send.
        std::vector<PendingTask> retry;
        handleMessages(request, response, &retry);
        return retry.size() == 1 && retry.front().second.instruction() == "tcp-retry-task";
    }
};

int main()
{
    std::filesystem::create_directories("logs");

    TcpFrameBuffer frameBuffer;
    std::vector<std::string> parsedFrames;
    if (!frameBuffer.append("first<TCP-6", parsedFrames) || !parsedFrames.empty() ||
        !frameBuffer.append("66>second<TCP-666>third<TCP", parsedFrames) ||
        parsedFrames != std::vector<std::string>({"first", "second"}))
    {
        std::cerr << "TCP frames were not reassembled in order" << std::endl;
        return 1;
    }
    parsedFrames.clear();
    if (!frameBuffer.append("-666>", parsedFrames) ||
        parsedFrames != std::vector<std::string>({"third"}))
    {
        std::cerr << "Split TCP delimiter was not reassembled" << std::endl;
        return 1;
    }

    int port = 0;
    {
        SocketServer occupied(0);
        occupied.launch();
        if (!occupied.isServerLaunched())
        {
            std::cerr << "Could not reserve a loopback port" << std::endl;
            return 1;
        }
        port = occupied.getServerPort();
        TestListenerTcp blocked("127.0.0.1", port);
        if (blocked.init() != -1)
        {
            std::cerr << "Listener accepted an occupied port" << std::endl;
            return 1;
        }
    }

    TestListenerTcp listener("127.0.0.1", port);
    if (listener.init() != 1)
    {
        std::cerr << "Listener did not start after the port was released" << std::endl;
        return 1;
    }

    SocketTunnelClient client;
    if (!client.init("127.0.0.1", port))
    {
        std::cerr << "Client did not connect to listener" << std::endl;
        return 1;
    }

    MultiBundleC2Message request;
    auto* bundle = request.add_bundlec2messages();
    bundle->set_beaconhash("TCPFRAMETEST1234TCPFRAMETEST1234");
    bundle->set_lastProofOfLife("0");
    const std::string wire = listener.encode(request) + TcpFrameBuffer::delimiter();
    TestListenerTcp recovery("127.0.0.1", 0);
    if (!recovery.preservesTaskAfterFailedSend(recovery.encode(request), bundle->beaconhash()))
    {
        std::cerr << "Failed TCP send did not preserve the queued task" << std::endl;
        return 1;
    }
    const std::size_t firstCut = wire.size() / 2;
    const std::size_t secondCut = wire.size() - 3;
    std::string reply;
    client.process(wire.substr(0, firstCut), reply);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    if (listener.getNumberOfSession() != 0)
    {
        std::cerr << "Listener handled an incomplete payload" << std::endl;
        return 1;
    }

    client.process(wire.substr(firstCut, secondCut - firstCut), reply);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    if (listener.getNumberOfSession() != 0)
    {
        std::cerr << "Listener handled a frame without its full delimiter" << std::endl;
        return 1;
    }

    TcpFrameBuffer replies;
    std::vector<std::string> frames;
    client.process(wire.substr(secondCut), reply);
    replies.append(reply, frames);
    for (int i = 0; i < 100 && (listener.getNumberOfSession() != 1 || frames.empty()); ++i)
    {
        client.process("", reply);
        replies.append(reply, frames);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (listener.getNumberOfSession() != 1 || frames.size() != 1)
    {
        std::cerr << "Listener did not reassemble the TCP frame" << std::endl;
        return 1;
    }
    return 0;
}
