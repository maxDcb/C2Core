#include "ListenerDns.hpp"
#include <server.hpp>

int main()
{
    dns::Server reservation(0, "listener.test");
    if (!reservation.launch())
        return 1;
    const int port = reservation.getPort();
    reservation.stop();

    ListenerDns listener("listener.test", port);
    if (listener.init() != 1)
        return 1;
    if (!listener.isRunning())
        return 1;

    ListenerDns conflicting("listener.test", port);
    if (conflicting.init() != -1)
        return 1;
    if (conflicting.isRunning())
        return 1;

    return 0;
}
