#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "BeaconHttp.hpp"

int main() {
    std::string config = R"({
        "xorKey":"key",
        "ModulesConfig":{},
        "ListenerHttpConfig":{
            "uri":["/checkin"],
            "client":{"headers":{}}
        }
    })";
    std::string ip = "127.0.0.1";
    int port = 1;
    BeaconHttp b(config, ip, port, false);
    b.checkIn();
    return b.hasPendingOutputForTest() ? 0 : 1;
}
