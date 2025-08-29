#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "BeaconHttp.hpp"

int main() {
    std::string config = R"({"xorKey":"key","ModulesConfig":{}})";
    std::string ip = "127.0.0.1";
    int port = 8080;
    BeaconHttp b(config, ip, port, false);
    return 0;
}
