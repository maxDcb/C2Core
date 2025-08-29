#include "BeaconTcp.hpp"

int main() {
    std::string config = R"({"xorKey":"key","ModulesConfig":{}})";
    std::string ip = "127.0.0.1";
    int port = 1;
    BeaconTcp b(config, ip, port);
    return 0;
}
