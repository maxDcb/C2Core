#include "BeaconDns.hpp"

int main() {
    std::string config = R"({"xorKey":"key","ModulesConfig":{}})";
    std::string dnsServer = "8.8.8.8";
    std::string domain = "example.com";
    BeaconDns b(config, dnsServer, domain);
    return 0;
}
