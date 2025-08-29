#include "BeaconSmb.hpp"

int main() {
    std::string config = R"({"xorKey":"key","ModulesConfig":{}})";
    std::string host = "localhost";
    std::string pipe = "test";
    BeaconSmb b(config, host, pipe);
    return 0;
}
