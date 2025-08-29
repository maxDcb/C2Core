#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "BeaconGithub.hpp"

int main() {
    std::string config = R"({"xorKey":"key","ModulesConfig":{}})";
    std::string project = "project";
    std::string token = "token";
    BeaconGithub b(config, project, token);
    return 0;
}
