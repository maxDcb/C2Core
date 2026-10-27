#include "../Netstat.hpp"

bool testNetstat();

int main()
{
    bool res;
    std::cout << "[+] testNetstat" << std::endl;
    res = testNetstat();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;
    return !res;
}

bool testNetstat()
{
#ifndef _WIN32
    if (netstat_detail::formatProcSocketLine(
            "0: 0100007F:0016 00000000:0000 0A", "TCP", false)
        != "TCP 127.0.0.1:22 -> 0.0.0.0:0 State:LISTEN(0A)\n") return false;
    if (netstat_detail::formatProcSocketLine(
            "1: 0201A8C0:1F90 0100007F:0050 01", "TCP", false)
        != "TCP 192.168.1.2:8080 -> 127.0.0.1:80 State:ESTABLISHED(01)\n") return false;
    if (netstat_detail::formatProcSocketLine(
            "2: 00000000000000000000000001000000:1383 00000000000000000000000000000000:0000 0A",
            "TCP6", true)
        != "TCP6 [::1]:4995 -> [::]:0 State:LISTEN(0A)\n") return false;
    if (netstat_detail::formatProcSocketLine(
            "3: 00000000:0035 00000000:0000 07", "UDP", false)
        != "UDP 0.0.0.0:53 -> 0.0.0.0:0 State:UNCONN(07)\n") return false;
    if (netstat_detail::formatProcSocketLine(
            "4: 0100007F:0016 00000000:0000 0A 0:0 0:0 0 0 0 123",
            "TCP", false, {{"123", "42/sshd"}})
        != "TCP 127.0.0.1:22 -> 0.0.0.0:0 State:LISTEN(0A) Owner:42/sshd\n") return false;
    if (!netstat_detail::formatProcSocketLine("bad input", "TCP", false).empty()) return false;
#endif
    std::unique_ptr<Netstat> mod = std::make_unique<Netstat>();
    std::vector<std::string> cmd = {"netstat"};
    C2Message msg, ret;
    mod->init(cmd, msg);
    mod->process(msg, ret);

    std::cout << "[+] netstat output: " << ret.returnvalue() << std::endl;

    return !ret.returnvalue().empty();
}
