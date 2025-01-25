#ifndef ATTACKFRAME_H
#define ATTACKFRAME_H

#include <string>
#include <cstdint>
#include "MacAddr.h"
#include "Dot11.h"

/*
 * RadiotapHdr, DeauthFixed, AuthFixed 구조체 + 함수 원형
 */

#pragma pack(push, 1)
// Radiotap Header (간단 8바이트)
struct RadioTapHdr {
    uint8_t  revision;
    uint8_t  pad;
    uint16_t length;
    uint32_t presentFlags;
};

// Deauth 고정 필드
struct DeauthFixed {
    uint16_t reasonCode;
};

// Auth 고정 필드
struct AuthFixed {
    uint16_t authAlgorithm;
    uint16_t authSeq;
    uint16_t statusCode;
};
#pragma pack(pop)

/*
 * parseMac : "00:11:22:33:44:55" -> MacAddr
 */
bool parseMac(const std::string& str, MacAddr& mac);

/*
 * buildMgmtFrame : Deauth/Auth 802.11 mgmt frame을 packetBuf에 작성
 *   - isDeauth = true => Deauth, false => Auth
 *   - isBroadcast = true => addr1 = ff:ff:ff:ff:ff:ff, else stationMac
 */
bool buildMgmtFrame(
    uint8_t* packetBuf,
    int& packetLen,
    const MacAddr& apMac,
    const MacAddr& stMac,
    bool isDeauth,
    bool isBroadcast
);

#endif
