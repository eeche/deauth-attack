#ifndef DOT11_H
#define DOT11_H

#include <cstdint>

#pragma pack(push, 1)
struct Dot11Hdr {
    uint16_t frameControl;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seqCtrl;
};
#pragma pack(pop)

// Subtype 상수
static const uint16_t FC_SUBTYPE_DEAUTH = 0x00C0; // 1100 0000
static const uint16_t FC_SUBTYPE_AUTH  = 0x00B0; // 1011 0000

#endif
