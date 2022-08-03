#ifndef SECRETS_H
#define SECRETS_H
const uint8_t AES_KEY[16] = {0xe3,0x6a,0xc,0x67,0xea,0x84,0xfa,0xc1,0x3f,0x6d,0xa6,0xbd,0x14,0x8c,0xf0,0xc7};
const uint8_t V_KEY[64] = {0x9b,0x41,0xac,0x1a,0x19,0xc2,0x41,0xec,0xc0,0x9,0x9a,0x1a,0x84,0xea,0xe6,0xf4,0x10,0x74,0xbd,0xbf,0x9f,0x35,0x6e,0x51,0xb2,0xda,0xb4,0x98,0x97,0x33,0x9f,0xb9,0x2f,0xc,0x10,0xe,0x96,0x5f,0x2b,0xcf,0xcf,0xc1,0xcb,0x63,0xdd,0xd5,0xd,0x86,0x44,0x8d,0x25,0x64,0x33,0x49,0xdc,0x5b,0xf7,0x36,0x57,0x94,0x9c,0x26,0x25,0x9e};
const uint8_t ECC_KEY[65] = {0x4,0x6b,0xb6,0x1c,0x85,0x36,0xda,0x83,0x8c,0x36,0x20,0x53,0xf1,0xba,0x84,0x37,0x9f,0x17,0xef,0x5a,0x5c,0xc9,0xff,0xed,0x7,0x32,0x39,0xce,0x78,0x6b,0x11,0x47,0x5,0x54,0xdd,0x94,0x42,0x94,0xa,0xfe,0x9,0x92,0x88,0xa9,0x4e,0x5d,0xf4,0x9c,0xb8,0x5c,0x4,0x45,0x92,0xb1,0xb1,0x9c,0xad,0xc7,0x24,0x8c,0x46,0xcd,0xc4,0xca,0xb7};
const uint8_t AAD[16] = {0x21,0x72,0xb7,0xca,0xe3,0xb,0x86,0xe6,0x44,0x99,0xbc,0xa7,0x4e,0xe,0xf7,0x9c};
#endif