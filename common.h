#ifndef _TH89D_COMMON_H_
#define _TH89D_COMMON_H_

#include <stdio.h>
#include <stdint.h>

static inline const char *th89d_sw_str(uint16_t sw)
{
	switch (sw) {
		case 0x9000: return "Success";
		case 0x6A00: return "Parameter Error";
		case 0x6D00: return "Command Error";
		case 0x6985: return "Data Error";
		case 0x6581: return "Operation Error";
		default:     return "Unknown";
	}
}

static inline void dump_hex(const uint8_t *buf, int len)
{
	for (int i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("%04X: ", i);
		printf("%02X ", buf[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	if (len % 16)
		printf("\n");
}

#endif /* _TH89D_COMMON_H_ */
