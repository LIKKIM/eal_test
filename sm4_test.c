// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "common.h"

/* ============================================================
 *			IOCTL & STRUCT
 * ============================================================ */
#define TH89D_IOCTL_MAGIC		'T'
#define TH89D_IOCTL_SM_OP		_IOWR(TH89D_IOCTL_MAGIC, 0x06, struct th89d_sm_args)

/* === 算法与模式定义 === */
#define TH89D_ALGO_SM4		0x04

#define TH89D_MODE_ECB		0x00
#define TH89D_MODE_CBC		0x10
#define TH89D_OP_ENCRYPT	0x00
#define TH89D_OP_DECRYPT	0x01

#define TH89D_SM4_ECB_ENC	(TH89D_MODE_ECB | TH89D_OP_ENCRYPT)
#define TH89D_SM4_ECB_DEC	(TH89D_MODE_ECB | TH89D_OP_DECRYPT)
#define TH89D_SM4_CBC_ENC	(TH89D_MODE_CBC | TH89D_OP_ENCRYPT)
#define TH89D_SM4_CBC_DEC	(TH89D_MODE_CBC | TH89D_OP_DECRYPT)

/* === SM 参数结构（用户态） === */
struct th89d_sm_args {
	uint8_t algo;
	uint8_t mode;

	uint8_t *key;
	uint8_t *iv;

	uint8_t *plaintext;
	uint32_t plaintext_len;

	uint8_t *ciphertext;
	uint32_t ciphertext_len;

	uint16_t sw;
};

static const char *mode_name(uint8_t mode)
{
	switch (mode) {
	case TH89D_SM4_ECB_ENC: return "SM4 ECB Encrypt";
	case TH89D_SM4_ECB_DEC: return "SM4 ECB Decrypt";
	case TH89D_SM4_CBC_ENC: return "SM4 CBC Encrypt";
	case TH89D_SM4_CBC_DEC: return "SM4 CBC Decrypt";
	default: return "UNKNOWN MODE";
	}
}

static void test_sm4(int fd)
{
	const uint8_t fixed_key[16] = {
		0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
		0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
	};

	const uint8_t fixed_iv[16] = {
		0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
		0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};

	const uint8_t fixed_plain[16] = {
		0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
		0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
	};

	uint8_t modes[] = {
		TH89D_SM4_ECB_ENC,
		TH89D_SM4_ECB_DEC,
		TH89D_SM4_CBC_ENC,
		TH89D_SM4_CBC_DEC,
	};

	uint8_t *saved_cipher = NULL;
	uint32_t saved_cipher_len = 0;

	printf("\n=== [TEST SM4] Encrypt / Decrypt ===\n");

	for (int i = 0; i < 4; i++) {

		struct th89d_sm_args sm;
		memset(&sm, 0, sizeof(sm));

		sm.algo = TH89D_ALGO_SM4;
		sm.mode = modes[i];

		/* ---- key ---- */
		sm.key = malloc(16);
		memcpy(sm.key, fixed_key, 16);

		/* ---- iv (CBC only) ---- */
		if (sm.mode & TH89D_MODE_CBC) {
			sm.iv = malloc(16);
			memcpy(sm.iv, fixed_iv, 16);
		} else {
			sm.iv = NULL;
		}

		/* ---- plaintext ---- */
		if (sm.mode == TH89D_SM4_ECB_DEC || sm.mode == TH89D_SM4_CBC_DEC) {
			/* decrypt → previous cipher */
			sm.plaintext_len = saved_cipher_len;
			sm.plaintext = malloc(saved_cipher_len);
			memcpy(sm.plaintext, saved_cipher, saved_cipher_len);
		} else {
			/* encrypt → fixed plain */
			sm.plaintext_len = 16;
			sm.plaintext = malloc(16);
			memcpy(sm.plaintext, fixed_plain, 16);
		}

		/* ---- ciphertext ---- */
		sm.ciphertext_len = 512;
		sm.ciphertext = malloc(sm.ciphertext_len);
		memset(sm.ciphertext, 0, sm.ciphertext_len);

		printf("\n[TEST] %s\n", mode_name(sm.mode));
		dump_hex(sm.key, 16);
		if (sm.iv)
			dump_hex(sm.iv, 16);
		dump_hex(sm.plaintext, sm.plaintext_len);

		/* ---- ioctl ---- */
		if (ioctl(fd, TH89D_IOCTL_SM_OP, &sm) < 0) {
			perror("ioctl SM_OP");
		} else {
			printf("SW = 0x%04X (%s)\n", sm.sw, th89d_sw_str(sm.sw));
			dump_hex(sm.ciphertext, sm.ciphertext_len);

			/* 保存加密输出给下一轮解密 */
			if (sm.mode == TH89D_SM4_ECB_ENC || sm.mode == TH89D_SM4_CBC_ENC) {
				saved_cipher = realloc(saved_cipher, sm.ciphertext_len);
				memcpy(saved_cipher, sm.ciphertext, sm.ciphertext_len);
				saved_cipher_len = sm.ciphertext_len;
			}
		}

		/* ---- free ---- */
		free(sm.key);
		if (sm.iv)
			free(sm.iv);
		free(sm.plaintext);
		free(sm.ciphertext);
	}

	if (saved_cipher)
		free(saved_cipher);

	printf("\n=== [TEST SM4] Done ===\n");
}

int main(void)
{
	int fd = open("/dev/thd89", O_RDWR);
	if (fd < 0) {
		perror("open /dev/thd89");
		return 1;
	}

	test_sm4(fd);

	close(fd);
	return 0;
}
