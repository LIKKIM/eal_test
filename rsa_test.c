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
#define TH89D_IOCTL_RSA_DATA_INPUT  _IOWR(TH89D_IOCTL_MAGIC, 0x09, struct th89d_rsa_data_input_args)
#define TH89D_IOCTL_RSA_OPERATION   _IOWR(TH89D_IOCTL_MAGIC, 0x0a, struct th89d_rsa_operation_args)

// 添加数据类型定义（用于数据输入阶段）
#define TH89D_RSA_DATA_TYPE_ENC_DATA 0x00   // 待加密数据
#define TH89D_RSA_DATA_TYPE_E        0x02   // E (公钥指数)
#define TH89D_RSA_DATA_TYPE_N        0x03   // N (模数)
#define TH89D_RSA_DATA_TYPE_DP       0x07   // DP (CRT参数)
#define TH89D_RSA_DATA_TYPE_DQ       0x08   // DQ (CRT参数)
#define TH89D_RSA_DATA_TYPE_D        0x09   // D (私钥指数)

/* RSA 输入模式定义 */
#define TH89D_RSA_INPUT_MODE_BIT    0x80    /* 输入模式位掩码 */
#define TH89D_RSA_DATA_COMPLETE     0x00    /* bit7=0: 数据已输入完成 */
#define TH89D_RSA_DATA_MORE         0x01    /* bit7=1: 数据未输入完成 */

/* 运算启动控制 */
#define TH89D_RSA_CAL_READ_ONLY         0     /* bit6=0: 只读取数据，不进行运算 */
#define TH89D_RSA_CAL_START             1     /* bit6=1: 启动运算 */

// 添加 RSA 操作模式定义
#define TH89D_RSA_MODE_ENC          0x00    // 加密
#define TH89D_RSA_MODE_DEC          0x01    // 标准解密
#define TH89D_RSA_MODE_CRT_DEC      0x04    // CRT解密
#define TH89D_RSA_MODE_GEN_E        0x02    // E生成
#define TH89D_RSA_MODE_GEN_KEY      0x03    // 密钥生成
#define TH89D_RSA_MODE_READ_DATA    0x05    // 只读低数据

/* RSA 数据输入参数结构 */
struct th89d_rsa_data_input_args {
	uint8_t  op_mode;		/* 操作模式: 0x00=加密, 0x01=解密, 0x04=CRT解密 */
	uint8_t  data_ctl;		/* 0: 数据已输入完成, 1: 数据未输入完成 */
	uint8_t  input_data_type;
	
	uint32_t key_bits;		/* 密钥位数 */
	uint32_t data_len;		/* 数据长度 */
	uint8_t *data_in;		/* 输入数据 */
	
	uint16_t sw;		/* 状态字 */
};

/* RSA 运算参数结构 */
struct th89d_rsa_operation_args {
	uint8_t  op_mode;		/* 操作模式: 0x00=加密, 0x01=解密, 0x04=CRT解密 */
	uint8_t  data_ctl;		/* 0: 数据已输入完成, 1: 数据未输入完成 */
	uint8_t  cal_ctl;		/* 运算启动控制 */
	uint8_t  input_data_type;
	
	uint32_t key_bits;		/* 密钥位数 */
	uint8_t  output_len;		/* 期望输出长度 */
	
	uint32_t result_len;		/* 结果长度 */
	uint8_t *result;		/* 输出结果 */
	
	uint16_t sw;			/* 状态字 */
};
/* ============================================================
 *			测试数据
 * ============================================================ */

/* 256位RSA测试数据 */
static const uint8_t rsa256_n[] = {
	0xB4, 0x66, 0x94, 0x9D, 0x5F, 0xD0, 0xB0, 0x4D,
	0xD7, 0xFA, 0x21, 0x6B, 0x1F, 0x79, 0x6F, 0x14,
	0x50, 0xF5, 0xA5, 0xC5, 0x38, 0xCC, 0xA4, 0x8E,
	0x7C, 0x83, 0x19, 0xC0, 0xEB, 0x83, 0x47, 0xB9
};

static const uint8_t rsa256_e[] = {
	0x00, 0x00, 0x00, 0x03
};

static const uint8_t rsa256_d[] = {
	0x78, 0x44, 0x63, 0x13, 0x95, 0x35, 0xCA, 0xDE,
	0x8F, 0xFC, 0x16, 0x47, 0x6A, 0x50, 0xF4, 0xB7,
	0x17, 0x4B, 0x6F, 0x72, 0xA3, 0x6D, 0x9C, 0x15,
	0x45, 0xFD, 0x8B, 0x60, 0x33, 0x2D, 0x23, 0x0B
};

static const uint8_t plaintext_m[] = {
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x05, 0x01, 0x01, 0x01
};

static const uint8_t expected_ciphertext[] = {
	0x5D, 0xE1, 0xDD, 0x51, 0xB2, 0x8E, 0x79, 0x1F,
	0x38, 0x1E, 0x3B, 0x9A, 0x02, 0x39, 0x99, 0x10,
	0xC5, 0x02, 0x21, 0x2E, 0xC2, 0x1C, 0x4E, 0xB0,
	0xA6, 0x5B, 0x11, 0x70, 0xFF, 0x24, 0x85, 0x9C
};

static int rsa_data_input(int fd, uint8_t op_mode, uint8_t data_ctl, uint8_t input_data_type, 
			  const uint8_t *data, uint32_t data_len, uint32_t key_bits)
{
	struct th89d_rsa_data_input_args args;
	uint8_t *user_data = NULL;
	int ret;
	
	memset(&args, 0, sizeof(args));
	
	args.op_mode = op_mode;
	args.data_ctl = data_ctl;
	args.input_data_type = input_data_type;
	args.key_bits = key_bits;
	args.data_len = data_len;
	
	/* 分配用户空间数据缓冲区 */
	user_data = malloc(data_len);
	if (!user_data) {
		perror("malloc");
		return -1;
	}
	memcpy(user_data, data, data_len);
	args.data_in = user_data;
	
	ret = ioctl(fd, TH89D_IOCTL_RSA_DATA_INPUT, &args);
	
	printf("RSA Data Input: data_ctl=0x%02X, type=0x%02X, len=%u, SW=0x%04X\n",
	       data_ctl, input_data_type, data_len, args.sw);
	
	free(user_data);
	return ret;
}

static int rsa_operation(int fd, uint8_t op_mode, uint8_t data_ctl, uint8_t cal_ctl, uint8_t input_data_type,
			 uint32_t key_bits, uint8_t output_len,
			 uint8_t *result, uint32_t result_max)
{
	struct th89d_rsa_operation_args args;
	uint8_t *user_result = NULL;
	int ret;
	
	memset(&args, 0, sizeof(args));
	
	args.op_mode = op_mode;
	args.data_ctl = data_ctl;
	args.cal_ctl = cal_ctl;
	args.input_data_type = input_data_type;
	args.key_bits = key_bits;
	args.output_len = output_len;
	args.result_len = result_max;
	
	/* 分配用户空间结果缓冲区 */
	user_result = malloc(result_max);
	if (!user_result) {
		perror("malloc");
		return -1;
	}
	memset(user_result, 0, result_max);
	args.result = user_result;
	
	ret = ioctl(fd, TH89D_IOCTL_RSA_OPERATION, &args);
	
	if (ret >= 0 && args.sw == 0x9000) {
		printf("RSA Operation: data_ctl=0x%02X, mode=0x%02X, result_len=%u, SW=0x%04X\n",
		       data_ctl, op_mode, args.result_len, args.sw);
		
		/* 拷贝结果 */
		if (args.result_len > 0 && args.result_len <= result_max) {
			memcpy(result, user_result, args.result_len);
		}
	} else {
		printf("RSA Operation failed: SW=0x%04X\n", args.sw);
	}
	
	free(user_result);
	return (args.sw == 0x9000) ? (int)args.result_len : -1;
}

int main(void)
{
	int fd = open("/dev/thd89", O_RDWR);
	if (fd < 0) {
		perror("open /dev/thd89");
		return 1;
	}
	
	printf("=== RSA Test Program (Separate IOCTLs) ===\n");
	printf("Testing 256-bit RSA encryption/decryption\n");
	
	const uint32_t key_bits = 256;
	const uint32_t key_bytes = key_bits / 8;
	uint8_t ciphertext[32] = {0};
	uint8_t decrypted[32] = {0};
	
	/* ========== 加密流程 ========== */
	printf("\n>>> Encryption Flow (data_ctl=0x00):\n");
	
	/* 1. 输入明文M */
	if (rsa_data_input(fd, TH89D_RSA_MODE_ENC, TH89D_RSA_DATA_COMPLETE, TH89D_RSA_DATA_TYPE_ENC_DATA,
			   plaintext_m, key_bytes, key_bits) < 0) {
		printf("Failed to input plaintext M\n");
		goto error;
	}
	
	/* 2. 输入模数N */
	if (rsa_data_input(fd, TH89D_RSA_MODE_ENC, TH89D_RSA_DATA_COMPLETE, TH89D_RSA_DATA_TYPE_N,
			   rsa256_n, key_bytes, key_bits) < 0) {
		printf("Failed to input modulus N\n");
		goto error;
	}
	
	/* 3. 输入公钥指数E */
	if (rsa_data_input(fd, TH89D_RSA_MODE_ENC, TH89D_RSA_DATA_COMPLETE, TH89D_RSA_DATA_TYPE_E,
			   rsa256_e, 4, key_bits) < 0) {
		printf("Failed to input public exponent E\n");
		goto error;
	}
	
	/* 4. 执行加密 */
	int cipher_len = rsa_operation(fd, TH89D_RSA_MODE_ENC, TH89D_RSA_DATA_COMPLETE, TH89D_RSA_CAL_START, TH89D_RSA_DATA_TYPE_ENC_DATA,
				       key_bits, key_bytes, ciphertext, sizeof(ciphertext));
	
	if (cipher_len > 0) {
		printf("Ciphertext (%d bytes):\n", cipher_len);
		dump_hex(ciphertext, cipher_len);
	}
	
	/* ========== 解密流程 ========== */
	printf("\n>>> Decryption Flow (data_ctl=0x01):\n");
	
	/* 1. 输入密文C */
	if (rsa_data_input(fd, TH89D_RSA_MODE_DEC, TH89D_RSA_DATA_COMPLETE, TH89D_RSA_DATA_TYPE_ENC_DATA,
			   ciphertext, key_bytes, key_bits) < 0) {
		printf("Failed to input ciphertext C\n");
		goto error;
	}
	
	/* 2. 输入模数N */
	if (rsa_data_input(fd, TH89D_RSA_MODE_DEC, TH89D_RSA_DATA_COMPLETE, TH89D_RSA_DATA_TYPE_N,
			   rsa256_n, key_bytes, key_bits) < 0) {
		printf("Failed to input modulus N\n");
		goto error;
	}
	
	/* 3. 输入私钥指数D */
	if (rsa_data_input(fd, TH89D_RSA_MODE_DEC, TH89D_RSA_DATA_COMPLETE, TH89D_RSA_DATA_TYPE_D,
			   rsa256_d, key_bytes, key_bits) < 0) {
		printf("Failed to input private exponent D\n");
		goto error;
	}
	
	/* 4. 输入公钥指数E */
	if (rsa_data_input(fd, TH89D_RSA_MODE_DEC, TH89D_RSA_DATA_COMPLETE, TH89D_RSA_DATA_TYPE_E,
			   rsa256_e, 4, key_bits) < 0) {
		printf("Failed to input public exponent E\n");
		goto error;
	}
	
	/* 5. 执行解密 */
	int plain_len = rsa_operation(fd, TH89D_RSA_MODE_DEC, TH89D_RSA_DATA_COMPLETE, TH89D_RSA_CAL_START, TH89D_RSA_DATA_TYPE_ENC_DATA,
				      key_bits, key_bytes, decrypted, sizeof(decrypted));
	
	if (plain_len > 0) {
		printf("Decrypted plaintext (%d bytes):\n", plain_len);
		dump_hex(decrypted, plain_len);
		
		/* 验证明文 */
		if (memcmp(decrypted, plaintext_m, key_bytes) == 0) {
			printf("[SUCCESS] Plaintext matches original message!\n");
		} else {
			printf("[FAILED] Plaintext does NOT match original message!\n");
		}
	}
	
	close(fd);
	return 0;
	
error:
	close(fd);
	return 1;
}