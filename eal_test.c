// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>

/* === IOCTL 定义 === */
#define TH89D_IOCTL_MAGIC        'T'
#define TH89D_IOCTL_RNG			_IOWR(TH89D_IOCTL_MAGIC, 0x01, struct th89d_rng_args)
#define TH89D_IOCTL_GET_VERSION		_IOWR(TH89D_IOCTL_MAGIC, 0x02, struct th89d_version_args)
#define TH89D_IOCTL_NVM_ERASE		_IOWR(TH89D_IOCTL_MAGIC, 0x03, struct th89d_nvm_erase_args)
#define TH89D_IOCTL_READ		_IOWR(TH89D_IOCTL_MAGIC, 0x04, struct th89d_read_args)
#define TH89D_IOCTL_SM_OP		_IOWR(TH89D_IOCTL_MAGIC, 0x06, struct th89d_sm_args)
#define TH89D_IOCTL_HASH_OP		_IOWR(TH89D_IOCTL_MAGIC, 0x08, struct th89d_hash_args)

/* === 结构体定义 === */
struct th89d_version_args {
	uint8_t  version_type;   /* 要获取的版本类型（原 p2） */
	char *version;        /* 输出的版本号字符串缓冲区 */
	uint16_t sw;             /* 状态字 */
};

struct th89d_rng_args {
	uint32_t random_len;   // 请求的随机数长度
	uint8_t *random;       // 输出随机数
	uint16_t sw;           // 状态字
};

struct th89d_nvm_erase_args {
	uint32_t addr;       // 起始地址
	uint8_t  pages;      // 页数
	uint16_t sw;         // 状态字
	uint32_t len;        // 返回长度
};

struct th89d_read_args {
	uint8_t p1;		// READ 模式：00普通、01加严、02容错、03探状态
	uint8_t p2;		// 读取模式：00 byte, 01 half-word, 02 word
	uint8_t  mode;		// 加严读模式：仅当 P1=01 时有效 (0=加严0, 1=加严1)
	uint32_t addr;		// 起始地址
	uint32_t read_len;	// 读取长度
	uint32_t data_len;
	uint8_t *out;		// 用户缓冲区
	uint16_t sw;		// 状态字
};

struct th89d_sm_args {
	uint8_t algo;     // P1: 01=SM1, 03=SSF33, 04=SM4
	uint8_t mode;     // P2 bit4=1 CBC, bit0=1 decrypt
	uint8_t key[16];  // 对称密钥
	uint8_t iv[16];   // 仅 CBC 模式有效
	uint8_t data_in[256];
	uint32_t data_in_len;
	uint8_t data_out[256];
	uint32_t data_out_len;
	uint16_t sw;
};

struct th89d_hash_args {
	uint8_t algo;          // 算法类型（SM3/SHA1/SHA256）
	uint8_t *data_in;      // 输入数据指针
	uint32_t data_in_len;  // 输入数据长度
	uint8_t *digest;       // 输出digest
	uint32_t digest_len;   // 输出长度（32或20）
	uint16_t block_size;   // 希望驱动分块大小（例如128/256）
	uint16_t sw;           // 状态字
};

/* === 版本子命令（P2）定义 === */
#define TH89D_VER_CRYPTO1     0x00
#define TH89D_VER_SM1         0x01
#define TH89D_VER_SECURE_LIB  0x02
#define TH89D_VER_SSF33       0x03
#define TH89D_VER_SM4         0x04
#define TH89D_VER_CLOCK_CTRL  0x05

static const char *const th89d_ver_name[] = {
	[TH89D_VER_CRYPTO1]    = "Crypto1",
	[TH89D_VER_SM1]        = "SM1",
	[TH89D_VER_SECURE_LIB] = "SecureLib",
	[TH89D_VER_SSF33]      = "SSF33",
	[TH89D_VER_SM4]        = "SM4",
	[TH89D_VER_CLOCK_CTRL] = "ClockCtrl",
};

// THD89 状态码定义
enum th89d_status_code {
	TH89D_SW_SUCCESS          = 0x9000, // 成功
	TH89D_SW_PARAM_ERROR      = 0x6A00, // 参数异常
	TH89D_SW_CMD_ERROR        = 0x6D00, // 命令或参数错误
	TH89D_SW_DATA_ERROR       = 0x6985, // 数据输入错误
	TH89D_SW_LEN_ERROR        = 0x6C00, // Le 错误
	TH89D_SW_MORE_DATA        = 0x6100, // 仍有数据可取
	TH89D_SW_OP_ERROR         = 0x6581, // 操作失败 / 运算错误
	TH89D_SW_CRYPTO_ERROR     = 0x6504, // 算法执行错误
};

const char *th89d_sw_str(uint16_t sw) {
	switch (sw) {
		case TH89D_SW_SUCCESS:      return "\033[32mSuccess\033[0m"; // 绿色
		case TH89D_SW_PARAM_ERROR:  return "\033[33mParameter Error\033[0m";
		case TH89D_SW_OP_ERROR:     return "\033[31mOperation Error\033[0m";
		case TH89D_SW_DATA_ERROR:   return "\033[31mData Input Error\033[0m";
		case TH89D_SW_CMD_ERROR:    return "\033[31mCommand Error\033[0m";
		case TH89D_SW_CRYPTO_ERROR: return "\033[31mCrypto Engine Error\033[0m";
		default:                    return "\033[90mUnknown Status\033[0m"; // 灰色
	}
}

/* === READ 模式 (P1) === */
#define TH89D_READ_P1_NORMAL    0x00  // 普通读 / 读 RAM
#define TH89D_READ_P1_STRICT    0x01  // 加严读
#define TH89D_READ_P1_TOLERANT  0x02  // 容错读
#define TH89D_READ_P1_STATUS    0x03  // 探状态校验

/* === 读取方式 (P2) === */
#define TH89D_READ_P2_BYTE      0x00  // 字节方式
#define TH89D_READ_P2_HALFWORD  0x01  // 半字方式
#define TH89D_READ_P2_WORD      0x02  // 字方式

/* === 加严模式定义 === */
#define TH89D_STRICT_MODE_0	0x00  // 加严读0
#define TH89D_STRICT_MODE_1	0x01  // 加严读1

static const char *const p1_mode_name[] = {
    [TH89D_READ_P1_NORMAL]   = "NORMAL",
    [TH89D_READ_P1_STRICT]   = "STRICT",
    [TH89D_READ_P1_TOLERANT] = "TOLERANT",
    [TH89D_READ_P1_STATUS]   = "STATUS",
};

static const char *const p2_mode_name[] = {
    [TH89D_READ_P2_BYTE]     = "BYTE",
    [TH89D_READ_P2_HALFWORD] = "HALFWORD",
    [TH89D_READ_P2_WORD]     = "WORD",
};

static const char *const strict_mode_name[] = {
    [TH89D_STRICT_MODE_0] = "STRICT_MODE_0",
    [TH89D_STRICT_MODE_1] = "STRICT_MODE_1",
};

/* === SM 算法类型定义 === */
#define TH89D_ALGO_SM1     0x01
#define TH89D_ALGO_SSF33   0x03
#define TH89D_ALGO_SM4     0x04

/* === SM 加密模式 (P2) 位定义 === */
#define TH89D_MODE_ECB     0x00    // bit4=0 → ECB
#define TH89D_MODE_CBC     0x10    // bit4=1 → CBC
#define TH89D_OP_ENCRYPT   0x00    // bit0=0 → Encrypt
#define TH89D_OP_DECRYPT   0x01    // bit0=1 → Decrypt

/* === 组合宏，方便使用 === */
#define TH89D_SM4_ECB_ENC  (TH89D_MODE_ECB | TH89D_OP_ENCRYPT)
#define TH89D_SM4_ECB_DEC  (TH89D_MODE_ECB | TH89D_OP_DECRYPT)
#define TH89D_SM4_CBC_ENC  (TH89D_MODE_CBC | TH89D_OP_ENCRYPT)
#define TH89D_SM4_CBC_DEC  (TH89D_MODE_CBC | TH89D_OP_DECRYPT)

/* === 模式名称表 === */
static const char *const sm4_mode_name[] = {
	[TH89D_SM4_ECB_ENC] = "SM4 ECB Encrypt",
	[TH89D_SM4_ECB_DEC] = "SM4 ECB Decrypt",
	[TH89D_SM4_CBC_ENC] = "SM4 CBC Encrypt",
	[TH89D_SM4_CBC_DEC] = "SM4 CBC Decrypt",
};

/* === 工具函数 === */
static void dump_hex(const char *title, const unsigned char *data, int len)
{
	printf("%s (%d bytes):\n", title, len);
	for (int i = 0; i < len; i++) {
		printf("%02X ", data[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	if (len % 16)
		printf("\n");
}

/* === 测试函数：GET_VERSION === */
static void test_get_version(int fd)
{
	printf("\n[TEST 1] GET_VERSION\n");

	for (int type = TH89D_VER_CRYPTO1; type <= TH89D_VER_CLOCK_CTRL; type++) {

		char buf[16];
		struct th89d_version_args ver;

		memset(buf, 0, sizeof(buf));
		memset(&ver, 0, sizeof(ver));

		ver.version_type = type;
		ver.version      = buf;   /* char* 正确匹配内核 */

		if (ioctl(fd, TH89D_IOCTL_GET_VERSION, &ver) < 0) {
		fprintf(stderr, "[%s] ioctl failed: %s\n",
			th89d_ver_name[type], strerror(errno));
		continue;
		}

		printf("[%s] Version (type=%02X): %s\n",
		th89d_ver_name[type], type, buf);

		printf("  SW = 0x%04X (SW1=0x%02X, SW2=0x%02X, %s)\n",
		ver.sw, ver.sw >> 8, ver.sw & 0xFF, th89d_sw_str(ver.sw));
	}
}

/* === 测试函数：RNG 随机数 === */
static void test_rng(int fd)
{
	printf("\n[TEST 2] RNG\n");

	struct th89d_rng_args *rng;
	unsigned char *randbuf;

	rng = calloc(1, sizeof(*rng));
	if (!rng) {
		perror("calloc rng");
		return;
	}

	randbuf = malloc(128);
	if (!randbuf) {
		perror("malloc randbuf");
		free(rng);
		return;
	}

	/* 初始化参数 */
	memset(randbuf, 0, 128);
	rng->random_len = 128;   /* 请求 128 字节随机数 */
	rng->random = randbuf;  /* 指向用户态缓冲区 */

	/* 发起 IOCTL 调用 */
	if (ioctl(fd, TH89D_IOCTL_RNG, rng) < 0) {
		perror("ioctl RNG");
		free(randbuf);
		free(rng);
		return;
	}

	/* 输出结果 */
	dump_hex("Random Data", randbuf, rng->random_len);
	printf("RNG SW = 0x%04X (SW1=0x%02X, SW2=0x%02X, %s)\n",
	       rng->sw, rng->sw >> 8, rng->sw & 0xFF, th89d_sw_str(rng->sw));

	free(randbuf);
	free(rng);
}

/* === 测试函数：NVM 擦除 === */
static void test_nvm_erase(int fd)
{
	printf("\n[TEST 3] NVM ERASE\n");

	struct th89d_nvm_erase_args erase;
	memset(&erase, 0, sizeof(erase));

	erase.addr  = 0x0C000000;  // 起始地址
	erase.pages = 1;           // 擦除 1 页

	if (ioctl(fd, TH89D_IOCTL_NVM_ERASE, &erase) < 0) {
		perror("ioctl NVM_ERASE");
		return;
	}

	printf("NVM erase success (addr=0x%08X, pages=%u)\n",
	       erase.addr, erase.pages);
	printf("  SW = 0x%04X (SW1=0x%02X, SW2=0x%02X), %s\n",
	       erase.sw, erase.sw >> 8, erase.sw & 0xFF, th89d_sw_str(erase.sw));
}

static void test_nvm_read(int fd, uint8_t p1, uint8_t p2,
                               uint8_t mode, uint32_t addr, uint32_t len)
{
	struct th89d_read_args rd = {0};
	unsigned char buf[512];

	rd.p1 = p1;      // 模式：00普通、01加严、02容错、03探状态
	rd.p2 = p2;      // 方式：00字节、01半字、02字
	rd.mode = mode;
	rd.addr = addr;
	rd.read_len = len;
	rd.out = buf;

	printf("\n[TEST 3] NVM READ\n");
	printf("  P1=%02X (%s)  P2=%02X (%s)  MODE=%02X (%s)\n",
		p1,
		(p1 <= TH89D_READ_P1_STATUS) ? p1_mode_name[p1] : "UNKNOWN",
		p2,
		(p2 <= TH89D_READ_P2_WORD) ? p2_mode_name[p2] : "UNKNOWN",
		mode,
		(mode <= TH89D_STRICT_MODE_1) ? strict_mode_name[mode] : "N/A");

	if (ioctl(fd, TH89D_IOCTL_READ, &rd) < 0) {
		perror("ioctl READ");
		return;
	}

	printf("READ (addr=0x%08X, data_len=%u bytes, req=%u)\n",
		rd.addr, rd.data_len, rd.read_len);

	if (rd.data_len != rd.read_len) {
		fprintf(stderr, "Error: expected %u, got %u bytes\n",
			rd.read_len, rd.data_len);
		fprintf(stderr, "SW = 0x%04X [%s]\n",
			rd.sw, th89d_sw_str(rd.sw));
		return;
	}

	for (int i = 0; i < rd.data_len; i++) {
		if (i % 16 == 0) printf("  %04X: ", i);
		printf("%02X ", buf[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}
	if (rd.data_len % 16) printf("\n");

	printf("SW = 0x%04X (SW1=%02X, SW2=%02X) [%s]\n",
		rd.sw, rd.sw >> 8, rd.sw & 0xFF, th89d_sw_str(rd.sw));
}

/* === 测试函数：SM4 加解密 === */
static void test_sm_encrypt(int fd)
{
	struct th89d_sm_args sm = {0};
	uint8_t modes[] = {
		TH89D_SM4_ECB_ENC,
		TH89D_SM4_ECB_DEC,
		TH89D_SM4_CBC_ENC,
		TH89D_SM4_CBC_DEC,
	};
	uint8_t last_cipher[256] = {0};
	uint32_t last_cipher_len = 0;

	printf("\n=== [TEST 4] SM4 Encrypt/Decrypt ===\n");

	for (int i = 0; i < 4; i++) {
		memset(&sm, 0, sizeof(sm));
		sm.algo = TH89D_ALGO_SM4;
		sm.mode = modes[i];

		/* === 测试密钥 === */
		memcpy(sm.key, "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
		               "\xFE\xDC\xBA\x98\x76\x54\x32\x10", 16);

		/* === 输入数据设置 === */
		if (sm.mode == TH89D_SM4_ECB_DEC || sm.mode == TH89D_SM4_CBC_DEC) {
			/* 解密时使用上一次加密的输出 */
			memcpy(sm.data_in, last_cipher, last_cipher_len);
			sm.data_in_len = last_cipher_len;
		} else {
			/* 加密时使用固定明文 */
			memcpy(sm.data_in, "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
		               "\xFE\xDC\xBA\x98\x76\x54\x32\x10", 16);
			sm.data_in_len = 16;
		}

		/* CBC 模式才需要 IV */
		if (sm.mode & TH89D_MODE_CBC) {
			memcpy(sm.iv, "\x00\x11\x22\x33\x44\x55\x66\x77"
			              "\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16);
		}

		printf("\n[TEST] %s\n", sm4_mode_name[modes[i]]);

		/* === 打印密钥 === */
		printf("Key (16 bytes):\n");
		for (int j = 0; j < 16; j++) {
			printf("%02X ", sm.key[j]);
			if ((j + 1) % 16 == 0) printf("\n");
		}

		/* === 打印 IV（仅 CBC 模式） === */
		if (sm.mode & TH89D_MODE_CBC) {
			printf("IV (16 bytes):\n");
			for (int j = 0; j < 16; j++) {
				printf("%02X ", sm.iv[j]);
				if ((j + 1) % 16 == 0) printf("\n");
			}
		}

		/* === 打印输入数据 === */
		printf("Input (%u bytes):\n", sm.data_in_len);
		for (uint32_t j = 0; j < sm.data_in_len; j++) {
			printf("%02X ", sm.data_in[j]);
			if ((j + 1) % 16 == 0) printf("\n");
		}
		if (sm.data_in_len % 16)
			printf("\n");

		/* === 执行 SM4 运算 === */
		if (ioctl(fd, TH89D_IOCTL_SM_OP, &sm) < 0) {
			perror("ioctl SM_OP");
			continue;
		}

		printf("SW=%04X (%s)\n", sm.sw, th89d_sw_str(sm.sw));

		/* === 打印输出结果 === */
		printf("Output (%u bytes):\n", sm.data_out_len);
		for (uint32_t j = 0; j < sm.data_out_len; j++) {
			printf("%02X ", sm.data_out[j]);
			if ((j + 1) % 16 == 0)
				printf("\n");
		}
		if (sm.data_out_len % 16)
			printf("\n");

		/* === 保存加密输出，用于后续解密 === */
		if (sm.mode == TH89D_SM4_ECB_ENC || sm.mode == TH89D_SM4_CBC_ENC) {
			memcpy(last_cipher, sm.data_out, sm.data_out_len);
			last_cipher_len = sm.data_out_len;
		}
	}

	printf("\n=== [TEST 4] Done ===\n");
}

/* === 测试函数：HASH (SM3 / SHA1 / SHA256) === */
static void test_hash_file(int fd, uint8_t algo, const char *filepath, uint16_t block_size)
{
	struct th89d_hash_args hash;
	uint8_t *data = NULL;
	uint8_t digest[512];
	const char *algo_name;
	FILE *fp = NULL;
	long file_size = 0;
	int ret = 0;

	switch (algo) {
	case 0x06: algo_name = "SM3";    break;
	case 0x08: algo_name = "SHA1";   break;
	case 0x0A: algo_name = "SHA256"; break;
	default:   algo_name = "UNKNOWN"; break;
	}

	printf("\n=== [TEST 5] HASH (%s, IOCTL_HASH_OP) ===\n", algo_name);

	/* === 打开文件 === */
	fp = fopen(filepath, "rb");
	if (!fp) {
		perror("fopen");
		return;
	}

	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	rewind(fp);

	if (file_size <= 0) {
		fprintf(stderr, "Error: empty file or cannot get size\n");
		fclose(fp);
		return;
	}

	data = malloc(file_size);
	if (!data) {
		perror("malloc");
		fclose(fp);
		return;
	}

	if (fread(data, 1, file_size, fp) != (size_t)file_size) {
		perror("fread");
		free(data);
		fclose(fp);
		return;
	}
	fclose(fp);

	/* === 填充 HASH 参数结构体 === */
	memset(&hash, 0, sizeof(hash));
	memset(digest, 0, sizeof(digest));

	hash.algo         = algo;           // 算法类型
	hash.data_in      = data;           // 输入数据指针
	hash.data_in_len  = file_size;      // 输入数据长度
	hash.digest       = digest;         // 输出缓冲区
	hash.digest_len   = sizeof(digest); // 输出缓冲区大小
	hash.block_size   = block_size;     // 应用指定分块大小

	printf("File: %s (%ld bytes), Block size = %u\n", filepath, file_size, block_size);

	/* === 执行 IOCTL === */
	ret = ioctl(fd, TH89D_IOCTL_HASH_OP, &hash);
	if (ret < 0) {
		perror("ioctl HASH_OP");
		free(data);
		return;
	}

	/* === 打印结果 === */
	printf("[HASH_OP] SW=0x%04X (%s)\n", hash.sw, th89d_sw_str(hash.sw));
	printf("Digest (%u bytes):\n", hash.digest_len);
	for (uint32_t i = 0; i < hash.digest_len; i++) {
		printf("%02X", hash.digest[i]);
	}
	printf("\n");

	free(data);
	printf("=== [TEST 5] HASH (%s) Done ===\n", algo_name);
}

/* === 主函数 === */
int main(void)
{
	int fd = open("/dev/thd89", O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	printf("=== TH89D TEST START ===\n");

	test_get_version(fd);
	test_rng(fd);
	// test_nvm_erase(fd);
	// test_nvm_read(fd, TH89D_READ_P1_NORMAL, TH89D_READ_P2_BYTE, TH89D_STRICT_MODE_0, 0x0C000000, 32);
	// test_nvm_read(fd, TH89D_READ_P1_NORMAL, TH89D_READ_P2_HALFWORD, TH89D_STRICT_MODE_0, 0x0C000000, 32);
	// test_nvm_read(fd, TH89D_READ_P1_STRICT, TH89D_READ_P2_BYTE, TH89D_STRICT_MODE_0, 0x0C000000, 32); // 加严读0
	// test_nvm_read(fd, TH89D_READ_P1_STRICT, TH89D_READ_P2_BYTE, TH89D_STRICT_MODE_1, 0x0C000000, 32); // 加严读1

	// test_nvm_read(fd, TH89D_READ_P1_NORMAL, TH89D_READ_P2_BYTE, TH89D_STRICT_MODE_0, 0x0C000010, 32);
	// test_nvm_read(fd, TH89D_READ_P1_NORMAL, TH89D_READ_P2_HALFWORD, TH89D_STRICT_MODE_0, 0x0C000010, 32);
	// test_nvm_read(fd, TH89D_READ_P1_STRICT, TH89D_READ_P2_BYTE, TH89D_STRICT_MODE_0, 0x0C000010, 32); // 加严读0
	// test_nvm_read(fd, TH89D_READ_P1_STRICT, TH89D_READ_P2_BYTE, TH89D_STRICT_MODE_1, 0x0C000010, 32); // 加严读1

	// test_sm_encrypt(fd);

	// test_hash_op(fd, 0x06); // SM3
	// test_hash_op(fd, 0x08); // SHA1
	// test_hash_op(fd, 0x0A); // SHA256


	const char *testfile = "test.bin";
	FILE *fp = fopen(testfile, "wb");
	if (!fp) {
		perror("fopen test.bin");
		close(fd);
		return 1;
	}

	unsigned char buf[8];
	for (int i = 0; i < 8; i++)
		buf[i] = (uint8_t)(i & 0xFF);   // 依次写入 0x00 ~ 0xFF 循环

	if (fwrite(buf, 1, sizeof(buf), fp) != sizeof(buf)) {
		perror("fwrite");
		fclose(fp);
		close(fd);
		return 1;
	}
	fclose(fp);
	printf("Wrote test file '%s' (%zu bytes)\n", testfile, sizeof(buf));

	// test_hash_file(fd, 0x06, "test.bin", 1);
	// test_hash_file(fd, 0x08, "test.bin", 1);
	// test_hash_file(fd, 0x0A, "test.bin", 1);

	// test_hash_file(fd, 0x06, "test.bin", 5);
	// test_hash_file(fd, 0x08, "test.bin", 5);
	// test_hash_file(fd, 0x0A, "test.bin", 5);

	// test_hash_file(fd, 0x06, "test.bin", 6);  超过5字节就不准了
	// test_hash_file(fd, 0x08, "test.bin", 6);
	// test_hash_file(fd, 0x0A, "test.bin", 6);


	close(fd);
	printf("\n=== TH89D TEST DONE ===\n");
	return 0;
}
