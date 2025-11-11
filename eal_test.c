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
#define TH89D_IOCTL_RNG          _IOWR(TH89D_IOCTL_MAGIC, 0x01, struct th89d_rng_args)
#define TH89D_IOCTL_GET_VERSION  _IOWR(TH89D_IOCTL_MAGIC, 0x02, struct th89d_version_args)
#define TH89D_IOCTL_NVM_ERASE    _IOWR(TH89D_IOCTL_MAGIC, 0x03, struct th89d_nvm_erase_args)
#define TH89D_IOCTL_READ	_IOWR(TH89D_IOCTL_MAGIC, 0x04, struct th89d_read_args)

/* === 结构体定义 === */
struct th89d_version_args {
	uint8_t  p2;         // 对应 __u8
	uint8_t *out;        // 用户空间缓冲区
	uint32_t len;        // 缓冲区长度
	uint16_t sw;         // 状态字
};

struct th89d_rng_args {
	uint32_t le;         // 请求长度
	uint32_t len;        // 实际长度
	uint8_t *out;        // 输出缓冲区
	uint16_t sw;         // 状态字
};

struct th89d_nvm_erase_args {
	uint32_t addr;       // 起始地址
	uint8_t  pages;      // 页数
	uint16_t sw;         // 状态字
	uint32_t len;        // 返回长度
};

struct th89d_read_args {
	uint8_t p1;       // 区域类型：00 RAM, 01 NVM, 02 SFR
	uint8_t p2;       // 读取模式：00 byte, 01 half-word, 02 word
	uint32_t addr;    // 起始地址
	uint32_t read_len;      // 读取长度
	uint32_t data_len;
	uint8_t *out;     // 用户缓冲区
	uint16_t sw;      // 状态字
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

	char buf[64];
	struct th89d_version_args ver;

	for (int p2 = TH89D_VER_CRYPTO1; p2 <= TH89D_VER_CLOCK_CTRL; p2++) {
		memset(buf, 0, sizeof(buf));
		memset(&ver, 0, sizeof(ver));

		ver.p2  = p2;
		ver.out = (unsigned char *)buf;
		ver.len = sizeof(buf);

		if (ioctl(fd, TH89D_IOCTL_GET_VERSION, &ver) < 0) {
			fprintf(stderr, "[%s] ioctl failed: %s\n",
				th89d_ver_name[p2], strerror(errno));
			continue;
		}

		printf("[%s] Version (P2=%02X): %s\n", th89d_ver_name[p2], p2, buf);
		printf("  SW = 0x%04X (SW1=0x%02X, SW2=0x%02X, %s)\n",
			ver.sw, ver.sw >> 8, ver.sw & 0xFF, th89d_sw_str(ver.sw));
	}
}

/* === 测试函数：RNG 随机数 === */
static void test_rng(int fd)
{
	printf("\n[TEST 2] RNG\n");

	unsigned char randbuf[32];
	struct th89d_rng_args rng;

	memset(&rng, 0, sizeof(rng));
	rng.le  = sizeof(randbuf); // 请求 32 字节随机数
	rng.len = sizeof(randbuf);
	rng.out = randbuf;

	if (ioctl(fd, TH89D_IOCTL_RNG, &rng) < 0) {
		perror("ioctl RNG");
		return;
	}

	dump_hex("Random Data", randbuf, rng.len);
	printf("RNG SW = 0x%04X (SW1=0x%02X, SW2=0x%02X, %s)\n",
		rng.sw, rng.sw >> 8, rng.sw & 0xFF, th89d_sw_str(rng.sw));
}

/* === 测试函数：NVM 擦除 === */
static void test_nvm_erase(int fd)
{
	printf("\n[TEST 3] NVM ERASE\n");

	struct th89d_nvm_erase_args erase;
	memset(&erase, 0, sizeof(erase));

	erase.addr  = 0x00002800;  // 起始地址
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

static void test_nvm_read(int fd)
{
	struct th89d_read_args rd;
	unsigned char buf[512];

	printf("\n[TEST 3] NVM READ\n");

	memset(&rd, 0, sizeof(rd));
	rd.p1 = 0x00;  // 普通读 RAM
	rd.p2 = 0x00;  // 字节方式
	rd.addr = 0x0C000000;
	rd.read_len  = 32;
	rd.out  = buf;

	if (ioctl(fd, TH89D_IOCTL_READ, &rd) < 0) {
		perror("ioctl READ");
		return;
	}

	printf("READ (addr=0x%08X, data_len=%d bytes, req=%d):\n",
	       rd.addr, rd.data_len, rd.read_len);

	if (rd.data_len != rd.read_len) {
	fprintf(stderr,
		"Error: expected %u bytes, but device returned %u bytes\n",
		rd.read_len, rd.data_len);
	fprintf(stderr, "SW = 0x%04X (SW1=0x%02X, SW2=0x%02X) [%s]\n",
		rd.sw, rd.sw >> 8, rd.sw & 0xFF, th89d_sw_str(rd.sw));
	return;
	}

	/* === 格式化打印，每行16字节 === */
	for (int i = 0; i < rd.data_len; i++) {
		if (i % 16 == 0)
			printf("  %04X: ", i);
		printf("%02X ", buf[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	if (rd.data_len % 16)
		printf("\n");

	printf("SW = 0x%04X (SW1=0x%02X, SW2=0x%02X)  [%s]\n",
	       rd.sw, rd.sw >> 8, rd.sw & 0xFF, th89d_sw_str(rd.sw));
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
	test_nvm_read(fd);

	close(fd);
	printf("\n=== TH89D TEST DONE ===\n");
	return 0;
}
