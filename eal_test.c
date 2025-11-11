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
		printf("  SW = 0x%04X (SW1=0x%02X, SW2=0x%02X)\n",
		       ver.sw, ver.sw >> 8, ver.sw & 0xFF);
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
	printf("RNG SW = 0x%04X (SW1=0x%02X, SW2=0x%02X)\n",
	       rng.sw, rng.sw >> 8, rng.sw & 0xFF);
}

/* === 测试函数：NVM 擦除 === */
static void test_nvm_erase(int fd)
{
	printf("\n[TEST 3] NVM ERASE\n");

	struct th89d_nvm_erase_args erase;
	memset(&erase, 0, sizeof(erase));

	erase.addr  = 0x00000000;  // 起始地址
	erase.pages = 1;           // 擦除 1 页

	if (ioctl(fd, TH89D_IOCTL_NVM_ERASE, &erase) < 0) {
		perror("ioctl NVM_ERASE");
		return;
	}

	printf("NVM erase success (addr=0x%08X, pages=%u)\n",
	       erase.addr, erase.pages);
	printf("  SW = 0x%04X (SW1=0x%02X, SW2=0x%02X)\n",
	       erase.sw, erase.sw >> 8, erase.sw & 0xFF);
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

	close(fd);
	printf("\n=== TH89D TEST DONE ===\n");
	return 0;
}
