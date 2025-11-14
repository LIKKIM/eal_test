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

#define TH89D_IOCTL_MAGIC		'T'
#define TH89D_IOCTL_RNG			_IOWR(TH89D_IOCTL_MAGIC, 0x01, struct th89d_rng_args)

struct th89d_rng_args {
	uint32_t random_len;	/* 请求的随机数长度 */
	uint8_t *random;	/* 输出缓冲区（用户态分配） */
	uint16_t sw;		/* 状态字 */
};

static void test_rng(int fd)
{
	printf("\n[TEST] RNG\n");

	struct th89d_rng_args rng;
	memset(&rng, 0, sizeof(rng));

	/* 申请随机数缓冲区 */
	uint32_t req_len = 128;
	uint8_t *randbuf = malloc(req_len);
	if (!randbuf) {
		perror("malloc randbuf");
		return;
	}
	memset(randbuf, 0, req_len);

	rng.random_len = req_len;
	rng.random = randbuf;

	/* 发起 IOCTL */
	if (ioctl(fd, TH89D_IOCTL_RNG, &rng) < 0) {
		perror("ioctl RNG");
		free(randbuf);
		return;
	}

	/* 打印输出 */
	printf("Random Data (%u bytes):\n", rng.random_len);
	dump_hex(rng.random, rng.random_len);

	printf("RNG SW = 0x%04X (SW1=0x%02X, SW2=0x%02X) [%s]\n",
		rng.sw, rng.sw >> 8, rng.sw & 0xFF,
		th89d_sw_str(rng.sw));

	free(randbuf);
	printf("\n[TEST] RNG DONE\n");
}

int main(void)
{
	int fd = open("/dev/thd89", O_RDWR);
	if (fd < 0) {
		perror("open /dev/thd89");
		return 1;
	}

	test_rng(fd);

	close(fd);
	return 0;
}
