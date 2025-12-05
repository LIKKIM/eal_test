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

static void test_rng(int fd, const char *output_filename)
{
	printf("\n[TEST] RNG\n");

	struct th89d_rng_args rng;
	memset(&rng, 0, sizeof(rng));

	/* 申请随机数缓冲区 */
	uint32_t req_len = 32;
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

	/* ========== 写入文件（如果指定了文件名） ========== */
	if (output_filename && output_filename[0] != '\0') {
		FILE *file = fopen(output_filename, "wb");
		if (file) {
			size_t written = fwrite(rng.random, 1, rng.random_len, file);
			fclose(file);

			if (written == rng.random_len) {
				printf("Random data saved to '%s' (%lu bytes)\n",
				       output_filename, (unsigned long)written);
			} else {
				printf("Warning: Partial write to '%s' "
				       "(written %lu/%u bytes)\n",
				       output_filename, (unsigned long)written, rng.random_len);
			}
		} else {
			perror("Failed to open output file");
		}
	}

	free(randbuf);
	printf("\n[TEST] RNG DONE\n");
}

/* 调用示例 */
int main(int argc, char *argv[])
{
	char *file_name = "random_output.bin";  /* 默认文件名 */
	int fd = open("/dev/thd89", O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	/* 处理命令行参数 */
	if (argc >= 2) {
		file_name = argv[1];  /* 使用用户指定的文件名 */
	} else {
		printf("No output file specified, using default: %s\n", file_name);
	}

	/* 测试RNG并保存到文件 */
	test_rng(fd, file_name);

	close(fd);
	return 0;
}
