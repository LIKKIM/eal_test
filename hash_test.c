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
#define TH89D_IOCTL_HASH_OP		_IOWR(TH89D_IOCTL_MAGIC, 0x08, struct th89d_hash_args)

/* HASH 参数结构 */
struct th89d_hash_args {
	uint8_t algo;			/* SM3/SHA1/SHA256 */
	uint8_t *data_in;
	uint32_t data_in_len;

	uint8_t *digest;		/* 输出区 */
	uint32_t digest_len;

	uint16_t block_size;		/* 分块大小 */
	uint16_t sw;
};

static void test_hash(const char *filepath, int fd, uint8_t algo, uint16_t blk_size)
{
	struct th89d_hash_args hash;
	uint8_t *data = NULL;
	uint8_t *digest = NULL;

	FILE *fp = NULL;
	long file_size = 0;

	const char *algo_name =
		(algo == 0x06) ? "SM3" :
		(algo == 0x08) ? "SHA1" :
		(algo == 0x0A) ? "SHA256" : "UNKNOWN";

	printf("\n=== [HASH_TEST] %s  file=\"%s\"  block=%u ===\n",
		algo_name, filepath, blk_size);

	/* ----- 打开文件 ----- */
	fp = fopen(filepath, "rb");
	if (!fp) {
		perror("fopen");
		return;
	}

	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	rewind(fp);

	if (file_size <= 0) {
		fprintf(stderr, "Error: cannot read file or empty\n");
		fclose(fp);
		return;
	}

	/* ----- 分配输入缓冲区 ----- */
	data = malloc(file_size);
	if (!data) {
		perror("malloc data");
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

	/* ----- 分配 digest 输出区 ----- */
	digest = malloc(512);
	if (!digest) {
		perror("malloc digest");
		free(data);
		return;
	}
	memset(digest, 0, 512);

	/* ----- 设置参数结构体 ----- */
	memset(&hash, 0, sizeof(hash));
	hash.algo = algo;
	hash.data_in = data;
	hash.data_in_len = file_size;
	hash.digest = digest;
	hash.digest_len = 512;		/* 最大空间 */
	hash.block_size = blk_size;

	/* ----- 发起 ioctl ----- */
	if (ioctl(fd, TH89D_IOCTL_HASH_OP, &hash) < 0) {
		perror("ioctl HASH_OP");
		free(data);
		free(digest);
		return;
	}

	/* ----- 输出结果 ----- */
	printf("SW = 0x%04X (%s)\n", hash.sw, th89d_sw_str(hash.sw));
	dump_hex(hash.digest, hash.digest_len);

	free(data);
	free(digest);

	printf("=== [HASH_TEST] %s DONE ===\n", algo_name);
}

int main(int argc, char *argv[])
{
	if (argc != 4) {
		printf("Usage:\n");
		printf("  hash_test <file> <algo> <block_size>\n");
		printf("\nAlgo:\n");
		printf("  0x06  SM3\n");
		printf("  0x08  SHA1\n");
		printf("  0x0A  SHA256\n");
		return 1;
	}

	const char *filepath = argv[1];
	uint8_t algo = (uint8_t)strtoul(argv[2], NULL, 0);
	uint16_t block_size = (uint16_t)strtoul(argv[3], NULL, 0);

	int fd = open("/dev/thd89", O_RDWR);
	if (fd < 0) {
		perror("open /dev/thd89");
		return 1;
	}

	test_hash(filepath, fd, algo, block_size);

	close(fd);
	return 0;
}
