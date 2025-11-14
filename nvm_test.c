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
#define TH89D_IOCTL_NVM_ERASE		_IOWR(TH89D_IOCTL_MAGIC, 0x03, struct th89d_nvm_erase_args)
#define TH89D_IOCTL_READ		_IOWR(TH89D_IOCTL_MAGIC, 0x04, struct th89d_read_args)

struct th89d_nvm_erase_args {
	uint32_t addr;
	uint8_t pages;
	uint16_t sw;
	uint32_t len;
};

struct th89d_read_args {
	uint8_t  read_mode;      /* normal / strict / tolerant / status */
	uint8_t  access_width;   /* byte / halfword / word */
	uint8_t  strict_level;   /* 0 or 1, only valid when read_mode = STRICT */

	uint32_t address;        /* start address */
	uint32_t length;         /* number of bytes requested */

	uint8_t *data;           /* user buffer */
	uint32_t data_len;       /* actual returned length */

	uint16_t sw;             /* status word */
};

static const char *name_read_mode[] = {
	"NORMAL",
	"STRICT",
	"TOLERANT",
	"STATUS"
};

static const char *name_access_width[] = {
	"BYTE",
	"HALFWORD",
	"WORD"
};

static void run_one_read(int fd,
		uint32_t addr, uint32_t len,
		uint8_t read_mode, uint8_t access_width, uint8_t strict_level)
{
	struct th89d_read_args rd;
	uint8_t *buf = malloc(len);

	if (!buf) {
		perror("malloc");
		return;
	}

	memset(&rd, 0, sizeof(rd));

	/* === 使用新结构体字段 === */
	rd.read_mode    = read_mode;
	rd.access_width = access_width;
	rd.strict_level = strict_level;
	rd.address      = addr;
	rd.length       = len;
	rd.data         = buf;

	printf("\n[%s  %s  strict=%u]\n",
		name_read_mode[read_mode],
		name_access_width[access_width],
		strict_level);

	if (ioctl(fd, TH89D_IOCTL_READ, &rd) < 0) {
		perror("ioctl READ");
		free(buf);
		return;
	}

	printf("SW=0x%04X (%s)\n", rd.sw, th89d_sw_str(rd.sw));
	printf("Read %u bytes\n", rd.data_len);

	if (rd.data_len > 0)
		dump_hex(buf, rd.data_len);

	free(buf);
}

static void test_nvm_erase(int fd, uint32_t addr, uint8_t pages)
{
	struct th89d_nvm_erase_args erase;

	memset(&erase, 0, sizeof(erase));
	erase.addr = addr;
	erase.pages = pages;

	printf("\n[ERASE] addr=0x%08X pages=%u\n", addr, pages);

	if (ioctl(fd, TH89D_IOCTL_NVM_ERASE, &erase) < 0) {
		perror("ioctl ERASE");
		return;
	}

	printf("ERASE OK  SW=0x%04X (%s)\n",
		erase.sw, th89d_sw_str(erase.sw));
}

int main(int argc, char *argv[])
{
	if (argc < 3) {
		printf("Usage:\n");
		printf("  nvm_test erase <addr> <pages>\n");
		printf("  nvm_test read <addr> <len>\n");
		return 1;
	}

	int fd = open("/dev/thd89", O_RDWR);
	if (fd < 0) {
		perror("open /dev/thd89");
		return 1;
	}

	/* ================= ERASE ================= */
	if (!strcmp(argv[1], "erase")) {
		// if (argc != 4) {
		// 	printf("Usage: nvm_test erase <addr> <pages>\n");
		// 	close(fd);
		// 	return 1;
		// }

		// uint32_t addr = strtoul(argv[2], NULL, 0);
		// uint8_t pages = strtoul(argv[3], NULL, 0);

		// test_nvm_erase(fd, addr, pages);
		// close(fd);
		// return 0;
	}

	/* ================= READ (自动跑所有模式) ================= */
	if (!strcmp(argv[1], "read")) {

		if (argc < 4) {
			printf("Usage: nvm_test read <addr> <len>\n");
			close(fd);
			return 1;
		}

		uint32_t addr = strtoul(argv[2], NULL, 0);
		uint32_t len = strtoul(argv[3], NULL, 0);

		printf("\n==== NVM READ TEST addr=0x%08X len=%u ====\n",
			addr, len);

		/* 自动执行所有常用模式 */

		/* NORMAL */
		run_one_read(fd, addr, len, 0, 0, 0);
		run_one_read(fd, addr, len, 0, 1, 0);
		run_one_read(fd, addr, len, 0, 2, 0);

		/* STRICT */
		run_one_read(fd, addr, len, 1, 0, 0);
		run_one_read(fd, addr, len, 1, 0, 1);

		/* TOLERANT */
		run_one_read(fd, addr, len, 2, 0, 0);

		printf("\n==== DONE ====\n");

		close(fd);
		return 0;
	}

	printf("Unknown command '%s'\n", argv[1]);
	close(fd);
	return 1;
}
