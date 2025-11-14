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
#define TH89D_IOCTL_GET_VERSION		_IOWR(TH89D_IOCTL_MAGIC, 0x02, struct th89d_version_args)

struct th89d_version_args {
	uint8_t  version_type;	/* 要获取的版本类型 */
	char *version;		/* 输出字符串 */
	uint16_t sw;		/* 状态字 */
};

#define TH89D_VER_CRYPTO1	0x00
#define TH89D_VER_SM1		0x01
#define TH89D_VER_SECURE_LIB	0x02
#define TH89D_VER_SSF33		0x03
#define TH89D_VER_SM4		0x04
#define TH89D_VER_CLOCK_CTRL	0x05

static const char *const th89d_ver_name[] = {
	[TH89D_VER_CRYPTO1]	= "Crypto1",
	[TH89D_VER_SM1]		= "SM1",
	[TH89D_VER_SECURE_LIB]	= "SecureLib",
	[TH89D_VER_SSF33]	= "SSF33",
	[TH89D_VER_SM4]		= "SM4",
	[TH89D_VER_CLOCK_CTRL]	= "ClockCtrl",
};

static void test_get_version(int fd)
{
	printf("\n[TEST] GET_VERSION\n");

	for (int type = TH89D_VER_CRYPTO1; type <= TH89D_VER_CLOCK_CTRL; type++) {

		char buf[16] = {0};
		struct th89d_version_args ver;

		memset(&ver, 0, sizeof(ver));

		ver.version_type = type;
		ver.version = buf;

		if (ioctl(fd, TH89D_IOCTL_GET_VERSION, &ver) < 0) {
			fprintf(stderr, "[%s] ioctl failed: %s\n",
				th89d_ver_name[type], strerror(errno));
			continue;
		}

		printf("[%s] Version (type=%02X): %s\n",
			th89d_ver_name[type], type, buf);

		printf("  SW = 0x%04X (SW1=0x%02X, SW2=0x%02X) [%s]\n",
			ver.sw, ver.sw >> 8, ver.sw & 0xFF,
			th89d_sw_str(ver.sw));
	}

	printf("\n[TEST] GET_VERSION DONE\n");
}

int main(void)
{
	int fd = open("/dev/thd89", O_RDWR);
	if (fd < 0) {
		perror("open /dev/thd89");
		return 1;
	}

	test_get_version(fd);

	close(fd);
	return 0;
}
