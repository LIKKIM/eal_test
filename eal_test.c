// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/* === IOCTL 定义 === */
#define TH89D_IOCTL_MAGIC        'T'
#define TH89D_IOCTL_GET_VERSION  _IOWR(TH89D_IOCTL_MAGIC, 0x02, struct th89d_version_args)

/* === 数据结构 === */
struct th89d_version_args {
	unsigned int p2;
	unsigned char *out;
	unsigned int len;
};

/* === P2 宏定义 === */
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

/* === 主函数 === */
int main(void)
{
	int fd = open("/dev/thd89", O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	char buf[64];
	struct th89d_version_args args;

	for (int p2 = TH89D_VER_CRYPTO1; p2 <= TH89D_VER_CLOCK_CTRL; p2++) {
		memset(buf, 0, sizeof(buf));
		memset(&args, 0, sizeof(args));

		args.p2  = p2;
		args.out = (unsigned char *)buf;
		args.len = sizeof(buf);

		if (ioctl(fd, TH89D_IOCTL_GET_VERSION, &args) < 0) {
			fprintf(stderr, "[%s] ioctl failed: %s\n",
				th89d_ver_name[p2], strerror(errno));
			continue;
		}

		printf("[%s] Version (P2=%02X): %s\n",
		       th89d_ver_name[p2], p2, buf);
	}

	close(fd);
	return 0;
}
