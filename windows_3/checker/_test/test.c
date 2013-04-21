/*
 * Simple Software RAID: test case
 */

#include <windows.h>
#include <winioctl.h>
#include <strsafe.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "ssr.h"
#include "crc32.h"

#define inline

#define INTERNAL_TESTING	1

#define DEBUG			0
#if DEBUG == 1
#define Dprintf(format, ...)	\
	fprintf(stderr, "[DEBUG] %d: " format, __LINE__, __VA_ARGS__)
#else
#define Dprintf(format, ...)   do { } while(0)
#endif


#define SECTOR_SIZE		KERNEL_SECTOR_SIZE
#define SECTOR_MASK		(KERNEL_SECTOR_SIZE-1)

#define CRC_SIZE		4

#define NUM_SUBTESTS		5

#define BASIC_MOD_PATH		"objchk_wnet_x86\\i386"
#define SSR_BASE_NAME		"ssr"
#define SSR_WIN_EXT		".sys"
#define SSR_MOD_NAME		SSR_BASE_NAME SSR_WIN_EXT
#define SSR_MOD_PATH		BASIC_MOD_PATH "\\" SSR_MOD_NAME

#define dprintf(format, ...)                        \
    fprintf(stdout, " [%s(), %s:%u] " format ,      \
            __FUNCTION__, __FILE__, __LINE__,       \
            ##__VA_ARGS__)


static void test(const char *msg, int test_val)
{
	unsigned int i;

        printf("test: %s", msg);
	fflush(stdout);

	for (i = 0; i < 60-strlen(msg); i++)
		putchar('.');
	if (!test_val)
	        printf("failed [error %d]\n", GetLastError());
	else
		printf("passed\n");

	fflush(stdout);
}

/* file descriptors for logical device and the two physical devices */
static HANDLE log_fd, phys_fd1, phys_fd2;

/* buffers for data regarding the three devices (logical + 2 physical) */
static unsigned char log_buffer[NUM_SUBTESTS * SECTOR_SIZE],
		     phys_buffer1[NUM_SUBTESTS * SECTOR_SIZE],
		     phys_buffer2[NUM_SUBTESTS * SECTOR_SIZE],
		     crc_buffer[SECTOR_SIZE];

/* start sectors array for test cases */
static size_t start_sector_v[NUM_SUBTESTS];


static inline unsigned int uint_rand(void)
{
	return (((unsigned char) rand()) << 24 |
			((unsigned char) rand()) << 16 |
			((unsigned char) rand()) << 8 |
			((unsigned char) rand()));
}

/*
 * random aligned sector position; multiple of SECTOR_SIZE / CRC_SIZE
 * such that corresponding CRC value it is "aligned" to a disk sector
 */

static inline size_t ssr_get_random_aligned_sector(void)
{
	size_t s;

	s = uint_rand() %
		(LOGICAL_DISK_SECTORS - 2 * SECTOR_SIZE / CRC_SIZE) +
		(SECTOR_SIZE / CRC_SIZE);
	s -= (s % (SECTOR_SIZE / CRC_SIZE));

	return s;
}

/*
 * generate start positions in start_sector_v array
 */

static inline void ssr_gen_start_sectors(void)
{
	size_t i;
	unsigned int basic_start;

	for (i = 0; i < NUM_SUBTESTS; i++) {
		basic_start = ssr_get_random_aligned_sector();
		start_sector_v[i] = basic_start - i;
	}
}

/*
 * "upgraded" read routine
 */

static inline size_t xread(HANDLE fd, void *buffer, size_t len)
{
	DWORD bytesRead;
	BOOL ret;
	size_t n;

	n = 0;
	while (n < len) {
		ret = ReadFile(
				fd,
				(char *) buffer + n,
				len - n,
				&bytesRead,
				NULL);
		if (ret != TRUE) {
			fprintf(stderr, "error code is %d\n", GetLastError());
		}
		assert(ret == TRUE);
		n += bytesRead;
	}

	return n;
}

/*
 * "upgraded" write routine
 */
static void WinPerror(const char *message)
{
	CHAR *errBuffer;

	if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(CHAR *) &errBuffer,
			0,
			NULL) == 0) {
		fprintf(stderr, "FormatMessage failed with %d\n", GetLastError());
		return;
	}

	fprintf(stderr, "%s) %s\n",message, errBuffer);
}


static inline size_t xwrite(HANDLE fd, void *buffer, size_t len)
{
	BOOL ret;
	DWORD bytesWritten, dw;
	LPWSTR lpMsgBuf = NULL;
	size_t n;

	n = 0;
	while (n < len) {
		ret = WriteFile(
				fd,
				(char *) buffer + n,
				len - n,
				&bytesWritten,
				NULL);
		dprintf("ret is %d | %ld | %ld | %ld | %p | %c | %d, %d\n", 
			ret, bytesWritten, n, len, fd, ((char *) buffer)[n], len - n);
		if (ret != TRUE) {
			fprintf(stderr, "error code is %d\n", GetLastError());
			WinPerror("Abur xwrite");

		}


		assert(ret == TRUE);
		if (bytesWritten == 0)
			break;
		n += bytesWritten;
	}

	return n;
}

static inline void ssr_test_open_nocheck(void)
{
	log_fd = CreateFile(
			LOGICAL_DISK_USER_NAME,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, 
			OPEN_EXISTING,
			0,
			NULL);
	assert(log_fd != INVALID_HANDLE_VALUE);
	phys_fd1 = CreateFile(
			PHYSICAL_DISK1_USER_NAME,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, 
			OPEN_EXISTING,
			0,
			NULL);
	assert(phys_fd1 != INVALID_HANDLE_VALUE);
	phys_fd2 = CreateFile(
			PHYSICAL_DISK2_USER_NAME,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, 
			OPEN_EXISTING,
			0,
			NULL);
	assert(phys_fd2 != INVALID_HANDLE_VALUE);
}

static inline void ssr_test_close_nocheck(void)
{
	CloseHandle(log_fd);
	CloseHandle(phys_fd1);
	CloseHandle(phys_fd2);
}

static inline void ssr_test_open(void)
{
	log_fd = CreateFile(
			LOGICAL_DISK_USER_NAME,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, 
			OPEN_EXISTING,
			0,
			NULL);
	test("open " LOGICAL_DISK_USER_NAME, log_fd != INVALID_HANDLE_VALUE);
	phys_fd1 = CreateFile(
			PHYSICAL_DISK1_USER_NAME,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, 
			OPEN_EXISTING,
			0,
			NULL);
	assert(phys_fd1 != INVALID_HANDLE_VALUE);
	phys_fd2 = CreateFile(
			PHYSICAL_DISK2_USER_NAME,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, 
			OPEN_EXISTING,
			0,
			NULL);
	assert(phys_fd2 != INVALID_HANDLE_VALUE);
	dprintf("Ended srsOpen\n");
}

static inline void ssr_test_close(void)
{
	test("close " LOGICAL_DISK_USER_NAME, CloseHandle(log_fd) != FALSE);
	test("close " LOGICAL_DISK_USER_NAME, CloseHandle(log_fd) == FALSE);
	assert(CloseHandle(phys_fd1) != FALSE);
	assert(CloseHandle(phys_fd2) != FALSE);
}

static inline size_t ssr_get_crc_offset(size_t data_sector)
{
	return LOGICAL_DISK_SIZE + data_sector * CRC_SIZE;
}

static inline size_t ssr_get_crc_offset_in_sector(size_t data_sector)
{
	return ssr_get_crc_offset(data_sector) & SECTOR_MASK;
}

static inline size_t ssr_get_crc_sector(size_t data_sector)
{
	return ssr_get_crc_offset(data_sector) & ~SECTOR_MASK;
}

/*
 * read sectors from logical disk
 */

static inline size_t ssr_read_log_sectors(HANDLE fd,
		void *buffer, size_t start_sector, size_t num_sectors)
{
	size_t n;

	SetFilePointer(fd, start_sector * SECTOR_SIZE, NULL, FILE_BEGIN);
	n = xread(fd, buffer, num_sectors * SECTOR_SIZE);

	return n;
}

/*
 * write sectors to logical disk
 */

static inline size_t ssr_write_log_sectors(HANDLE fd,
		void *buffer, size_t start_sector, size_t num_sectors)
{
	size_t n;

	SetFilePointer(fd, start_sector * SECTOR_SIZE, NULL, FILE_BEGIN);
	n = xwrite(fd, buffer, num_sectors * SECTOR_SIZE);

	return n;
}

/*
 * read sector from physical disk
 */

static inline size_t ssr_read_phys_sector(HANDLE fd,
		void *buffer, size_t sector)
{
	unsigned int crc_comp, crc_read;
	size_t n;

	SetFilePointer(fd, sector * SECTOR_SIZE, NULL, FILE_BEGIN);
	n = xread(fd, buffer, SECTOR_SIZE);
	crc_comp = update_crc(0, (unsigned char *) buffer, SECTOR_SIZE);

	/* adjust offset for sector alignment */
	SetFilePointer(fd, ssr_get_crc_sector(sector), NULL, FILE_BEGIN);
	n += xread(fd, crc_buffer, SECTOR_SIZE);

	crc_read = * (unsigned int *) (crc_buffer +
			ssr_get_crc_offset_in_sector(sector));

	test("crc check", crc_read == crc_comp);

	return n;
}

/*
 * write sector to physical disk
 */

static inline size_t ssr_write_phys_sector(HANDLE fd,
		void *buffer, size_t sector)
{
	unsigned int crc_comp;
	size_t n;
	size_t crc_offset;

	SetFilePointer(fd, sector * SECTOR_SIZE, NULL, FILE_BEGIN);
	n = xwrite(fd, buffer, SECTOR_SIZE);
	crc_comp = update_crc(0, buffer, SECTOR_SIZE);

	/* adjust offset for sector alignment */
	SetFilePointer(fd, ssr_get_crc_sector(sector), NULL, FILE_BEGIN);
	n += xread(fd, crc_buffer, SECTOR_SIZE);

	* (unsigned int *) (crc_buffer +
			ssr_get_crc_offset_in_sector(sector)) = crc_comp;

	SetFilePointer(fd, crc_offset, NULL, FILE_BEGIN);
	n += xwrite(fd, crc_buffer, SECTOR_SIZE);

	return n;
}

/*
 * fill buffer with random data
 */

static inline void buf_fill_fixed(unsigned char *buf, size_t len,
		unsigned char value)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = value;
}

/*
 * fill buffer with random data
 */

static inline void buf_fill_random(unsigned char *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = (unsigned char) rand();
}

/*
 * test writes: write on RAID virtual disk and check the physical disks
 */

static void ssr_test_writes(size_t start_sector, size_t num_sectors)
{
	size_t n;
	size_t count = 0;
	size_t i;

again:
	/* write log_buffer to RAID device */
#if INTERNAL_TESTING == 1
	buf_fill_fixed(log_buffer, SECTOR_SIZE, 10);
#else
	buf_fill_random(log_buffer, SECTOR_SIZE);
#endif
	n = ssr_write_log_sectors(log_fd, log_buffer, start_sector, num_sectors);

	ssr_test_close_nocheck();
	ssr_test_open_nocheck();

	for (i = 0; i < num_sectors; i++) {
		/* read data from physical devices */
		n = ssr_read_phys_sector(phys_fd1, phys_buffer1, start_sector + i);
		n = ssr_read_phys_sector(phys_fd2, phys_buffer2, start_sector + i);

		/* compare data */
		test("test write1", memcmp(log_buffer + i * SECTOR_SIZE, phys_buffer1, SECTOR_SIZE) == 0);
		test("test write2", memcmp(log_buffer + i * SECTOR_SIZE, phys_buffer2, SECTOR_SIZE) == 0);
	}

	count++;
	if (count < 1)		/* twice on the same area */
		goto again;
}

/*
 * test reads: read data from physical disks and check the RAID virtual disk
 */

static void ssr_test_reads(size_t start_sector, size_t num_sectors)
{
	size_t n;
	size_t i;

	/* read data from RAID virtual disk */
	n = ssr_read_log_sectors(log_fd, log_buffer, start_sector, num_sectors);

	for (i = 0; i < num_sectors; i++) {
		/* read data from physical disks */
		n = ssr_read_phys_sector(phys_fd1, phys_buffer1, start_sector + i);
		n = ssr_read_phys_sector(phys_fd2, phys_buffer2, start_sector + i);

		/* compare data */
		test("test read1", memcmp(log_buffer + i * SECTOR_SIZE, phys_buffer1, SECTOR_SIZE) == 0);
		test("test read2", memcmp(log_buffer + i * SECTOR_SIZE, phys_buffer2, SECTOR_SIZE) == 0);
	}
}

/*
 * test read/write operations on device
 *
 * ReadFile/WriteFile on physical drives can only be done at sector level
 * (SECTOR_SIZE bytes at a time)
 */

static void ssr_test_ops(void)
{
	size_t rand_sect[NUM_SUBTESTS];
	int i;

	ssr_test_open();

	for (i = 0; i < NUM_SUBTESTS; i++) {
#if INTERNAL_TESTING == 1
		rand_sect[i] = 800;
		buf_fill_fixed(phys_buffer1, SECTOR_SIZE, i+1);
#else
		rand_sect[i] = rand() % LOGICAL_DISK_SECTORS;
		buf_fill_random(phys_buffer1, SECTOR_SIZE);
#endif

		SetFilePointer(log_fd, rand_sect[i] * SECTOR_SIZE,
				NULL, FILE_BEGIN);
		dprintf("Trying simple write\n");
		test("simple write", xwrite(log_fd, phys_buffer1, SECTOR_SIZE) == SECTOR_SIZE);

		ssr_test_close_nocheck();
		ssr_test_open_nocheck();

		SetFilePointer(log_fd, rand_sect[i] * SECTOR_SIZE,
				NULL, FILE_BEGIN);
		test("simple read", xread(log_fd, phys_buffer2, SECTOR_SIZE) == SECTOR_SIZE);
		test("simple compare", memcmp(phys_buffer1, phys_buffer2, SECTOR_SIZE) == 0);
		Dprintf("%02x %02x %02x %02x\n",
				phys_buffer1[0], phys_buffer1[1], phys_buffer1[2], phys_buffer1[3]);
		Dprintf("%02x %02x %02x %02x\n",
				phys_buffer2[0], phys_buffer2[1], phys_buffer2[2], phys_buffer2[3]);

	}

	ssr_test_close();
}

static void ssr_test_mirror(void)
{
	size_t i;

	ssr_test_open();
	ssr_test_close();

	ssr_test_open();

	ssr_gen_start_sectors();

	for (i = 0; i < NUM_SUBTESTS; i++)
		ssr_test_writes(start_sector_v[i], NUM_SUBTESTS);
	for (i = 0; i < NUM_SUBTESTS; i++)
		ssr_test_reads(start_sector_v[i], NUM_SUBTESTS);

	ssr_test_close();
}

/*
 * add random amount of data to byte; make sure the result value
 * is different from the original one
 */

static inline unsigned char corrupt_byte(unsigned char byte)
{
	return byte + ((rand() % 128) + 1);
}

/*
 * corrupt physical sector
 */

static void ssr_corrupt(HANDLE fd, size_t sector)
{
	size_t n;
	size_t corrupt_byte_idx;

#if INTERNAL_TESTING == 1
	corrupt_byte_idx = 0;
#else
	corrupt_byte_idx = rand() % SECTOR_SIZE;
#endif
	SetFilePointer(fd, sector * SECTOR_SIZE, NULL, FILE_BEGIN);
	n = xread(fd, phys_buffer1, SECTOR_SIZE);
	phys_buffer1[corrupt_byte_idx] =
		corrupt_byte(phys_buffer1[corrupt_byte_idx]);

	Dprintf("[corrupt] fd: %d, sector: %d, idx: %d, byte: %02x\n",
			fd, sector, corrupt_byte_idx,
			phys_buffer1[corrupt_byte_idx]);
	SetFilePointer(fd, sector * SECTOR_SIZE, NULL, FILE_BEGIN);
	n = xwrite(fd, phys_buffer1, SECTOR_SIZE);
}

/*
 * check sector corruption
 */

static void ssr_check_corrupt(HANDLE fd, size_t sector)
{
	size_t n;
	unsigned int crc_read1, crc_read2, crc_comp1, crc_comp2;

	SetFilePointer(phys_fd1, sector * SECTOR_SIZE, NULL, FILE_BEGIN);
	n = xread(phys_fd1, phys_buffer1, SECTOR_SIZE);
	crc_comp1 = update_crc(0, phys_buffer1, SECTOR_SIZE);

#if INTERNAL_TESTING == 1
	Dprintf("[check_corrupt] buff1[0] = %02x\n", phys_buffer1[0]);
#endif
	/* adjust offset for sector alignment */
	SetFilePointer(phys_fd1, ssr_get_crc_sector(sector), NULL, FILE_BEGIN);
	n = xread(phys_fd1, crc_buffer, SECTOR_SIZE);
	crc_read1 = * (unsigned int *) (crc_buffer +
			ssr_get_crc_offset_in_sector(sector));

	SetFilePointer(phys_fd2, sector * SECTOR_SIZE, NULL, FILE_BEGIN);
	n = xread(phys_fd2, phys_buffer2, SECTOR_SIZE);
	crc_comp2 = update_crc(0, phys_buffer2, SECTOR_SIZE);

#if INTERNAL_TESTING == 1
	Dprintf("[check_corrupt] buff2[0] = %02x\n", phys_buffer2[0]);
#endif
	/* adjust offset for sector alignment */
	SetFilePointer(phys_fd2, ssr_get_crc_sector(sector), NULL, FILE_BEGIN);
	n = xread(phys_fd2, crc_buffer, SECTOR_SIZE);
	crc_read2 = * (unsigned int *) (crc_buffer +
			ssr_get_crc_offset_in_sector(sector));

	Dprintf("crc_comp1 = %08x, crc_read1 = %08x, "		\
			"crc_comp2 = %08x, crc_read2 = %08x\n",
			crc_comp1, crc_read1, crc_comp2, crc_read2);
	if (fd == phys_fd1)
		test("check corrupt",
			crc_comp1 != crc_read1 && crc_comp2 == crc_read2);
	else
		test("check corrupt",
			crc_comp1 == crc_read1 && crc_comp2 != crc_read2);
}

static void ssr_test_recovery_fd(HANDLE fd)
{
	size_t i;

	ssr_gen_start_sectors();

	/* write consistent data */
	for (i = 0; i < NUM_SUBTESTS; i++) {
		buf_fill_random(log_buffer, NUM_SUBTESTS * SECTOR_SIZE);
		ssr_write_log_sectors(log_fd, log_buffer, start_sector_v[i], NUM_SUBTESTS);
	}

	for (i = 0; i < NUM_SUBTESTS; i++)
		ssr_corrupt(fd, start_sector_v[i]);

	for (i = 0; i < NUM_SUBTESTS; i++)
		ssr_check_corrupt(fd, start_sector_v[i]);

	for (i = 0; i < NUM_SUBTESTS; i++)
		ssr_read_log_sectors(log_fd, log_buffer, start_sector_v[i], NUM_SUBTESTS);

	for (i = 0; i < NUM_SUBTESTS; i++)
		ssr_test_reads(start_sector_v[i], NUM_SUBTESTS);
}

static inline void ssr_test_recovery(void)
{
	ssr_test_open();
	ssr_test_recovery_fd(phys_fd1);
	ssr_test_close();

	ssr_test_open();
	ssr_test_recovery_fd(phys_fd2);
	ssr_test_close();
}

static void ssr_test_out_of_bounds(void)
{
	BOOL ret;
	DWORD bytesRead;
	DWORD bytesWritten;

	ssr_test_open();

	SetFilePointer(log_fd, LOGICAL_DISK_SIZE - SECTOR_SIZE, NULL, FILE_BEGIN);

	ret = WriteFile(
			log_fd,
			log_buffer,
			SECTOR_SIZE,
			&bytesWritten,
			NULL);
	test("write limit", bytesWritten == SECTOR_SIZE && ret == TRUE);
	ret = WriteFile(
			log_fd,
			log_buffer,
			SECTOR_SIZE,
			&bytesWritten,
			NULL);
	test("write out of bounds", bytesWritten == 0 || ret == FALSE);

	SetFilePointer(log_fd, LOGICAL_DISK_SIZE - SECTOR_SIZE, NULL, FILE_BEGIN);

	ret = ReadFile(
			log_fd,
			log_buffer,
			SECTOR_SIZE,
			&bytesRead,
			NULL);
	test("read limit", bytesRead == SECTOR_SIZE && ret == TRUE);
	ret = ReadFile(
			log_fd,
			log_buffer,
			SECTOR_SIZE,
			&bytesRead,
			NULL);
	test("read out of bounds", bytesRead == 0 || ret == FALSE);

	ssr_test_close();
}

static inline void ssr_test_insmod(void)
{
	char loadCommand[] = "driver load " SSR_MOD_PATH;
	test(loadCommand, system(loadCommand) == 0);
}

static inline void ssr_test_rmmod(void)
{
	char unloadCommand[] = "driver unload " SSR_BASE_NAME;
	test(unloadCommand, system(unloadCommand) == 0);
}

int main(void)
{
	printf("\nTEST BASIC START\n\n");
	ssr_test_insmod();
	ssr_test_rmmod();

	srand((unsigned int) time(NULL));

	ssr_test_insmod();

	printf("\nTEST OPS\n\n");
	ssr_test_ops();
	printf("\nTEST MIRROR\n\n");
	ssr_test_mirror();
	printf("\nTEST RECOVERY\n\n");
	ssr_test_recovery();
	printf("\nTEST OUT OF BOUNDS\n\n");
	ssr_test_out_of_bounds();

	printf("\nTEST BASIC END\n\n");
	ssr_test_rmmod();

	return 0;
}
