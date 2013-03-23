#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <wait.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#include "sci_lin.h"

static int last_child;

__attribute__((regparm(0))) int msyscall(int sno, long *args)
{
	int ret;

	__asm__ __volatile__ ( " push %%ebp" : :);
	__asm__ __volatile__ ( " push %0" : : "g" (sno));
	__asm__ __volatile__ ( " push %0" : : "g" (args[0]));
	__asm__ __volatile__ ( " push %0" : : "g" (args[1]));
	__asm__ __volatile__ ( " push %0" : : "g" (args[2]));
	__asm__ __volatile__ ( " push %0" : : "g" (args[3]));
	__asm__ __volatile__ ( " push %0" : : "g" (args[4]));
	__asm__ __volatile__ ( " push %0" : : "g" (args[5]));
	__asm__ __volatile__ ( " pop %%ebp; pop %%edi; pop %%esi; pop %%edx; \
				 pop %%ecx; pop %%ebx; pop %%eax; int $0x80; \
				 pop %%ebp" : : );
	__asm__ __volatile__ ( " movl %%eax, %0" : "=g" (ret):);
	 
	return ret;
}

int vsyscall(int sno, int n, ...)
{
	va_list va;
	long args[6];
	int i;
	
	va_start(va, n);
	for(i=0; i<n; i++)
		args[i]=va_arg(va, long);
	va_end(va);
	return msyscall(sno, args);
}

#define test(s, a, t) \
({\
	int i;\
	char dummy[1024];\
	\
	sprintf(dummy, s, a);\
        printf("test: %s", dummy); \
	for(i=0; i<60-strlen(dummy); i++)\
		putchar('.');\
	if (!(t))\
	        printf("failed\n");\
	else\
		printf("passed\n");\
	fflush(stdout);\
})

int clear_log()
{
	return system("dmesg -c &> /dev/null");
}

int find_log(long pid, long sno, long *args, long ret)
{
	char dummy[1024];
	/* Witout timestamps */
	/*
	sprintf(dummy, "dmesg | grep '^\\[%lx\\]%lx(%lx,%lx,%lx,%lx,%lx,%lx)=%lx' &> /dev/null", (long)getpid(), sno, args[0],
		args[1], args[2], args[3], args[4], args[5], ret);
	*/
	/* With timestamps */
	sprintf(dummy, "dmesg | grep '^\\[\\s*[0-9]*\\.[0-9]\\{6\\}\\] \\[%lx\\]%lx(%lx,%lx,%lx,%lx,%lx,%lx)=%lx' 2>&1 > /dev/null", (long)getpid(), sno, args[0],
		args[1], args[2], args[3], args[4], args[5], ret);
	return system(dummy);
}

int do_monitor(int syscall)
{
	int sno, ret, i;
	long args[6];
	
	sno=syscall;
	for(i=0; i<6; i++)
		args[i]=rand();
	ret=msyscall(sno, args); 
	test("%d interceptor", syscall, find_log(getpid(), sno, args, ret) == 0);
	return 0;
}


int do_intercept(int syscall, int status)
{
	test("%d intercept", syscall, vsyscall(MY_SYSCALL_NO, 3, REQUEST_SYSCALL_INTERCEPT, syscall, 0) == status);
	return 0;
}

int do_release(int syscall, int status)
{
	test("%d release", syscall, vsyscall(MY_SYSCALL_NO, 3, REQUEST_SYSCALL_RELEASE, syscall, 0) == status);
	return 0;
}

int do_start(int syscall, int pid, int status)
{
	if (pid == -1)
		pid=getpid();
	test("%d start", syscall, vsyscall(MY_SYSCALL_NO, 3, REQUEST_START_MONITOR, syscall, pid) == status);
	return 0;
}

int do_stop(int syscall, int pid, int status)
{
	test("%d stop", syscall, vsyscall(MY_SYSCALL_NO, 3, REQUEST_STOP_MONITOR, syscall, pid) == status);
	return 0;
}

void do_as_guest(const char *str, int args1, int args2) 
{
	char dummy[1024];
	char dummy2[1024];
	char* exec[]={"bash", "-c", dummy2, NULL};

	sprintf(dummy, str, args1, args2);
	sprintf(dummy2, "su nobody -c '%s' ", dummy);
	switch ((last_child=fork()))  {
		case -1:
			assert(0);
		case 0:
			execvp("/bin/bash", exec);
			assert(0);
		default:
			waitpid(last_child, NULL, 0);
	}
}

int do_phase2(int syscall)
{
	do_intercept(syscall, -EPERM);
	do_release(syscall, -EPERM);
	do_start(syscall, 0, -EPERM);
	do_stop(syscall, 0, -EPERM);
	do_start(syscall, 1, -EPERM);
	do_stop(syscall, 1, -EPERM);
	do_start(syscall, getpid(), 0);
	do_start(syscall, getpid(), -EBUSY);
	do_monitor(syscall);
	do_stop(syscall, getpid(), 0);
	do_stop(syscall, getpid(), -EINVAL);
	return 0;
}


void test_syscall(int syscall)
{
	clear_log();
	do_intercept(syscall, 0);
	do_intercept(syscall, -EBUSY);
	do_as_guest("./test phase2 %d", syscall, 0);
	do_start(syscall, -2, -EINVAL);
	do_start(syscall, 0, 0);
	do_stop(syscall, 0, 0);
	do_start(syscall, 1, 0);
	do_as_guest("./test stop %d 1 %d", syscall, -EPERM);
	do_stop(syscall, 1, 0);
	do_as_guest("./test start %d -1 %d", syscall, 0);
	do_stop(syscall, last_child, -EINVAL);
	do_release(syscall, 0);
}


int main(int argc, char **argv)
{

	srand(time(NULL));

	if (argc>1 && strcmp(argv[1], "intercept") == 0) 
		return do_intercept(atoi(argv[2]), atoi(argv[3]));

	if (argc>1 && strcmp(argv[1], "start") == 0)
		return do_start(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));

	if (argc>1 && strcmp(argv[1], "stop") == 0)
		return do_stop(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));

	if (argc>1 && strcmp(argv[1], "release") == 0)
		return do_release(atoi(argv[2]), atoi(argv[3]));

	if (argc>1 && strcmp(argv[1], "monitor") == 0)
		return do_monitor(atoi(argv[2]));

	if (argc>1 && strcmp(argv[1], "phase2") == 0)
		return do_phase2(atoi(argv[2]));

	test("insmod sci.ko", "", system("insmod sci.ko") == 0);
	test("bad MY_SYSCALL args%s", "",  vsyscall(MY_SYSCALL_NO, 3, 100, 0, 0) == -EINVAL);
	do_intercept(MY_SYSCALL_NO, -EINVAL);
	do_release(MY_SYSCALL_NO, -EINVAL);

	do_intercept(__NR_exit_group, -EINVAL);
	do_release(__NR_exit_group, -EINVAL);

	test_syscall(SYS_open);
	test_syscall(SYS_read);
	test_syscall(SYS_close);
	test_syscall(SYS_mmap);
	test_syscall(SYS_ioctl);
	test("rmmod sci.ko", "", system("rmmod sci") == 0);
	return 0;
}

