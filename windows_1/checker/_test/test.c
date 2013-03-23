#include <stdarg.h>
#include <stdio.h>
#include <windows.h>
#include <assert.h>
#include <ntstatus.h>

typedef long NTSTATUS ;

#include "sci_win.h"

static HANDLE ntdll;
static HANDLE token;
static unsigned long last_child;


int syscall(int sno, void *args)
{
	int r;

#ifdef __GNUC__
	__asm__ __volatile__ 
	("movl %1, %%eax; movl %2, %%edx ; int $0x2e; movl %%eax, %0" 
		: "=g" (r) 
		: "g" (sno), "g" (args));
#else
	_asm mov eax, sno
	_asm mov edx, args
	_asm int 0x2e
	_asm mov r, eax
#endif
	return r;
}


int vsyscall(int sno, int count, ...)
{
	va_list va;
	void *args[64];
	int r, i;

	va_start(va, count);
	for(i=0; i<count; i++)
		args[i]=va_arg(va, void*);
	va_end(va);
	r=syscall(sno, args);
	return r;
}

int print_error() 
{
	char *error;
	
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&error, 0, NULL);
	printf("%s\n", error);
	return 0;
}



void clear_log()
{
	HANDLE log;

	assert(log=OpenEventLog(NULL, "System"));
	ClearEventLog(log, NULL);
	CloseEventLog(log);
}

int find_log(const char *driver_name, HANDLE pid, int sno, int sano, void *args, int ret)
{
	static char buffer[4096];
	static int len=4096, ok;
	DWORD readed, dummy;
	EVENTLOGRECORD *event;
	HANDLE log;
	struct log_packet *lp;

	while (1) {
		int i;
		assert(log=OpenEventLog(NULL, "System"));
		i=0; readed=0; 
		do {
			while (readed > 0) { 
				char *source=(char*)event+sizeof(EVENTLOGRECORD);
				i++;
				if (strcmp(driver_name, source) == 0 && event->EventID == 0) {
					lp=(struct log_packet*)((char*)event+event->DataOffset+40);
					if (lp->syscall == sno && lp->syscall_ret == ret &&
						lp->syscall_arg_no == sano && lp->pid == pid &&
						memcmp(args, lp->syscall_arg, sano*4) == 0)
						return 1;
				}
				readed-=event->Length;
				event=(EVENTLOGRECORD*)((char*)event+event->Length);
			}
			ok=ReadEventLog(log, EVENTLOG_FORWARDS_READ|EVENTLOG_SEQUENTIAL_READ, 0, buffer, len, &readed, &dummy);
			event=(EVENTLOGRECORD*)buffer;
		} while (ok);
		CloseEventLog(log);
	}
}

int get_syscall_no(const char *str)
{
	unsigned char *addr;
	int ret;

	assert(addr=(char*)GetProcAddress(ntdll, str));
	assert(addr[0] == 0xb8);
	assert(addr[12] == 0xc3 || addr[12] == 0xc2);

	ret=*(int*)(addr+1);
	return ret;
}

int get_syscall_arg_no(const char *str)
{
	unsigned char *addr;

	assert(addr=(char*)GetProcAddress(ntdll, str));
	assert(addr[0] == 0xb8);
	assert(addr[12] == 0xc3 || addr[12] == 0xc2);
	if (addr[12] == 0xc3)
		return 0;
	return *((short*)(addr+13))/4;
}

#define test(s, a, t) \
{\
	printf("test: "); printf(s, a); printf("...");\
	if (!(t))\
		printf("failed\n");\
	else\
		printf("passed\n");\
}

int do_monitor(const char *str)
{
	int sno, sano, ret, i;
	int *args;

	sno=get_syscall_no(str);
	sano=get_syscall_arg_no(str);
	assert(args=malloc(sano*4));
	for(i=0; i<sano; i++)
		args[i]=rand();
	ret=syscall(sno, args); 
	test("%s interceptor", str, find_log("sci", (HANDLE)GetCurrentProcessId(), sno, sano, args, ret));
	free(args);
	return 0;
}


int do_intercept(const char *str, int status)
{
	test("%s intercept", str, vsyscall(MY_SYSCALL_NO, 3, REQUEST_SYSCALL_INTERCEPT, get_syscall_no(str), 0) == status);
	return 0;
}

int do_release(const char *str, int status)
{
	test("%s release", str, vsyscall(MY_SYSCALL_NO, 3, REQUEST_SYSCALL_RELEASE, get_syscall_no(str), 0) == status);
	return 0;
}

int do_start(const char *str, int pid, int status)
{
	if (pid == -1)
		pid=GetCurrentProcessId();
	test("%s start", str, vsyscall(MY_SYSCALL_NO, 3, REQUEST_START_MONITOR, get_syscall_no(str), pid) == status);
	return 0;
}

int do_stop(const char *str, int pid, int status)
{
	test("%s stop", str, vsyscall(MY_SYSCALL_NO, 3, REQUEST_STOP_MONITOR, get_syscall_no(str), pid) == status);
	return 0;
}

void do_as_guest(const char *str, const char *args1, int args2) 
{
	char dummy[1024];
	PROCESS_INFORMATION pi;
	STARTUPINFO si;

	memset(&si, 0, sizeof(si)); memset(&pi, 0, sizeof(pi));
	sprintf(dummy, str, args1, args2);
	CreateProcessAsUser(token, NULL, dummy, NULL, NULL, FALSE, 0, NULL, NULL,
		&si, &pi);
	last_child=pi.dwProcessId;
	WaitForSingleObject(pi.hProcess, INFINITE);
}

int do_phase2(const char *syscall)
{
	do_intercept(syscall, STATUS_ACCESS_DENIED);
	do_release(syscall, STATUS_ACCESS_DENIED);
	do_start(syscall, 0, STATUS_ACCESS_DENIED);
	do_stop(syscall, 0, STATUS_ACCESS_DENIED);
	do_start(syscall, GetCurrentProcessId(), STATUS_SUCCESS);
	//do_start(syscall, GetCurrentProcessId(), STATUS_DEVICE_BUSY);
	//do_monitor(syscall);
	// do_stop(syscall, GetCurrentProcessId(), STATUS_SUCCESS);
	// do_stop(syscall, GetCurrentProcessId(), STATUS_INVALID_PARAMETER);
	return 0;
}

test_syscall(const char *syscall)
{
	clear_log();
	do_intercept(syscall, STATUS_SUCCESS);
	do_intercept(syscall, STATUS_DEVICE_BUSY);
	 do_as_guest("test phase2 %s", syscall, 0);
	// do_start(syscall, -2, STATUS_INVALID_PARAMETER);
	// do_start(syscall, 0, STATUS_SUCCESS);
	// do_stop(syscall, 0, STATUS_SUCCESS);
	// do_as_guest("test stop %s 0 %d", syscall, STATUS_ACCESS_DENIED);
	// do_as_guest("test start %s -1 %d", syscall, STATUS_SUCCESS);
	// do_stop(syscall, last_child, STATUS_INVALID_PARAMETER);
	// do_release(syscall, STATUS_SUCCESS);
}


int main(int argc, char **argv)
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;

	memset(&si, 0, sizeof(si)); memset(&pi, 0, sizeof(pi));

	srand(time(NULL));

	if (!(ntdll=LoadLibrary("ntdll.dll"))) {
		print_error();
		return -1;
	}

	if (argc>1 && strcmp(argv[1], "intercept") == 0) 
		return do_intercept(argv[2], atoi(argv[3]));

	if (argc>1 && strcmp(argv[1], "start") == 0)
		return do_start(argv[2], atoi(argv[3]), atoi(argv[4]));

	if (argc>1 && strcmp(argv[1], "stop") == 0)
		return do_stop(argv[2], atoi(argv[3]), atoi(argv[4]));

	if (argc>1 && strcmp(argv[1], "release") == 0)
		return do_release(argv[2], atoi(argv[3]));

	if (argc>1 && strcmp(argv[1], "monitor") == 0)
		return do_monitor(argv[2]);

	if (argc>1 && strcmp(argv[1], "phase2") == 0)
		return do_phase2(argv[2]);


	if (!LogonUser("student", NULL, "student", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token)) {
		print_error();
		return -1;
	}

	system("driver load objchk_wnet_x86/i386/sci.sys");

	// test("bad MY_SYSCALL args", NULL, vsyscall(MY_SYSCALL_NO, 3, 100, 0, 0) == STATUS_INVALID_PARAMETER);
	// test("MY_SYSCALL_NO intercept", NULL, vsyscall(MY_SYSCALL_NO, 3, REQUEST_SYSCALL_INTERCEPT, MY_SYSCALL_NO, 0) == STATUS_INVALID_PARAMETER);
	// test("MY_SYSCALL_NO release", NULL, vsyscall(MY_SYSCALL_NO, 3, REQUEST_SYSCALL_RELEASE, MY_SYSCALL_NO, 0) == STATUS_INVALID_PARAMETER);

	test_syscall("NtOpenMutant");
	// test_syscall("NtReleaseMutant");
	// test_syscall("NtOpenFile");
	// test_syscall("NtReadFile");
	// test_syscall("NtClose");

	system("driver unload sci");

	return 0;
}
