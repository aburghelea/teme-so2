/*
 * User: Alexandru George Burghelea
 * 342C5
 * SO2 2013
 * Tema 1
 */

#ifndef _SCI_LIN_H
#define _SCI_LIN_H

#define REQUEST_START_MONITOR		0
#define REQUEST_STOP_MONITOR		1
#define REQUEST_SYSCALL_INTERCEPT	2
#define REQUEST_SYSCALL_RELEASE		3

#define MY_SYSCALL_NO             0

#define LOG_LEVEL KERN_ALERT

#ifdef __KERNEL__

extern void *sys_call_table[];
extern long my_nr_syscalls;

asmlinkage long my_syscall(int cmd, long syscall, long pid);

#define log_syscall(pid, syscall, arg1, arg2, arg3, arg4, arg5, arg6, ret) \
	printk(KERN_DEBUG"[%x]%lx(%lx,%lx,%lx,%lx,%lx,%lx)=%lx\n", pid, \
		syscall, \
		arg1, arg2, arg3, arg4, arg5, arg6, \
		ret \
	);
#endif

struct syscall_params {
	long ebx, ecx, edx, esi, edi, ebp, eax;
};

static asmlinkage long sci_syscall(struct syscall_params sp);

#endif
