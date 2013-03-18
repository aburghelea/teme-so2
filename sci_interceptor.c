/*
 * User: Alexandru George Burghelea
 * 342C5
 * SO2 2013
 * Tema 1
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/sched.h>
#include "sci_lin.h"
#include "sci_list.h"
#include <asm/unistd.h>

MODULE_DESCRIPTION("System call interceptor");
MODULE_AUTHOR("Alexandru George Burghelea");
MODULE_LICENSE("GPL");

typedef long (*syscall)(struct syscall_params);
syscall *replace_call_table;

DEFINE_SPINLOCK(call_table_lock);

/**
 * init_replace_call_table() - Allocates and ints a duplicate for sys_call_table
 * @return: 0 for success, -ENOMEM if the allocation failed
 */
static int init_replace_call_table(void)
{
	int i, ct_size;
	spin_lock(&call_table_lock);
	ct_size = my_nr_syscalls * sizeof(syscall);
	replace_call_table = kmalloc(ct_size, GFP_KERNEL);
	if (!replace_call_table) {
		spin_unlock(&call_table_lock);
		return -ENOMEM;
	}

	for (i = 0 ; i < my_nr_syscalls; i++)
		replace_call_table[i] = NULL;

	spin_unlock(&call_table_lock);
	return 0;
}

/**
 * clean_replace_call_table() - Restores sys_call_table from the replacement
 * 
 * Restores sys_call_table from the replacement call table and frees the
 * memorie allocated for replace_call_table;
 */
static void clean_replace_call_table(void)
{
	int i;
	spin_lock(&call_table_lock);

	for (i = 0; i < my_nr_syscalls; i++) {
		if (replace_call_table[i] != NULL)
			sys_call_table[i] = replace_call_table[i];
	}

	kfree(replace_call_table);

	spin_unlock(&call_table_lock);
}

/**
 * start_intercept() - Intercepts a system call
 * @syscall:	Desired syscall
 * @return:		0 for succesfull registration, -EBUSY if syscall is already
 *			already intercepted
 */
static long start_intercept(long syscall)
{
	if (replace_call_table[syscall] != NULL)
		return -EBUSY;

	replace_call_table[syscall] = sys_call_table[syscall];
	sys_call_table[syscall] = sci_syscall;

	return 0;
}

/**
 * stop_intercept() - Deintercepts a system call
 * @syscall:	Desired syscall
 * @return:		0 for succesfull release, -EINVAL if syscall was not already
 * 			already intercepted
 */
static long stop_intercept(long syscall)
{
	if (replace_call_table[syscall] == NULL)
		return -EINVAL;

	sys_call_table[syscall] = replace_call_table[syscall];
	replace_call_table[syscall] = NULL;

	return 0;
}

/**
 * start_monitor() - Monitors the activity of a siscall for a process
 * @syscall:	Desired syscall
 * @pid:		Desired pid
 * @return: 0 for succesfull start, -EBUSY if syscall is already 
 * 			being monitored
 */
static long start_monitor(long syscall, long pid)
{
	if (sci_info_contains_pid_syscall(pid, syscall))
		return -EBUSY;

	sci_info_add(syscall, pid);

	return 0;
}

/**
 * start_monitor() - Unonitors the activity of a siscall for a process
 * @syscall:	Desired syscall
 * @pid:		Desired pid
 * @return: 0 for succesfull stop, -EINVAL if syscall is not already 
 * 			being monitored
 */
static long stop_monitor(long syscall, long pid)
{
	if (!sci_info_contains_pid_syscall(pid, syscall))
		return -EINVAL;

	sci_info_remove_for_pid_syscall(pid, syscall);

	return 0;
}

/**
 * param_validate() - Validates the input parameters for the call
 * @cmd: Desired comand
 * @syscall:	Desired syscall
 * @pid:		Desired pid
 * @return: 0 for succesfull validate, one of the error codes for the 
 * 			situatiaon (see requirements for details) 
 */
static long param_validate(long cmd, long syscall, long pid)
{
	int is_itct, ai;

	if (syscall == MY_SYSCALL_NO || syscall == __NR_exit_group || pid < 0)
		return -EINVAL;

	if (cmd == REQUEST_START_MONITOR || cmd == REQUEST_STOP_MONITOR) {
		int bcu = 0;
		if (pid > 0) {
			struct task_struct *process;
			process = pid_task(find_vpid(pid), PIDTYPE_PID);
			if (process == NULL) {
				sci_info_remove_for_pid(pid);
				return -EINVAL;
			}
			bcu = process->cred->euid == current->cred->euid;
		}
		if (bcu == 0 && current->cred->euid == ROOT_EUID)
			bcu = 1;
		if (!bcu)
			return -EPERM;
	}
	
	is_itct = cmd == REQUEST_SYSCALL_INTERCEPT;
	is_itct = is_itct || cmd == REQUEST_SYSCALL_RELEASE;
	if (is_itct) {
		if (0 != current->cred->euid)
			return -EPERM;

		ai = replace_call_table[syscall] != NULL;
		ai = ai && (cmd == REQUEST_SYSCALL_INTERCEPT);
		if (ai)
			return -EBUSY;

	}
	return 0;
}

/**
 * my_syscall() - Interceptor syscall
 * @cmd: Desired comand
 * @syscall:	Desired syscall
 * @pid:		Desired pid
 * @return: 0 for succesfull run, one of the error codes from 
 *			param_validate(see requirements for details) 
 */
asmlinkage long my_syscall(int cmd, long syscall, long pid)
{
	long code = 0;
	code = param_validate(cmd, syscall, pid);

	if (code)
		return code;

	switch (cmd) {
	case REQUEST_SYSCALL_INTERCEPT: {
		code = start_intercept(syscall);
		break;
	}
	case REQUEST_SYSCALL_RELEASE: {
		code = stop_intercept(syscall);
		break;
	}
	case REQUEST_START_MONITOR: {
		code = start_monitor(syscall, pid);
		break;
	}
	case REQUEST_STOP_MONITOR: {
		code = stop_monitor(syscall, pid);
		break;
	}
	default:
		return -EINVAL;
	}

	return code;
}

/**
 * my_syscall() - Syscall wrapper
 * @sp:		Registers values
 * @return: syscall result
 */
asmlinkage long sci_syscall(struct syscall_params sp)
{
	long syscall = sp.eax;
	long ret = replace_call_table[syscall](sp);
	if (sci_info_contains_pid_syscall(current->pid, syscall))
		log_syscall(current->pid, syscall, sp.ebx, sp.ecx,
					sp.edx, sp.esi, sp.edi, sp.ebp, ret);
	return ret;
}

/**
 * exit_group_syscall() - __NR_exit_group syscall wrapper
 * @sp:		Register values
 * @return: syscall result 
 */
 asmlinkage long exit_group_syscall(struct syscall_params sp)
 {
	sci_info_remove_for_pid(current->pid);
	
	return replace_call_table[__NR_exit_group](sp);
 }
 
/**
 * sci_init() - Module init
 */
static int sci_init(void)
{
	int err;
	err = init_replace_call_table();
	if (err)
		return err;

	sci_info_init();

	sys_call_table[MY_SYSCALL_NO] = my_syscall;
	replace_call_table[__NR_exit_group] = sys_call_table[__NR_exit_group];
	sys_call_table[__NR_exit_group] = exit_group_syscall;

	return 0;
}

/**
 * sci_init() - Module exit
 */
static void sci_exit(void)
{
	clean_replace_call_table();
	sci_info_purge_list();
}

module_init(sci_init);
module_exit(sci_exit);
