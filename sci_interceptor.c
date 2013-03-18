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

extern void *sys_call_table[];
extern long my_nr_syscalls;

typedef long (*syscall)(struct syscall_params);
syscall *replace_call_table;

DEFINE_SPINLOCK(call_table_lock);

static int init_replace_call_table(void)
{
    int i;
    spin_lock(&call_table_lock);
    
    replace_call_table = kmalloc( my_nr_syscalls * sizeof(syscall), GFP_KERNEL);
    if (!replace_call_table) {
        spin_unlock(&call_table_lock);
        return -ENOMEM;
    }

    for (i = 0 ; i < my_nr_syscalls; i++)
        replace_call_table[i] = NULL;

    spin_unlock(&call_table_lock);
    return 0;
}

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

static int start_intercept(long syscall)
{
    if (replace_call_table[syscall] != NULL)
        return -EBUSY;

    replace_call_table[syscall] = sys_call_table[syscall];
    sys_call_table[syscall] = sci_syscall;

    return 0;
}

static int stop_intercept (long syscall)
{
    if (replace_call_table[syscall] == NULL)
        return -EINVAL;
        
    sys_call_table[syscall] = replace_call_table[syscall];
    replace_call_table[syscall] = NULL;

    return 0;
}

static int start_monitor (long syscall, long pid)
{
    if (sci_info_contains_pid_syscall(pid,syscall))
        return -EBUSY;

    sci_info_add(syscall, pid);

    return 0;
}

static int stop_monitor (long syscall, long pid)
{
    if (!sci_info_contains_pid_syscall(pid,syscall)) 
        return -EINVAL;

    sci_info_remove_for_pid_syscall(pid, syscall);

    return 0;
}

static long param_validate(long cmd, long syscall, long pid)
{
    if (syscall == MY_SYSCALL_NO || syscall == __NR_exit_group || pid < 0) {
        return -EINVAL;
    }

    if (cmd == REQUEST_START_MONITOR || cmd == REQUEST_STOP_MONITOR) {
        int bcu = 0;
        if (pid > 0) {
            struct task_struct *process = pid_task(find_vpid(pid), PIDTYPE_PID);
            if (process == NULL) {
                sci_info_remove_for_pid(pid);
                return -EINVAL;
            }
            bcu = process->cred->euid == current->cred->euid;
        }
        if (bcu == 0 && current->cred->euid == 0)
            bcu = 1;
        if (!bcu) {
            return -EPERM;
        }
    }

    if (cmd == REQUEST_SYSCALL_INTERCEPT || cmd == REQUEST_SYSCALL_RELEASE) {
        if (0 != current->cred->euid) {
            return -EPERM;
        }

        if (replace_call_table[syscall] != NULL && cmd == REQUEST_SYSCALL_INTERCEPT ) {
            return -EBUSY;
        }

    }
    return 0;
}

asmlinkage long my_syscall(int cmd, long syscall, long pid)
{
    long invalid = param_validate(cmd, syscall, pid);
    if (invalid)
        return invalid;
    
    int code = 0;

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

asmlinkage long sci_syscall(struct syscall_params sp)
{
    long syscall = sp.eax;
    long ret = replace_call_table[syscall](sp);
    if (sci_info_contains_pid_syscall(current->pid, syscall)) {
        log_syscall(current->pid, syscall,sp.ebx, sp.ecx, sp.edx,sp.esi, sp.edi, sp.ebp,ret);
    }
    return ret;
}

static int sci_init(void)
{
    int err;

    sys_call_table[MY_SYSCALL_NO] = my_syscall;

    err = init_replace_call_table();
    if (err) {
        return err;
    }

    sci_info_init();

    return 0;
}

static void sci_exit(void)
{
    clean_replace_call_table();
    sci_info_purge_list();
}

module_init(sci_init);
module_exit(sci_exit);
