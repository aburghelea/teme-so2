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
        
    printk(LOG_LEVEL "Starting Intercept for %ld\n", syscall);
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
        
    sci_info_add(syscall, pid);
    
    return 0;
}
asmlinkage long sci_syscall(struct syscall_params sp) 
{
    long syscall = sp.eax;
    long ret = replace_call_table[syscall](sp); 
    if (sci_info_contains_pid_syscall(current->pid, syscall)) {
        log_syscall(current->pid, syscall,sp.ebx, sp.ecx, sp.edx,sp.esi, sp.edi, sp.ebp,ret);
        printk(LOG_LEVEL "DADADADADA\n");
    }
    return ret;
}
static long param_validate(long cmd, long syscall, long pid)
{
    if (syscall == MY_SYSCALL_NO || syscall == __NR_exit_group ){
        printk(LOG_LEVEL "EINVAL\n");
        return -EINVAL;
    }
 
    if (cmd == REQUEST_START_MONITOR || cmd == REQUEST_STOP_MONITOR) {
        int bcu = 0;
        printk(LOG_LEVEL "%ld -- ",pid);
        if (pid > 0) {
            struct task_struct *process = pid_task(find_vpid(pid), PIDTYPE_PID);
            bcu = process->cred->euid == current->cred->euid;
            printk(LOG_LEVEL "bcu %d %d -- %d\n ",bcu, process->cred->euid , current->cred->uid);
        }    
        if (!bcu ){
            printk(LOG_LEVEL "EPERMx\n");
            return -EPERM;
        }
    }

    if (cmd == REQUEST_SYSCALL_INTERCEPT || cmd == REQUEST_SYSCALL_RELEASE) {
        if (0 != current->cred->euid) {
            printk(LOG_LEVEL "EPERM\n");
            return -EPERM;
        }  
        
        if (replace_call_table[syscall] != NULL){
            printk(LOG_LEVEL "EBUSY\n");
            return -EBUSY;
        }
          
    }
    printk(LOG_LEVEL "NORM\n");    
    return 0;
}
asmlinkage long my_syscall(int cmd, long syscall, long pid)
{
    //printk(LOG_LEVEL "THIS IS ME TRING TO INTERCEPT THE CALLS");
    long invalid = param_validate(cmd, syscall, pid);
    if (invalid)
        return invalid;
        
    switch (cmd)
    {
        case REQUEST_SYSCALL_INTERCEPT: {
            int code = start_intercept(syscall);
            if(code != 0)
                return code;
            break;
        }
        case REQUEST_SYSCALL_RELEASE: {
            int code = stop_intercept(syscall);
            if(code != 0)
                return code;
            break;
         }
        case REQUEST_START_MONITOR: {
            int code = start_monitor(syscall, pid);
            if(code != 0)
                return code;
            break;
        }
        case REQUEST_STOP_MONITOR:{
            int code = stop_monitor(syscall, pid);
            if(code != 0)
                return code;
            break;
        }
        default:
            printk(LOG_LEVEL ">>>> PANICA <<<<\n");

    }

    return 0;
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
