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

MODULE_DESCRIPTION("System call interceptor");
MODULE_AUTHOR("Alexandru George Burghelea");
MODULE_LICENSE("GPL");

extern void *sys_call_table[];
extern long my_nr_syscalls;

void **replace_call_table;
DEFINE_SPINLOCK(call_table_lock);

static int init_replace_call_table(void)
{
    int i;
    spin_lock(&call_table_lock);
    replace_call_table = kmalloc( my_nr_syscalls * sizeof(void *), GFP_KERNEL);
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
    spin_lock(&call_table_lock);
    kfree(replace_call_table);
    spin_unlock(&call_table_lock);
}

asmlinkage long my_syscall(int cmd, long syscall, long pid)
{
    printk(LOG_LEVEL "THIS IS ME TRING TO INTERCEPT THE CALLS");

    switch (cmd)
    {
        case REQUEST_SYSCALL_INTERCEPT:
            printk(LOG_LEVEL "Intercept request for %ld\n", syscall);
            break;
        case REQUEST_SYSCALL_RELEASE:
            printk(LOG_LEVEL "Release request for %ld\n", syscall);
            break;
        case REQUEST_START_MONITOR:
            sci_
            printk(LOG_LEVEL "Monitor request for %ld %ld\n", pid, syscall);
            break;
        case REQUEST_STOP_MONITOR:
            printk(LOG_LEVEL "Stop request for %ld %ld\n", pid, syscall);
            break;
        default:
            printk(LOG_LEVEL ">>>> PANICA <<<<\n");

    }

    return 0;
}

static int sci_init(void)
{
    int err;
    printk(LOG_LEVEL "SCI Loading %ld\n", my_nr_syscalls);
    sys_call_table[MY_SYSCALL_NO] = my_syscall;
    err = init_replace_call_table();

    if (!err)
        return err;
        
    sci_info_add();

    return 0;
}

static void sci_exit(void)
{
    printk(LOG_LEVEL "SCI Unloading\n");
    clean_replace_call_table();
    sci_info_purge_list();
}

module_init(sci_init);
module_exit(sci_exit);
