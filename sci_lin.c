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

MODULE_DESCRIPTION("System call interceptor");
MODULE_AUTHOR("Alexandru George Burghelea");
MODULE_LICENSE("GPL");

extern void *sys_call_table[];
extern long my_nr_syscalls;

asmlinkage long my_syscall(int cmd, long syscall, long pid)
{
	printk(LOG_LEVEL "THIS IS ME TRING TO INTERCEPT THE CALLS");
}

static int sci_init(void)
{
	printk(LOG_LEVEL "SCI Loading %ld\n", my_nr_syscalls);
	sys_call_table[MY_SYSCALL_NO] = my_syscall;
	return 0;
}



static void sci_exit(void)
{
	printk(LOG_LEVEL "SCI Unloading\n");
}

module_init(sci_init);
module_exit(sci_exit);
