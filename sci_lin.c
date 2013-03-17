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


static long (*f)(struct syscall_params);
static long (*g)(struct syscall_params);

extern void *sys_call_table[];
extern long my_nr_syscalls;

asmlinkage long interceptor (struct syscall_params sp)
{
	int syscall = sp.eax;
	int r = f(sp);
	printk (LOG_LEVEL "Open intercept %d %d\n", syscall, r);

	return r;
}

asmlinkage long interceptor2 (struct syscall_params sp)
{
	int syscakk = sp.eax;
	int r = g(sp);
	printk (LOG_LEVEL "Close intercept %d %d\n", syscall, r);

	return r;
}

static int sci_init(void)
{
	printk(LOG_LEVEL "SCI Loading\n");
	f = sys_call_table[__NR_open];
	g = sys_call_table[__NR_close];
	sys_call_table[__NR_close] = interceptor2;
	sys_call_table[__NR_open] = interceptor;
	return 0;
}

static void sci_exit(void)
{
	printk(LOG_LEVEL "SCI Unloading\n");
	sys_call_table[__NR_open] = f;
	sys_call_table[__NR_close] = g;
}

module_init(sci_init);
module_exit(sci_exit);
