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


//static long (*f)(struct syscall_params);

static int sci_init(void)
{
	printk(LOG_LEVEL "SCI Loading\n");
	//f = sys_call_table[_NR_open];
	//sys_call_table[_NR_open] = interceptor;
	return 0;
}

static void sci_exit(void)
{
	printk(LOG_LEVEL "SCI Unloading\n");
	//sys_call_table[_NR_open] = f;
}

module_init(sci_init);
module_exit(sci_exit);
