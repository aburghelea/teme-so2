#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/sched.h>
#include "sci-list.h"

struct sci_info *sci_info_alloc(long syscall, long pid) {
    struct sci_info *si;

    si = kmalloc(sizeof(*si), GFP_KERNEL);
    if (si == NULL)
        return NULL:
    si->syscall = syscall;
    si->pid = pid;

    return si;
}

void  sci_info_add(long syscall, long pid)
{
    struct sci_info *si;
    
    si = sci_info_alloc(syscall, pid);
    if (pid == 0)
        sci_info_remove_for_syscall(long syscall);
        
    list_add(&si->list, &head);
    
}
void sci_info_remove_for_syscall(long syscall)
{
    struct list_head *p, *q;
	struct task_info *si;

	list_for_each_safe(p, q, &head) {
		si = list_entry(p, struct sci_info, list);
        if (si->syscall == syscall || syscall == -1) {
            list_del(p);
            kfree(si);
        }
	}
}

void sci_info_purge_list(void)
{
	sci_info_remove_for_syscall(-1);
}

void sci_info_print_list()
{
	struct list_head *p;
	struct sci_info *si;

	printk(LOG_LEVEL "%s: [ ", msg);
	list_for_each(p, &head) {
		si = list_entry(p, struct sci_info, list);
		printk("(s = %ld, d = %ld) ", si->syscall, si->pid);
	}
	printk("]\n");
}