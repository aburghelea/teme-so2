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

#include "sci_list.h"

static struct list_head head;
static spinlock_t sci_info_lock;

static struct sci_info *sci_info_alloc(long syscall, long pid);
static int sci_info_contains_pid_syscall_unlocked(long pid, long syscall);
static void sci_info_remove_for_syscall(long syscall);

/**
 * sci_info_init() - Inits a struct sci_info list
 */
void sci_info_init(void)
{
	INIT_LIST_HEAD(&head);
	spin_lock_init(&sci_info_lock);
}

/**
 * sci_info_add() - Adds a sci_info element to the list
 * @syscall:	Syscall to be monitored
 * @pid:		Process for witch the syscall is monitored
 */
void  sci_info_add(long syscall, long pid)
{
	struct sci_info *si;
	spin_lock(&sci_info_lock);
	if (sci_info_contains_pid_syscall_unlocked(pid, syscall))
		return;

	si = sci_info_alloc(syscall, pid);
	if (pid == 0)
		sci_info_remove_for_syscall(syscall);

	list_add(&si->list, &head);
	spin_unlock(&sci_info_lock);
}

/**
 * sci_info_remove_for_pid() - Removes all the entries with the desired pid
 * @pid:	Disired pid to remove
 */
void sci_info_remove_for_pid(long pid)
{
	struct list_head *p, *q;
	struct sci_info *si;
	spin_lock(&sci_info_lock);
	list_for_each_safe(p, q, &head) {
		si = list_entry(p, struct sci_info, list);
		if (si->pid == pid) {
			list_del(p);
			kfree(si);
		}
	}
	spin_unlock(&sci_info_lock);
}

/**
 * sci_info_remove_for_pid_syscall() Removes entries with the pid and syscall
 * @pid:		Desired pid
 * @syscall:	Desired syscall
 */
void sci_info_remove_for_pid_syscall(long pid, long syscall)
{
	struct list_head *p, *q;
	struct sci_info *si;
	int valid_pid;
	spin_lock(&sci_info_lock);
	list_for_each_safe(p, q, &head) {
		si = list_entry(p, struct sci_info, list);
		valid_pid = si->pid == pid || si->pid == 0;
		if (valid_pid && si->syscall == syscall) {
			list_del(p);
			kfree(si);
		}
	}
	spin_unlock(&sci_info_lock);
}

/**
 * sci_info_contains_pid_syscall() - Check the existence of an entry
 * @pid:		Desired pid
 * @syscall:	Desired syscall
 * @return 1 if the entry exist, 0 otherwise
 */
int sci_info_contains_pid_syscall(long pid, long syscall)
{
	int status = 0;

	spin_lock(&sci_info_lock);
	status = sci_info_contains_pid_syscall_unlocked(pid, syscall);
	spin_unlock(&sci_info_lock);

	return status;
}
/**
 * sci_info_purge_list() - Deletes and dealocates all the elemens of the list
 */
void sci_info_purge_list(void)
{
	spin_lock(&sci_info_lock);
	sci_info_remove_for_syscall(-1);
	spin_unlock(&sci_info_lock);
}

/**
 * sci_info_print_list() - Prints the content of a list (KERN_ALERT)
 */
void sci_info_print_list(void)
{
	struct list_head *p;
	struct sci_info *si;
	spin_lock(&sci_info_lock);
	printk(KERN_ALERT ": [ ");
	list_for_each(p, &head) {
		si = list_entry(p, struct sci_info, list);
		printk("(s = %ld, d = %ld) ", si->syscall, si->pid);
	}
	printk("]\n");
	spin_unlock(&sci_info_lock);
}
/**
 * sci_info_alloc() Creates a sci_info from a pid and syscall
 * @pid:		Desired pid
 * @syscall:	Desired syscall
 * @return struct *sci_info with the desired info
 */
static struct sci_info *sci_info_alloc(long syscall, long pid)
{
	struct sci_info *si;

	si = kmalloc(sizeof(*si), GFP_KERNEL);
	if (si == NULL)
		return NULL;
	si->syscall = syscall;
	si->pid = pid;

	return si;
}

/**
 * sci_info_remove_for_syscall() - Removes all the entries with the syscall
 * @syscall:	Disired syscall to remove
 *
 * It is not protected by a spin_lock
 */
static void sci_info_remove_for_syscall(long syscall)
{
	struct list_head *p, *q;
	struct sci_info *si;
	list_for_each_safe(p, q, &head) {
		si = list_entry(p, struct sci_info, list);
		if (syscall == -1 || si->syscall == syscall) {
			list_del(p);
			kfree(si);
		}
	}
}

/**
 * sci_info_contains_pid_syscall_unlocked() - Checks the existence of sci_info
 * @syscall:	Desired syscall
 * @return 1 if the entry exist, 0 otherwise
 *
 * It is not protected by a spin_lock
 */
static int sci_info_contains_pid_syscall_unlocked(long pid, long syscall)
{
	struct list_head *p;
	struct sci_info *si;

	list_for_each(p, &head) {
		si = list_entry(p, struct sci_info, list);
		if ((si->pid == pid || si->pid == 0) && si->syscall == syscall)
			return 1;
	}

	return 0;
}

