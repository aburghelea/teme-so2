/*
 * User: Alexandru George Burghelea
 * 342C5
 * SO2 2013
 * Tema 1
 */

#ifndef _SCI_LIST_H
#define _SCI_LIST_H

/**
 * struct sci_info - Struct describing association between pid and syscall
 * @pid:		Process id
 * @syscall:	System Call
 * @list:		Struct list_head for using the sci_info in a kernel list
 *
 * It is used to maintain the system calls that are monitored and for witch
 * process they are logged
 */
struct sci_info {
	long pid;
	long syscall;
	struct list_head list;
};

/**
 * sci_info_init() - Inits a struct sci_info list
 */
void sci_info_init(void);

/**
 * sci_info_add() - Adds a sci_info element to the list
 * @syscall:	Syscall to be monitored
 * @pid:		Process for witch the syscall is monitored
 */
void  sci_info_add(long syscall, long pid);

/**
 * sci_info_remove_for_pid() - Removes all the entries with the desired pid
 * @pid:	Disired pid to remove
 */
void sci_info_remove_for_pid(long pid);

/**
 * sci_info_remove_for_pid_syscall() Removes entries with the pid and syscall
 * @pid:		Desired pid
 * @syscall:	Desired syscall
 */
void sci_info_remove_for_pid_syscall(long pid, long syscall);

/**
 * sci_info_contains_pid_syscall() - Check the existence of an entry
 * @pid:		Desired pid
 * @syscall:	Desired syscall
 * @return 1 if the entry exist, 0 otherwise
 */
int sci_info_contains_pid_syscall(long pid, long syscall);

/**
 * sci_info_purge_list() - Deletes and dealocates all the elemens of the list
 */
void sci_info_purge_list(void);

/**
 * sci_info_print_list() - Prints the content of a list (KERN_ALERT)
 */
void sci_info_print_list(void);

#endif
