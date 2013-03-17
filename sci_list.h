#ifndef _SCI_LIST_H
#define _SCI_LIST_H

struct sci_info {
    long pid;
    long syscall;

    struct list_head list;
};

void sci_info_init(void);

struct sci_info *sci_info_alloc(long syscall, long pid);

void  sci_info_add(long syscall, long pid);

void sci_info_remove_for_syscall(long syscall);

void sci_info_remove_for_pid(long pid);

void sci_info_remove_for_pid_syscall(long pid, long syscall);

int sci_info_contains_pid_syscall(long pid, long syscall);

void sci_info_purge_list(void);

void sci_info_print_list(void);

#endif 
