#ifndef _SCI_LIST_H
#define _SCI_LIST_H

struct sci_info {
    long pid;
    long syscall;

    struct list_head list;
}

struct list_head head;

struct sci_info *sci_info_alloc(long syscall, long pid);

void  sci_info_add(long syscall, long pid);

void sci_info_remove_for_syscall(long syscall);

void sci_info_purge_list(void);

void sci_info_print_list();

#endif 
