#ifndef _SCI_LIST_H
#define _SCI_LIST_H

#define MEM_TAG 'ruba'

struct sci_info
{
	SINGLE_LIST_ENTRY list;
	HANDLE pid;
	void *syscall;

};

void sci_info_init();

NTSTATUS sci_info_add(void *sycall, HANDLE pid);

NTSTATUS sci_info_remove_for_pid (HANDLE pid);

NTSTATUS sci_info_remove_for_syscall(void *syscall);

NTSTATUS sci_info_remove_for_pid_syscall(void *syscall, HANDLE pid);

BOOLEAN sci_info_contains_pid_syscall(void *syscall, HANDLE pid);

void destroy_list(void);

void print_list(void);

#endif