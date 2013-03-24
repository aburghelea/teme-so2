#ifndef _SCI_LIST_H
#define _SCI_LIST_H

#define MTAG 'ruba'

struct sci_info
{
	SINGLE_LIST_ENTRY list;
	HANDLE pid;
	int syscall;

};

void sci_info_init();

NTSTATUS sci_info_add(int sycall, HANDLE pid);

NTSTATUS sci_info_remove_for_pid (HANDLE pid);

NTSTATUS sci_info_remove_for_syscall(int syscall);

NTSTATUS sci_info_remove_for_pid_syscall(int syscall, HANDLE pid);

BOOLEAN sci_info_contains_pid_syscall(int syscall, HANDLE pid);

void destroy_list(void);

void print_list(void);

#endif