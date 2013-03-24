#ifndef _SCI_LIST_H
#define _SCI_LIST_H

#define MTAG 'ruba'

struct sci_info {
    SINGLE_LIST_ENTRY list;
    HANDLE pid;
    int syscall;
};

/* Initialize sci_info list and spinlock */
void sci_info_init();

/* Add a entry for syscall-pid
 * Returns STATUS_SUCCESS if the elemet was added or if it already exists
 */
NTSTATUS sci_info_add(int sycall, HANDLE pid);

/* Removes all the entries that have the desired pid
 * Returns STATUS_SUCCESS if operation completed,
 * or STATUS_INVALID_PARAMETER otherwise
 */
NTSTATUS sci_info_remove_for_pid (HANDLE pid);

/* Removes the entries that have the desired syscall
 * Returns STATUS_SUCCESS if operation completed,
 * or STATUS_INVALID_PARAMETER otherwise
 */
NTSTATUS sci_info_remove_for_syscall(int syscall);

/* Removes all the entries that have the desired pid and syscall
 * Returns STATUS_SUCCESS if operation completed,
 * or STATUS_INVALID_PARAMETER otherwise
 */
NTSTATUS sci_info_remove_for_pid_syscall(int syscall, HANDLE pid);

/* Checks if there is an entry with the pid and syscall
 * Returns STATUS_SUCCESS if operation completed,
 * or STATUS_INVALID_PARAMETER otherwise
 */
BOOLEAN sci_info_contains_pid_syscall(int syscall, HANDLE pid);

/* Deletes the lists and frees the memory */
void sci_info_destroy(void);

#endif