#include <ntddk.h>
#include "sci_list.h"

static SINGLE_LIST_ENTRY head = {NULL};
static KSPIN_LOCK sci_info_lock;
static KIRQL sci_info_irql;

/* Initialize sci_info list and spinlock */
void sci_info_init(void)
{
    KeInitializeSpinLock(&sci_info_lock);
}

/* Add a entry for syscall-pid
 * Returns STATUS_SUCCESS if the elemet was added or if it already exists
 */
NTSTATUS sci_info_add(int syscall, HANDLE pid)
{
    struct sci_info *si;

    if (sci_info_contains_pid_syscall(syscall, pid)) {
        return STATUS_SUCCESS;
    }

    if (pid == NULL)
        sci_info_remove_for_syscall(syscall);

    if (!(si = ExAllocatePoolWithTag(NonPagedPool, sizeof(*si), MTAG)))
        return STATUS_NO_MEMORY;

    si->syscall = syscall;
    si->pid = pid;

    KeAcquireSpinLock(&sci_info_lock, &sci_info_irql);
    PushEntryList(&head, &si->list);
    KeReleaseSpinLock(&sci_info_lock, sci_info_irql);


    return STATUS_SUCCESS;
}

/* Removes all the entries that have the desired pid
 * Returns STATUS_SUCCESS if operation completed,
 * or STATUS_INVALID_PARAMETER otherwise
 */
NTSTATUS sci_info_remove_for_pid(HANDLE pid)
{
    SINGLE_LIST_ENTRY *current, *prev;
    struct sci_info *si = NULL;
    NTSTATUS ret = STATUS_INVALID_PARAMETER;
    prev = &head;
    current = head.Next;

    KeAcquireSpinLock(&sci_info_lock, &sci_info_irql);
    while (current != NULL) {
        si = CONTAINING_RECORD(current, struct sci_info, list);
        if (si->pid == pid) {
            PopEntryList(prev);
            ret = STATUS_SUCCESS;
            break;
        }
        prev = current;
        current = current->Next;
    }

    KeReleaseSpinLock(&sci_info_lock, sci_info_irql);
    if (ret == STATUS_SUCCESS)
        ExFreePoolWithTag(si, MTAG);

    return ret;
}

/* Removes the entries that have the desired syscall
 * Returns STATUS_SUCCESS if operation completed,
 * or STATUS_INVALID_PARAMETER otherwise
 */
NTSTATUS sci_info_remove_for_syscall(int syscall)
{
    SINGLE_LIST_ENTRY *current, *prev;
    struct sci_info *si = NULL;
    NTSTATUS ret = STATUS_INVALID_PARAMETER;
    prev = &head;
    current = head.Next;

    KeAcquireSpinLock(&sci_info_lock, &sci_info_irql);
    while (current != NULL) {
        si = CONTAINING_RECORD(current, struct sci_info, list);
        if (si->syscall == syscall) {
            PopEntryList(prev);
            ret = STATUS_SUCCESS;
            break;
        }
        prev = current;
        current = current->Next;
    }

    KeReleaseSpinLock(&sci_info_lock, sci_info_irql);
    if (ret == STATUS_SUCCESS)
        ExFreePoolWithTag(si, MTAG);

    return ret;
}

/* Removes all the entries that have the desired pid and syscall
 * Returns STATUS_SUCCESS if operation completed,
 * or STATUS_INVALID_PARAMETER otherwise
 */
NTSTATUS sci_info_remove_for_pid_syscall(int syscall, HANDLE pid)
{
    SINGLE_LIST_ENTRY *current, *prev;
    struct sci_info *si = NULL;
    NTSTATUS ret = STATUS_INVALID_PARAMETER;
    int valid_pid, valid_syscall;
    prev = &head;
    current = head.Next;

    KeAcquireSpinLock(&sci_info_lock, &sci_info_irql);
    while (current != NULL) {
        si = CONTAINING_RECORD(current, struct sci_info, list);
        valid_pid = si->pid == pid || si->pid == NULL;
        valid_syscall = si->syscall == syscall;

        if (valid_syscall && valid_pid) {
            PopEntryList(prev);
            ret = STATUS_SUCCESS;
            break;
        }
        prev = current;
        current = current->Next;
    }

    KeReleaseSpinLock(&sci_info_lock, sci_info_irql);
    if (ret == STATUS_SUCCESS)
        ExFreePoolWithTag(si, MTAG);

    return FALSE;
}

/* Checks if there is an entry with the pid and syscall
 * Returns STATUS_SUCCESS if operation completed,
 * or STATUS_INVALID_PARAMETER otherwise
 */
BOOLEAN sci_info_contains_pid_syscall(int syscall, HANDLE pid)
{
    SINGLE_LIST_ENTRY *current;
    struct sci_info *si = NULL;
    NTSTATUS ret = STATUS_INVALID_PARAMETER;
    int valid_pid, valid_syscall;
    current = head.Next;

    KeAcquireSpinLock(&sci_info_lock, &sci_info_irql);
    while (current != NULL) {
        si = CONTAINING_RECORD(current, struct sci_info, list);
        valid_pid = si->pid == pid || si->pid == 0;
        valid_syscall = si->syscall == syscall;

        if (valid_syscall && valid_pid) {
            KeReleaseSpinLock(&sci_info_lock, sci_info_irql);
            return TRUE;
        }
        current = current->Next;
    }
    KeReleaseSpinLock(&sci_info_lock, sci_info_irql);

    return FALSE;
}

/* Deletes the lists and frees the memory */
void sci_info_destroy(void)
{
    SINGLE_LIST_ENTRY *current, *next;
    struct sci_info *si = NULL;
    next = NULL;

    KeAcquireSpinLock(&sci_info_lock, &sci_info_irql);
    for (current = head.Next; current != NULL; current = next) {
        si = CONTAINING_RECORD(current, struct sci_info, list);
        next = current->Next;

        PopEntryList(&head);
        ExFreePoolWithTag(si, MTAG);
    }
    KeReleaseSpinLock(&sci_info_lock, sci_info_irql);
}

/* Prints the content of the list
 * Deprecated (was used in testing)
 */
static void sci_info_print(void)
{
    int val;
    struct sci_info *entry ;
    SINGLE_LIST_ENTRY *current = head.Next;

    KeAcquireSpinLock(&sci_info_lock, &sci_info_irql);
    while (current != NULL) {
        entry = CONTAINING_RECORD(current, struct sci_info, list);
        val = *((int *) entry->pid);
        current = current->Next;
    }
    KeReleaseSpinLock(&sci_info_lock, sci_info_irql);
}
