/*
 * SO2 Lab 3 - task 3
 */

#include <ntddk.h>

#include "sci_list.h"
 
SINGLE_LIST_ENTRY head;// = { NULL };

void sci_info_init(void)
{
    head.Next = NULL;
}
 
NTSTATUS sci_info_add(void *syscall, HANDLE pid) 
{
    struct sci_info *si;


    if (sci_info_contains_pid_syscall(syscall, pid)) {
        DbgPrint("Already in\n");
        return STATUS_SUCCESS;
    }

    if (pid == NULL)
        sci_info_remove_for_syscall(syscall);

    if (!(si = ExAllocatePoolWithTag(NonPagedPool, sizeof(*si), MEM_TAG )))
        return STATUS_NO_MEMORY;

    si->syscall = syscall;
    si->pid = pid;
    PushEntryList(&head, &si->list);

    return STATUS_SUCCESS;
}

NTSTATUS sci_info_remove_for_pid (HANDLE pid)
{
    SINGLE_LIST_ENTRY *current, *prev;
    struct sci_info *si = NULL;
    NTSTATUS ret = STATUS_INVALID_PARAMETER;
    prev = &head;
    current = head.Next;

    while(current != NULL){
        si = CONTAINING_RECORD(current, struct sci_info, list);
        if (si->pid == pid) {
            PopEntryList(prev);
            ret = STATUS_SUCCESS;
            break;
        }
        prev = current;
        current = current->Next;
    }
 
    if (ret == STATUS_SUCCESS)
        ExFreePoolWithTag(si, MEM_TAG);

    return ret;
}

NTSTATUS sci_info_remove_for_syscall(void *syscall)
{
    SINGLE_LIST_ENTRY *current, *prev;
    struct sci_info *si = NULL;
    NTSTATUS ret = STATUS_INVALID_PARAMETER;
    prev = &head;
    current = head.Next;

    while(current != NULL){
        si = CONTAINING_RECORD(current, struct sci_info, list);
        if (si->syscall == syscall) {
            PopEntryList(prev);
            ret = STATUS_SUCCESS;
            break;
        }
        prev = current;
        current = current->Next;
    }
 
    if (ret == STATUS_SUCCESS)
        ExFreePoolWithTag(si, MEM_TAG);

    return ret;
}

NTSTATUS sci_info_remove_for_pid_syscall(void *syscall, HANDLE pid)
{
    SINGLE_LIST_ENTRY *current, *prev;
    struct sci_info *si = NULL;
    NTSTATUS ret = STATUS_INVALID_PARAMETER;
    int valid_pid, valid_syscall;
    prev = &head;
    current = head.Next;

    

    while(current != NULL){
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

    if (ret == STATUS_SUCCESS)
        ExFreePoolWithTag(si, MEM_TAG);
 
    return FALSE;
}

BOOLEAN sci_info_contains_pid_syscall(void *syscall, HANDLE pid)
{
    SINGLE_LIST_ENTRY *current;
    struct sci_info *si = NULL;
    NTSTATUS ret = STATUS_INVALID_PARAMETER;
    int valid_pid, valid_syscall;
    current = head.Next;

        

    while(current != NULL){
        si = CONTAINING_RECORD(current, struct sci_info, list);
        valid_pid = si->pid == pid || si->pid == 0;
        valid_syscall = si->syscall == syscall;

        if (valid_syscall && valid_pid) {
            return TRUE;
        }
        current = current->Next;
    }

    return FALSE;
}

void destroy_list(void)
{
    SINGLE_LIST_ENTRY *current, *next;
    struct sci_info *si = NULL;
    next = NULL;
 
    for (current = head.Next; current != NULL; current = next) {
        si = CONTAINING_RECORD(current, struct sci_info, list);
        next = current->Next;
 
        PopEntryList(&head);
        ExFreePoolWithTag(si, MEM_TAG);
    }
}

void print_list(void)
{
    int val;
    struct sci_info *entry ;
    SINGLE_LIST_ENTRY *current = head.Next;

    while (current != NULL) {
        entry = CONTAINING_RECORD(current, struct sci_info, list);
        val = *((int *) entry->pid);
        DbgPrint("-- popped value %d\n",  val);
        current = current->Next;
    }
}
