#include <ntddk.h>

#include "sci_list.h"
#include "sci_win.h"

#define shallow shallowCopyDescriptorTable
#define deep deepCopyDescriptoTableInfo

struct std OrigDescriptorTable;
struct std OrigDescriptorTableShadow;
struct std *CurrentDescriptorTable;
char *intercepted;
PDRIVER_OBJECT gdriver;

static BOOLEAN userHasPermissionToMonitor(long cmd, HANDLE pid)
{
    BOOLEAN ret = FALSE;
    PTOKEN_USER currentUser, requestingUser;
    if (cmd != REQUEST_START_MONITOR && cmd != REQUEST_STOP_MONITOR)
        return TRUE;

    if (UserAdmin())
        return TRUE;

    if (pid != NULL) {
        GetCurrentUser(&currentUser);
        GetUserOf(pid, &requestingUser);
        ret = CheckUsers(currentUser, requestingUser);
    }

    return ret;
}

static BOOLEAN userHasPermissionToIntercept(long cmd)
{
    if (UserAdmin())
        return TRUE;

    return cmd != REQUEST_SYSCALL_INTERCEPT && cmd != REQUEST_SYSCALL_RELEASE;
}

static BOOLEAN monitoringValidPid(long cmd, HANDLE pid)
{
    PTOKEN_USER dummy;
    int succ =  GetUserOf(pid, &dummy);

    if (cmd != REQUEST_START_MONITOR && cmd != REQUEST_STOP_MONITOR)
        return TRUE;

    if (succ != STATUS_SUCCESS && pid != NULL)
        return FALSE;

    return TRUE;
}

static NTSTATUS param_validate(long cmd, long syscall, HANDLE pid)
{
    int is_itct, ai;

    if (syscall == MY_SYSCALL_NO || !monitoringValidPid(cmd, pid))
        return STATUS_INVALID_PARAMETER;

    if (!userHasPermissionToMonitor(cmd, pid))
        return STATUS_ACCESS_DENIED;

    if (!userHasPermissionToIntercept(cmd))
        return STATUS_ACCESS_DENIED;

    return STATUS_SUCCESS;
}

NTSTATUS sci_syscall()
{
    NTSTATUS(*sysc)();
    IO_ERROR_LOG_PACKET *elp;
    struct log_packet *packet;
    UCHAR elp_s;
    int syscall, pr_s, t, i, ret;
    void *old_stack, *new_stack;

    _asm mov syscall, eax
    t = syscall >> 12;
    i = syscall & 0x0000FFF;
    pr_s = KeServiceDescriptorTable[t].spt[i];
    _asm mov old_stack, ebp
    _asm add old_stack, 8
    _asm sub esp, pr_s
    _asm mov new_stack, esp
    RtlCopyMemory(new_stack, old_stack, pr_s);

    sysc = OrigDescriptorTable.st[i];
    ret = sysc();
    if (sci_info_contains_pid_syscall(i, PsGetCurrentProcessId())) {

        elp_s = pr_s + sizeof(IO_ERROR_LOG_PACKET) + sizeof(struct log_packet);
        elp = IoAllocateErrorLogEntry(gdriver, elp_s);
        if (elp != NULL) {
            elp->DumpDataSize = pr_s + sizeof(struct log_packet);
            elp->ErrorCode = STATUS_SUCCESS;
            packet = (struct log_packet *) &elp->DumpData;
            packet->pid = PsGetCurrentProcessId();
            packet->syscall = i;
            packet->syscall_arg_no = pr_s / sizeof(int);
            packet->syscall_ret = ret;
            RtlCopyMemory(packet->syscall_arg, old_stack, pr_s);
            IoWriteErrorLogEntry(elp);
        } else {
            return STATUS_NO_MEMORY;
        }
    }

    return ret;
}

NTSTATUS start_intercept(int syscall)
{
    int t, i;

    t = syscall >> 12;
    i = syscall & 0x0000FFF;

    if (intercepted[i] != 0)
        return STATUS_DEVICE_BUSY;

    intercepted[i] = 'A';
    KeServiceDescriptorTable[t].st[i] = sci_syscall;
    KeServiceDescriptorTableShadow[t].st[i] = sci_syscall;

    return STATUS_SUCCESS;
}

NTSTATUS stop_intercept(int syscall)
{
    int t, i;

    t = syscall >> 12;
    i = syscall & 0x0000FFF;

    if (intercepted[i] == 0)
        return STATUS_INVALID_PARAMETER;

    intercepted[i] = 0;
    KeServiceDescriptorTable[t].st[i] = OrigDescriptorTable.st[i];
    KeServiceDescriptorTableShadow[t].st[i] = OrigDescriptorTableShadow.st[i];

    return STATUS_SUCCESS;
}

static NTSTATUS start_monitor(long syscall, HANDLE pid)
{
    if (sci_info_contains_pid_syscall(syscall, pid))
        return STATUS_DEVICE_BUSY;

    return sci_info_add(syscall, pid);

}

static NTSTATUS stop_monitor(long syscall, HANDLE pid)
{
    if (!sci_info_contains_pid_syscall(syscall, pid))
        return STATUS_INVALID_PARAMETER;

    return sci_info_remove_for_pid_syscall(syscall, pid);
}

int my_syscall(int cmd, int syscall_no, HANDLE pid)
{
    NTSTATUS code = param_validate(cmd, syscall_no, pid);
    if (code != STATUS_SUCCESS)
        return code;

    switch (cmd) {
    case REQUEST_SYSCALL_INTERCEPT: {
        code = start_intercept(syscall_no);
        break;
    }
    case REQUEST_SYSCALL_RELEASE: {
        code = stop_intercept(syscall_no);
        break;
    }
    case REQUEST_START_MONITOR: {
        code = start_monitor(syscall_no, pid);
        break;
    }
    case REQUEST_STOP_MONITOR: {
        code = stop_monitor(syscall_no, pid);
        break;
    }
    default:
        return STATUS_INVALID_PARAMETER;
    }

    return code;
}

void shallowCopyDescriptorTable(struct std *destination, struct std *source)
{
    destination->st = source->st;
    destination->ct = source->ct;
    destination->ls = source->ls;
    destination->spt = source->spt;
}
static void freeDescriptorTableInfo(struct std *table)
{
    if (table) {
        if (table->spt)
            ExFreePoolWithTag(table->spt, MTAG);
        if (table->st)
            ExFreePoolWithTag(table->st, MTAG);
        if (intercepted)
            ExFreePoolWithTag(intercepted, MTAG);
        ExFreePoolWithTag(table, MTAG);
    }
}

struct std *allocateDescriptorTableInfo()
{
    struct std *table;
    int i;
    long no_syscalls = MY_SYSCALL_NO + 1;
    SIZE_T st_size = no_syscalls * sizeof(void *);
    SIZE_T ct_size = no_syscalls * sizeof(int);
    SIZE_T spt_size = no_syscalls * sizeof(unsigned char);
    SIZE_T std_size = sizeof(struct std);

    if (!(table = ExAllocatePoolWithTag(NonPagedPool, std_size, MTAG)))
        goto free;

    if (!(table->st = ExAllocatePoolWithTag(NonPagedPool, st_size, MTAG)))
        goto free;

    if (!(table->spt = ExAllocatePoolWithTag(NonPagedPool, spt_size, MTAG)))
        goto free;

    if (!(intercepted = ExAllocatePoolWithTag(NonPagedPool, spt_size, MTAG)))
        goto free;

    for (i = 0; i < no_syscalls; i++)
        intercepted[i] = 0;
goto exit;

free:
    freeDescriptorTableInfo(table);
    return NULL;

exit:
    return table;
}

void deepCopyDescriptoTableInfo(struct std *destination, struct std *source)
{
    int i = 0;

    for (i = 0 ; i <= source->ls; i++) {
        destination->st[i] = source->st[i];
        destination->spt[i] = source->spt[i];
    }

    destination->st[MY_SYSCALL_NO] = my_syscall;
    destination->ls = MY_SYSCALL_NO + 1;
    destination->spt[MY_SYSCALL_NO] = sizeof(int) * 2 + sizeof(HANDLE);
}

NTSTATUS InitServiceDescriptorTable()
{
    shallow(&OrigDescriptorTable, &KeServiceDescriptorTable[0]);
    shallow(&OrigDescriptorTableShadow, KeServiceDescriptorTableShadow);

    CurrentDescriptorTable = allocateDescriptorTableInfo();
    if (!CurrentDescriptorTable)
        return STATUS_NO_MEMORY;

    deep(CurrentDescriptorTable, &OrigDescriptorTable);
    WPON();
    shallow(&KeServiceDescriptorTable[0], CurrentDescriptorTable);
    shallow(KeServiceDescriptorTableShadow, CurrentDescriptorTable);
    WPOFF();

    return STATUS_SUCCESS;
}

void CleanServiceDescriptorTable()
{
    WPON();
    if (CurrentDescriptorTable) {
        shallow(&KeServiceDescriptorTable[0], &OrigDescriptorTable);
        shallow(KeServiceDescriptorTableShadow, &OrigDescriptorTableShadow);
    }
    WPOFF();
}

VOID deleteRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create)
{
    if (create)
        return;
    else
        if (!sci_info_remove_for_pid(pid))
            DbgPrint("Remove from sci_info error\n");
}

void DriverUnload(PDRIVER_OBJECT driver)
{
    CleanServiceDescriptorTable();
    freeDescriptorTableInfo(CurrentDescriptorTable);
    sci_info_destroy();
    PsSetCreateProcessNotifyRoutine(deleteRoutine, TRUE);

    return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    NTSTATUS status;
    driver->DriverUnload = DriverUnload;
    gdriver = driver;
    get_shadow();
    sci_info_init();

    if (status=InitServiceDescriptorTable())
        return status;

    if (PsSetCreateProcessNotifyRoutine(deleteRoutine, FALSE))
        return STATUS_INVALID_PARAMETER;

    return STATUS_SUCCESS;
}