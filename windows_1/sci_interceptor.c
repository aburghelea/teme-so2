#include <ntddk.h>

#include "sci_list.h"
#include "sci_win.h"


void **OriginalServiceTableShadow;
void **OriginalServiceTable;

void InitServiceDescriptorTable() {
	
	long no_syscalls = MY_SYSCALL_NO + 1;
	SIZE_T sts = no_syscalls * sizeof(void *);
	void ** newSt = ExAllocatePoolWithTag(NonPagedPool, sts, MEM_TAG);

	OriginalServiceTable = KeServiceDescriptorTable[0].st;
	OriginalServiceTableShadow = KeServiceDescriptorTableShadow->st;

	KeServiceDescriptorTable[0].st = newSt;
	KeServiceDescriptorTableShadow->st = newSt;
}

void ResetServiceDescriptorTable(){
	KeServiceDescriptorTable[0].st = OriginalServiceTable;
	KeServiceDescriptorTableShadow->st = OriginalServiceTableShadow;	
}

struct std OriginalDescriptorTable;
struct std OriginalDescriptorTableShadow;
struct std *CurrentDescriptorTable;
char *intercepted;

static NTSTATUS param_validate(long cmd, long syscall, HANDLE pid)
{
	int is_itct, ai;

	if (syscall == MY_SYSCALL_NO)
		return STATUS_INVALID_PARAMETER;

	// if (cmd == REQUEST_START_MONITOR || cmd == REQUEST_STOP_MONITOR) {
	// 	int bcu = 0;
	// 	if (pid > 0) {
	// 		struct task_struct *process;
	// 		process = pid_task(find_vpid(pid), PIDTYPE_PID);
	// 		if (process == NULL) {
	// 			sci_info_remove_for_pid(pid);
	// 			return -EINVAL;
	// 		}
	// 		bcu = process->cred->euid == current->cred->euid;
	// 	}
	// 	if (bcu == 0 && current->cred->euid == ROOT_EUID)
	// 		bcu = 1;
	// 	if (!bcu)
	// 		return -EPERM;
	// }
	
	// is_itct = cmd == REQUEST_SYSCALL_INTERCEPT;
	// is_itct = is_itct || cmd == REQUEST_SYSCALL_RELEASE;
	// if (is_itct) {
	// 	if (0 != current->cred->euid)
	// 		return -EPERM;

	// 	ai = replace_call_table[syscall] != NULL;
	// 	ai = ai && (cmd == REQUEST_SYSCALL_INTERCEPT);
	// 	if (ai)
	// 		return -EBUSY;

	// }
	return STATUS_SUCCESS;
}

NTSTATUS start_intercept(int syscall)
{
	if (intercepted[syscall] != 0)
		return STATUS_DEVICE_BUSY;

	intercepted[syscall] = 'A';
	//TODO INTERCEPT

	return STATUS_SUCCESS;
}

NTSTATUS stop_intercept(int syscall)
{
	
	if (intercepted[syscall] == 0)
		return STATUS_INVALID_PARAMETER;

	intercepted[syscall] = 0;
	//TODO INTERCEPT

	return STATUS_SUCCESS;
}
int my_syscall (int cmd, int syscall_no, HANDLE pid)
{	
	NTSTATUS code = param_validate(cmd, syscall_no, pid);
	if (code != STATUS_SUCCESS) {
		DbgPrint("Exit with VALDIATE %d\n",code);
		return code;
	}

	DbgPrint("Entering my syscall %d %d\n",cmd, syscall_no);	
	switch (cmd) {
	case REQUEST_SYSCALL_INTERCEPT: {
		DbgPrint("REQUEST_SYSCALL_INTERCEPT\n");
		code = start_intercept(syscall_no);
		break;
	}
	case REQUEST_SYSCALL_RELEASE: {
		DbgPrint("REQUEST_SYSCALL_RELEASE\n");
		code = stop_intercept(syscall_no);
		break;
	}
	case REQUEST_START_MONITOR: {
		DbgPrint("REQUEST_START_MONITOR\n");
		//code = start_monitor(syscall, pid);
		break;
	}
	case REQUEST_STOP_MONITOR: {
		DbgPrint("REQUEST_STOP_MONITOR\n");
		//code = stop_monitor(syscall, pid);
		break;
	}
	default:
		DbgPrint("Exit with INVALID\n");
		return STATUS_INVALID_PARAMETER;
	}	

	DbgPrint("Exit with SUCCESS\n");
	return code;
}

void shallowCopyDT(struct std *destination, struct std *source)
{
	destination->st = source->st;
	destination->ct = source->ct;
	destination->ls = source->ls;
	destination->spt = source->spt;
}

struct std *allocateDescriptorTableInfo() {
	struct std *table;

	long no_syscalls = MY_SYSCALL_NO + 1;
	int i;
	SIZE_T st_size = no_syscalls * sizeof(void *);
	SIZE_T ct_size = no_syscalls * sizeof(int);
	SIZE_T spt_size = no_syscalls * sizeof(unsigned char);

	if (!(table = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct std), MEM_TAG)))
		return NULL;

	if (!(table->st = ExAllocatePoolWithTag(NonPagedPool, st_size, MEM_TAG)))
		return NULL;

	if (!(table->ct = ExAllocatePoolWithTag(NonPagedPool, ct_size, MEM_TAG)))
		return NULL;
	
	if (!(table->spt = ExAllocatePoolWithTag(NonPagedPool, spt_size, MEM_TAG)))
		return NULL;

	if (!(intercepted = ExAllocatePoolWithTag(NonPagedPool, spt_size, MEM_TAG)))
		return NULL;

	for (i = 0; i < no_syscalls; i++)
		intercepted[i] = 0;

	return table;	
}

void deepCopyDescriptoTableInfo( struct std *destination, struct std *source)
{
	int i = 0;
	DbgPrint("%d\n", source->ls);
		
	for (i = 0 ; i <= source->ls; i++){
		destination->st[i] = source->st[i];
		destination->spt[i] = source->spt[i];
	}

	destination->st[MY_SYSCALL_NO] = my_syscall;
	destination->ls = MY_SYSCALL_NO + 1;
	destination->spt[MY_SYSCALL_NO] = sizeof(int) * 2 + sizeof(HANDLE);
}
void InitServiceDescriptorTable() {
	WPON();
	// shallowCopyDT(&OriginalDescriptorTable, &KeServiceDescriptorTable[0]);	
	// shallowCopyDT(&KeServiceDescriptorTable[0], &OriginalDescriptorTable);
	// get_shadow();
	// shallowCopyDT(&OriginalDescriptorTableShadow, KeServiceDescriptorTableShadow);

	// CurrentDescriptorTable = allocateDescriptorTableInfo();
 
 
	// deepCopyDescriptoTableInfo(CurrentDescriptorTable, &OriginalDescriptorTable);
	// WPON();
	// shallowCopyDT(&KeServiceDescriptorTable[0],CurrentDescriptorTable);
	// shallowCopyDT(KeServiceDescriptorTableShadow, CurrentDescriptorTable);
	WPOFF();
}

void CleanServiceDescriptorTable(){
	WPON();
	// if (CurrentDescriptorTable != NULL)
	// {
		// shallowCopyDT(&KeServiceDescriptorTable[0], &OriginalDescriptorTable);
		// get_shadow();
		// shallowCopyDT(KeServiceDescriptorTableShadow, &OriginalDescriptorTableShadow);
	// }
	WPOFF();
}


void DriverUnload(PDRIVER_OBJECT driver)
{
	CleanServiceDescriptorTable();

	
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
	get_shadow();
	
	InitServiceDescriptorTable();
	driver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;  
}