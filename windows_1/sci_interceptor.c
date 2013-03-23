#include <ntddk.h>

#include "sci_list.h"
#include "sci_win.h"

// void **OriginalServiceTableShadow;
// void **OriginalServiceTable;
// unsigned char *OriginalSpt;
// unsigned char *OriginalShadowSpt;
// int OriginalLs;

struct std OriginalDescriptorTable;
struct std OriginalDescriptorTableShadow;
struct std *CurrentDescriptorTable;

int my_syscall (int cmd, int syscall_no, HANDLE pid)
{	
	DbgPrint("Entering my syscall");	
	switch (cmd) {
	case REQUEST_SYSCALL_INTERCEPT: {
		DbgPrint("REQUEST_SYSCALL_INTERCEPT\n");
		//code = start_intercept(syscall);
		break;
	}
	case REQUEST_SYSCALL_RELEASE: {
		DbgPrint("REQUEST_SYSCALL_RELEASE\n");
		//code = stop_intercept(syscall);
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
		return STATUS_INVALID_PARAMETER;
	}	

	return STATUS_SUCCESS;
}

void shallowCopyDT(struct std *destination, struct std *source)
{
	destination->st = source->st;
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


		return table;	
}

void deepCopyDescriptoTableInfo( struct std *destination, struct std *source)
{
	int i = 0;
	DbgPrint("%d\n", source->ls);
		
	for (i = 0 ; i <= source->ls; i++){
		DbgPrint("DEEP %d\n", i);
		destination->st[i] = source->st[i];
		destination->spt[i] = source->spt[i];
	}

	destination->st[MY_SYSCALL_NO] = my_syscall;
	destination->ls = MY_SYSCALL_NO + 1;
	destination->spt[MY_SYSCALL_NO] = sizeof(int) * 2 + sizeof(HANDLE);
}
void InitServiceDescriptorTable() {
	
	shallowCopyDT(&OriginalDescriptorTable, &KeServiceDescriptorTable[0]);	
	shallowCopyDT(&OriginalDescriptorTableShadow, KeServiceDescriptorTableShadow);

	CurrentDescriptorTable = allocateDescriptorTableInfo();

	deepCopyDescriptoTableInfo(CurrentDescriptorTable, &OriginalDescriptorTable);
	WPON();
	shallowCopyDT(&KeServiceDescriptorTable[0],CurrentDescriptorTable);
	KeServiceDescriptorTableShadow = CurrentDescriptorTable;
	WPOFF();
}

void CleanServiceDescriptorTable(){
	WPON();
	if (CurrentDescriptorTable != NULL)
	{
	
		shallowCopyDT(&KeServiceDescriptorTable[0], &OriginalDescriptorTable);
		KeServiceDescriptorTableShadow = &OriginalDescriptorTableShadow;
	
	}
	WPOFF();
}


void DriverUnload(PDRIVER_OBJECT driver)
{
	// CleanServiceDescriptorTable();
	
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
	get_shadow();
	
	InitServiceDescriptorTable();
	driver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;  
}