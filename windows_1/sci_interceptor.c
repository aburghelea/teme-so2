#include <ntddk.h>

#include "sci_list.h"
#include "sci_win.h"

void **OriginalServiceTableShadow;
void **OriginalServiceTable;

void InitServiceDescriptorTable() {
	
	void ** newSt;
	long no_syscalls = MY_SYSCALL_NO + 1;
	int i;
	SIZE_T sts = no_syscalls * sizeof(void *);
	if (!(newSt = ExAllocatePoolWithTag(NonPagedPool, sts, MEM_TAG)))
		return;

	OriginalServiceTable = KeServiceDescriptorTable[0].st;
	OriginalServiceTableShadow = KeServiceDescriptorTableShadow->st;

	for (i = 0; i <= KeServiceDescriptorTable[0].ls; i++) {
		newSt[i] = KeServiceDescriptorTable[0].st[i];
	}

	WPON();
	KeServiceDescriptorTable[0].st = newSt;
	KeServiceDescriptorTableShadow->st = newSt;
	WPOFF();
}

void CleanServiceDescriptorTable(){
	WPON();
	if (OriginalServiceTable != NULL)
	{
		KeServiceDescriptorTable[0].st = OriginalServiceTable;
		KeServiceDescriptorTableShadow->st = OriginalServiceTableShadow;	
	}
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