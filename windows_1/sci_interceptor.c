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

void DriverUnload(PDRIVER_OBJECT driver)
{
	WPOFF();
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
	get_shadow();
	WPON();

	driver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;  
}