#include <ntddk.h>

#include "sci_list.h"
#include "sci_win.h"


void DriverUnload(PDRIVER_OBJECT driver)
{
	WPOFF();
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
	get_shadow();
	WPON();
 //    int a = 1, b = 2, c = 4;
	// driver->DriverUnload = DriverUnload;
 //    sci_info_init();

 //    sci_info_add(NULL, &a);
 //    sci_info_add(NULL, &a);
 //    sci_info_add(NULL, &b);
 //    sci_info_add(NULL, &b);
 //    sci_info_add(NULL, &c);
 //    sci_info_add(NULL, &c);

 //    print_list();
 //    sci_info_remove_for_pid_syscall(NULL, &a);
 //    print_list();

	return STATUS_SUCCESS;  
}