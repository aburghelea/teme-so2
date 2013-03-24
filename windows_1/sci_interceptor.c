#include <ntddk.h>

#include "sci_list.h"
#include "sci_win.h"

struct std OriginalDescriptorTable;
struct std OriginalDescriptorTableShadow;
struct std *CurrentDescriptorTable;
char *intercepted;
PDRIVER_OBJECT gdriver;

static NTSTATUS param_validate(long cmd, long syscall, HANDLE pid)
{
	int is_itct, ai;

	if (syscall == MY_SYSCALL_NO)
		return STATUS_INVALID_PARAMETER;

	if (cmd == REQUEST_START_MONITOR || cmd == REQUEST_STOP_MONITOR) {
		BOOLEAN bcu = 0;
	 	if (pid != NULL) {
	 		PTOKEN_USER currentUser;
	 		PTOKEN_USER requestingUser;
	 		GetCurrentUser(&currentUser);
	 		
	 		GetUserOf(pid, &requestingUser);
	 		bcu = CheckUsers(currentUser, requestingUser);
	 		DbgPrint("Sunt de la acealsi %d", bcu == FALSE);
		}
	 	if (bcu == FALSE && UserAdmin())
	 			bcu = TRUE;
	 	if (bcu == FALSE){
	 		DbgPrint("Exit denied\n");
	 		return STATUS_ACCESS_DENIED;
	 	}
	}
	
	is_itct = cmd == REQUEST_SYSCALL_INTERCEPT;
	is_itct = is_itct || cmd == REQUEST_SYSCALL_RELEASE;
	if (is_itct) {
	 	if (!UserAdmin())
	 		return STATUS_ACCESS_DENIED;

	 	// ai = intercepted[syscall] != 0;
	 	// ai = ai && (cmd == REQUEST_SYSCALL_INTERCEPT);
	 	// if (ai)
	// 		return -EBUSY;

	}
	return STATUS_SUCCESS;
}


 
NTSTATUS interceptor()
{
	NTSTATUS (*f)();
	IO_ERROR_LOG_PACKET *log_entry;
	struct log_packet *logPacket;
	UCHAR log_entry_size;

    int syscall, param_size, syscall_table;
    int syscall_index, r;
    void *old_stack, *new_stack;
 
    _asm mov syscall, eax
 
    syscall_table = syscall >> 12;
    syscall_index = syscall & 0x0000FFF;
    param_size = KeServiceDescriptorTable[syscall_table].spt[syscall_index];
 
    _asm mov old_stack, ebp
    _asm add old_stack, 8
    _asm sub esp, param_size
    _asm mov new_stack, esp
 
    RtlCopyMemory(new_stack, old_stack, param_size);
 
    f = OriginalDescriptorTable.st[syscall_index];
    r = f();
    if (sci_info_contains_pid_syscall(syscall_index, PsGetCurrentProcessId())){
    	
    	log_entry_size = param_size + sizeof(IO_ERROR_LOG_PACKET) + sizeof(struct log_packet);
    	log_entry = (IO_ERROR_LOG_PACKET *) IoAllocateErrorLogEntry(gdriver, log_entry_size);
    	if (log_entry != NULL) {
    		// RtlFillMemory(log_entry, log_entry_size, 0);
    		log_entry->DumpDataSize = param_size + sizeof(struct log_packet);
    		log_entry->ErrorCode = STATUS_SUCCESS;
    		logPacket = (struct log_packet*) &log_entry->DumpData;
    		logPacket->pid = PsGetCurrentProcessId();
    		logPacket->syscall = syscall_index;
    		logPacket->syscall_ret = r;
    		logPacket->syscall_arg_no = param_size / sizeof(int);
    		RtlCopyMemory(logPacket->syscall_arg, old_stack, param_size);
    		IoWriteErrorLogEntry(log_entry);
    	}
    }
    DbgPrint("syscall %d returns %d\n", syscall, r);
 
    return r;
}
 
void intercept(int syscall)
{
    int syscall_table, syscall_index;
 
    syscall_table = syscall >> 12;
    syscall_index = syscall & 0x0000FFF;
    //f = KeServiceDescriptorTable[syscall_table].st[syscall_index];
 
    /* save service descriptor table entry to f */
 
    KeServiceDescriptorTable[syscall_table].st[syscall_index] = interceptor;
    KeServiceDescriptorTableShadow[syscall_table].st[syscall_index] = interceptor;
    DbgPrint("Intercept request\n");
}

void deintercept(int syscall)
{
    int syscall_table, syscall_index;
 
    syscall_table = syscall >> 12;
    syscall_index = syscall & 0x0000FFF;
    //f = KeServiceDescriptorTable[syscall_table].st[syscall_index];
 
    /* save service descriptor table entry to f */
 
    KeServiceDescriptorTable[syscall_table].st[syscall_index] 
    	= OriginalDescriptorTable.st[syscall_index];
    
    KeServiceDescriptorTableShadow[syscall_table].st[syscall_index] 
    	= OriginalDescriptorTableShadow.st[syscall_index] ;
}

NTSTATUS start_intercept(int syscall)
{
	if (intercepted[syscall] != 0)
		return STATUS_DEVICE_BUSY;

	intercepted[syscall] = 'A';
	intercept(syscall);

	return STATUS_SUCCESS;
}

NTSTATUS stop_intercept(int syscall)
{
	
	if (intercepted[syscall] == 0)
		return STATUS_INVALID_PARAMETER;

	intercepted[syscall] = 0;
	deintercept(syscall);

	return STATUS_SUCCESS;
}

static long start_monitor(long syscall, HANDLE pid)
{
	PTOKEN_USER dummy;
	int succ =  GetUserOf(pid, &dummy);
	if (succ != STATUS_SUCCESS && pid != NULL)
		return STATUS_INVALID_PARAMETER;
	else {
		DbgPrint("Pid VALID\n");
	}
	if (sci_info_contains_pid_syscall(syscall, pid))
		return STATUS_DEVICE_BUSY;

	sci_info_add(syscall, pid);

	return 0;
}

static long stop_monitor(long syscall, HANDLE pid)
{
	PTOKEN_USER dummy;
	int succ = STATUS_SUCCESS == GetUserOf(pid, &dummy);
	if ((!succ && pid !=NULL) || !sci_info_contains_pid_syscall(syscall, pid))
		return STATUS_INVALID_PARAMETER;

	sci_info_remove_for_pid_syscall(syscall, pid);

	return 0;
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
		code = start_monitor(syscall_no, pid);
		break;
	}
	case REQUEST_STOP_MONITOR: {
		DbgPrint("REQUEST_STOP_MONITOR\n");
		code = stop_monitor(syscall_no, pid);
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
	shallowCopyDT(&OriginalDescriptorTable, &KeServiceDescriptorTable[0]);	
	shallowCopyDT(&OriginalDescriptorTableShadow, KeServiceDescriptorTableShadow);

	CurrentDescriptorTable = allocateDescriptorTableInfo();
 
 
	deepCopyDescriptoTableInfo(CurrentDescriptorTable, &OriginalDescriptorTable);
	WPON();
	shallowCopyDT(&KeServiceDescriptorTable[0],CurrentDescriptorTable);
	shallowCopyDT(KeServiceDescriptorTableShadow, CurrentDescriptorTable);
	WPOFF();
}

void CleanServiceDescriptorTable(){
	WPON();
	if (CurrentDescriptorTable != NULL)
	{
		shallowCopyDT(&KeServiceDescriptorTable[0], &OriginalDescriptorTable);
		shallowCopyDT(KeServiceDescriptorTableShadow, &OriginalDescriptorTableShadow);
	}
	WPOFF();
}

VOID deleteRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create)
{
	if (create)
		return;

	else 
		sci_info_remove_for_pid(pid);

}

void DriverUnload(PDRIVER_OBJECT driver)
{
	CleanServiceDescriptorTable();

	PsSetCreateProcessNotifyRoutine(deleteRoutine, TRUE);
	
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
	gdriver = driver;
	get_shadow();
	
	InitServiceDescriptorTable();

	if (PsSetCreateProcessNotifyRoutine(deleteRoutine,FALSE))
		return STATUS_INVALID_PARAMETER;

	driver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;  
}