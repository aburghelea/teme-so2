/*
 * User: Alexandru George Burghelea
 * 342C5
 * SO2 2013
 * Tema 2
 */

#include <ntddk.h>
#include "ssr.h"
#include "crc32.h"

typedef struct _SSR_DEVICE_DATA {
	PDEVICE_OBJECT DeviceObject;
	// char buffer[BUFFER_SIZE];
	ULONG bufferSize;
	KEVENT event;
} SSR_DEVICE_DATA, *PSSR_DEVICE_DATA;

/* Frees the memory and returns system to original state */
void DriverUnload ( PDRIVER_OBJECT driver )
{

	DEVICE_OBJECT *device;

	while (TRUE) {
		device = driver->DeviceObject;
		if (device == NULL)
			break;
		IoDeleteDevice(device);
	}


    return;
}

/* Driver Entry point , inits the Descriptor tables and spinlocks */
NTSTATUS DriverEntry ( PDRIVER_OBJECT driver, PUNICODE_STRING registry )
{
	NTSTATUS status;
	UNICODE_STRING devUnicodeName, linkUnicodeName;
	DEVICE_OBJECT *device;

	RtlZeroMemory(&devUnicodeName, sizeof(devUnicodeName));
	RtlZeroMemory(&linkUnicodeName, sizeof(linkUnicodeName));
	RtlInitUnicodeString(&devUnicodeName,LOGICAL_DISK_DEVICE_NAME);
	RtlInitUnicodeString(&linkUnicodeName,LOGICAL_DISK_LINK_NAME);


	status = IoCreateDevice(driver,
		sizeof(SSR_DEVICE_DATA),
		&devUnicodeName,
		FILE_DEVICE_DISK,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&device
		);
	if (status != STATUS_SUCCESS) {

		goto error;
	}

    driver->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
error:
	DbgPrint("[DriverEntry] Force kill");

    return status;
}