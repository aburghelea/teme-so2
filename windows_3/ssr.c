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
	PDEVICE_OBJECT deviceObject;
	PFILE_OBJECT mainFileObject;
	PFILE_OBJECT backUpFileObject;
	KEVENT event;
} SSR_DEVICE_DATA, *PSSR_DEVICE_DATA;


SSR_DEVICE_DATA data;

static NTSTATUS OpenPhysicalDisk(PCWSTR diskName, SSR_DEVICE_DATA *dev)
{
	UNICODE_STRING diskDeviceName;
	RtlInitUnicodeString(&diskDeviceName, diskName);
	return IoGetDeviceObjectPointer(
			&diskDeviceName,
			GENERIC_READ | GENERIC_WRITE,
			&dev->mainFileObject,
			&dev->deviceObject);
}

static void ClosePhysicalDisk(SSR_DEVICE_DATA *dev)
{
	ObDereferenceObject(dev->mainFileObject);
}

/* Frees the memory and returns system to original state */
void DriverUnload ( PDRIVER_OBJECT driver )
{

	DEVICE_OBJECT *device;
	UNICODE_STRING linkUnicodeName;
    RtlZeroMemory ( &linkUnicodeName, sizeof ( linkUnicodeName ) );
	RtlInitUnicodeString ( &linkUnicodeName, LOGICAL_DISK_LINK_NAME );
	IoDeleteSymbolicLink(&linkUnicodeName);
	DbgPrint("[DriverUnload] SymbolicLink deleted");

	while (TRUE) {
		device = driver->deviceObject;
		if (device == NULL)
			break;
		IoDeleteDevice(device);
		DbgPrint("[DriverUnload] Device deleting");
	}

	ClosePhysicalDisk(&data);
	DbgPrint("[DriverUnload] Device deleted");
    return;
}

/* Driver Entry point , inits the Descriptor tables and spinlocks */
NTSTATUS DriverEntry ( PDRIVER_OBJECT driver, PUNICODE_STRING registry )
{
	NTSTATUS status;
	UNICODE_STRING devUnicodeName, linkUnicodeName;
	DEVICE_OBJECT *device;


    RtlZeroMemory ( &devUnicodeName, sizeof ( devUnicodeName ) );
    RtlZeroMemory ( &linkUnicodeName, sizeof ( linkUnicodeName ) );
    RtlInitUnicodeString ( &devUnicodeName, LOGICAL_DISK_DEVICE_NAME );
    RtlInitUnicodeString ( &linkUnicodeName, LOGICAL_DISK_LINK_NAME );


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

    status = IoCreateSymbolicLink ( &linkUnicodeName, &devUnicodeName );
	if (status != STATUS_SUCCESS)
		goto error;

    driver->DriverUnload = DriverUnload;
    device->Flags |= DO_DIRECT_IO;
    // data = (SSR_DEVICE_DATA *) device->DeviceExtension;
	data.deviceObject = device;

	status = OpenPhysicalDisk(PHYSICAL_DISK1_DEVICE_NAME, &data);
	if (status != STATUS_SUCCESS) {
		DbgPrint("[DriverEntry] Error opening physical disk\n");
		goto error;
	}


    DbgPrint("[DriverEntry] Exit success");
	return STATUS_SUCCESS;
error:
	DbgPrint("[DriverEntry] Force kill");

    return status;
}


