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

	PDEVICE_OBJECT mainPhysicalDeviceObject;
	PDEVICE_OBJECT backUpPhysicalDeviceObject;

	PFILE_OBJECT mainFileObject;
	PFILE_OBJECT backUpFileObject;
	KEVENT event;

	char buffer[256];
	ULONG bufferSize;

} SSR_DEVICE_DATA, *PSSR_DEVICE_DATA;




static NTSTATUS OpenPhysicalDisk(PCWSTR diskName, SSR_DEVICE_DATA *dev)
{
	UNICODE_STRING diskDeviceName;
	NTSTATUS mainStatus, backUpStatus;
	RtlInitUnicodeString(&diskDeviceName, diskName);
	mainStatus = IoGetDeviceObjectPointer(
			&diskDeviceName,
			GENERIC_READ | GENERIC_WRITE,
			&dev->mainFileObject,
			&dev->mainPhysicalDeviceObject);

	backUpStatus = IoGetDeviceObjectPointer(
			&diskDeviceName,
			GENERIC_READ | GENERIC_WRITE,
			&dev->backUpFileObject,
			&dev->backUpPhysicalDeviceObject);
	return mainStatus && backUpStatus;
}

static void ClosePhysicalDisk(SSR_DEVICE_DATA *dev)
{
	ObDereferenceObject(dev->mainFileObject);
	ObDereferenceObject(dev->backUpFileObject);
	DbgPrint("[DriverUnload] DisksDeleting deleting");
}


/*
 * open device dispatch routine -- do nothing interesting, successfully
 */

NTSTATUS SSROpen(PDEVICE_OBJECT device, IRP *irp)
{

	/* data is not required; retrieve it for consistency */
	SSR_DEVICE_DATA * data =
		(SSR_DEVICE_DATA *) device->DeviceExtension;
	DbgPrint("[SSROpen] Device opened\n");
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


/*
 * close device dispatch routine -- do nothing interesting, successfully
 */

NTSTATUS SSRClose(PDEVICE_OBJECT device, IRP *irp)
{
	/* data is not required; retrieve it for consistency */
	SSR_DEVICE_DATA * data =
		(SSR_DEVICE_DATA *) device->DeviceExtension;

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	DbgPrint("[SSRClose] Device closed\n");
	return STATUS_SUCCESS;
}

/*
 * read from device dispatch routine
 * 	- retrieve buffer size from stack location
 * 	- use _IO_TYPE_ specific method to retrieve user buffer pointer
 * 	- copy data to user buffer
 * 	- complete IRP
 */

NTSTATUS SSRRead(PDEVICE_OBJECT device, IRP *irp)
{
	SSR_DEVICE_DATA * data =
		(SSR_DEVICE_DATA *) device->DeviceExtension;
	PIO_STACK_LOCATION pIrpStack;
	PCHAR readBuffer;
	ULONG sizeToRead, sizeRead;

	/* retrieve buffer size from current stack location */
	pIrpStack = IoGetCurrentIrpStackLocation(irp);
	sizeToRead = pIrpStack->Parameters.Read.Length;
	sizeRead = (sizeToRead < data->bufferSize) ? sizeToRead : data->bufferSize;


	DbgPrint("[SSRRead] DIRECT I/O\n");
	readBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
			NormalPagePriority);
	RtlCopyMemory(readBuffer, data->buffer, sizeRead);

	DbgPrint("[SSRRead] Read buffer \"%s\" of %d bytes\n",
			data->buffer,
			sizeRead);

	/* complete IRP */
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeRead;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS SSRWrite(PDEVICE_OBJECT device, IRP *irp)
{
	SSR_DEVICE_DATA * data =
		(SSR_DEVICE_DATA *) device->DeviceExtension;
	PIO_STACK_LOCATION pIrpStack;
	PCHAR writeBuffer;
	ULONG sizeToWrite, sizeWritten;
	DbgPrint("[SSRWrite] DIRECT I/O\n");
	pIrpStack = IoGetCurrentIrpStackLocation(irp);
	sizeToWrite = pIrpStack->Parameters.Write.Length;
	sizeWritten = (sizeToWrite <= 256) ? sizeToWrite : 256-1;
	RtlZeroMemory(data->buffer, 256);
	data->bufferSize = 0;


	writeBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
			NormalPagePriority);
	RtlCopyMemory(data->buffer, writeBuffer, sizeWritten);


	data->bufferSize = sizeWritten;


	/* complete IRP */
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeWritten;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	DbgPrint("[SSRWrite] Wrote buffer of %d bytes\n",
			sizeWritten);
	return STATUS_SUCCESS;
}


NTSTATUS SSRDeviceIoControl(PDEVICE_OBJECT device, IRP *irp)
{
	ULONG controlCode, inSize, outSize, bytesWritten = 0;
	PIO_STACK_LOCATION pIrpStack;
	NTSTATUS status = STATUS_SUCCESS;
	SSR_DEVICE_DATA * data =
		(SSR_DEVICE_DATA *) device->DeviceExtension;
	PCHAR *buffer;
	DbgPrint("Pe aici intram");
	/* get control code from stack location and buffer from IRP */
	pIrpStack = IoGetCurrentIrpStackLocation(irp);
	controlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	buffer = irp->AssociatedIrp.SystemBuffer;

	switch (controlCode) {

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
	}

	/* complete IRP */
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytesWritten;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
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
		device = driver->DeviceObject;
		if (device == NULL)
			break;
		ClosePhysicalDisk((SSR_DEVICE_DATA *) driver->DeviceObject->DeviceExtension);
		IoDeleteDevice(device);
		DbgPrint("[DriverUnload] Device deleting");
	}

	DbgPrint("[DriverUnload] Device deleted");
    return;
}

/* Driver Entry point , inits the Descriptor tables and spinlocks */
NTSTATUS DriverEntry ( PDRIVER_OBJECT driver, PUNICODE_STRING registry )
{
	NTSTATUS status;
	UNICODE_STRING devUnicodeName, linkUnicodeName;
	DEVICE_OBJECT *device;
	SSR_DEVICE_DATA *data;

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


    device->Flags |= DO_DIRECT_IO;

    data = (SSR_DEVICE_DATA *) device->DeviceExtension;
	data->deviceObject = device;

	driver->DriverUnload = DriverUnload;
	driver->MajorFunction[ IRP_MJ_CREATE ] = SSROpen;
	driver->MajorFunction[ IRP_MJ_READ ] = SSRRead;
	driver->MajorFunction[ IRP_MJ_WRITE ] = SSRWrite;
	driver->MajorFunction[ IRP_MJ_CLOSE ] = SSRClose;
	driver->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = SSRDeviceIoControl;


	status = OpenPhysicalDisk(PHYSICAL_DISK1_DEVICE_NAME, data);
	if (status != STATUS_SUCCESS) {
		DbgPrint("[DriverEntry] Error opening physical disk\n");
		goto error;
	}


    DbgPrint("[DriverEntry] Loaded successfully");
	return STATUS_SUCCESS;
error:
	DbgPrint("[DriverEntry] Force kill");

    return status;
}


