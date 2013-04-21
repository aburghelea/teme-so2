/*
 * User: Alexandru George Burghelea
 * 342C5
 * SO2 2013
 * Tema 2
 */

#include <ntddk.h>
#include "ssr.h"
#include "crc32.h"


#define BUFFER_SIZE 256
typedef struct _SSR_DEVICE_DATA {
    PDEVICE_OBJECT deviceObject;

    PDEVICE_OBJECT mainPhysicalDeviceObject;
    PDEVICE_OBJECT backUpPhysicalDeviceObject;

    PFILE_OBJECT mainFileObject;
    PFILE_OBJECT backUpFileObject;

    KEVENT event;
    IO_STATUS_BLOCK ioStatus;

    char *buffer;
    ULONG bufferSize;

    unsigned long CRC;
    LARGE_INTEGER byteOffset;

} SSR_DEVICE_DATA, *PSSR_DEVICE_DATA;




static NTSTATUS OpenPhysicalDisk ( PCWSTR diskName, PCWSTR backupName, SSR_DEVICE_DATA *dev )
{
    UNICODE_STRING diskDeviceName;
     UNICODE_STRING backupDeviceName;
    NTSTATUS mainStatus, backUpStatus;
    RtlInitUnicodeString ( &diskDeviceName, diskName );
    RtlInitUnicodeString ( &backupDeviceName, backupName );
    mainStatus = IoGetDeviceObjectPointer (
                     &diskDeviceName,
                     GENERIC_READ | GENERIC_WRITE,
                     &dev->mainFileObject,
                     &dev->mainPhysicalDeviceObject );

    backUpStatus = IoGetDeviceObjectPointer (
                       &backupDeviceName,
                       GENERIC_READ | GENERIC_WRITE,
                       &dev->backUpFileObject,
                       &dev->backUpPhysicalDeviceObject );
    return mainStatus && backUpStatus;
}

static void ClosePhysicalDisk ( SSR_DEVICE_DATA *dev )
{
    ObDereferenceObject ( dev->mainFileObject );
    ObDereferenceObject ( dev->backUpFileObject );
    DbgPrint ( "[DriverUnload] DisksDeleting deleting" );
}


#define IRP_WRITE_MESSAGE   "def"

static NTSTATUS SendIrp ( SSR_DEVICE_DATA *dev, ULONG major, 
                          BOOLEAN backUp, BOOLEAN CRC ) {
    PIRP irp = NULL;
    KEVENT irpEvent;
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER offset;
    PDEVICE_OBJECT storageDeviceObject;
    PVOID buffer;
    ULONG size ;
    /* compiler has support for 64-bit integers */
    // offset.QuadPart = 0;


    KeInitializeEvent (
        &irpEvent,
        NotificationEvent,
        FALSE );

    if (!backUp) {
        storageDeviceObject = dev->mainPhysicalDeviceObject;
    } else {
        storageDeviceObject = dev->backUpPhysicalDeviceObject;
    }

    if (CRC) {
        buffer = &dev->CRC;
        size = (sizeof(dev->CRC));
        offset.QuadPart = LOGICAL_DISK_SIZE;
    } else {
        buffer = dev->buffer;
        size = dev->bufferSize;
        offset = dev->byteOffset;
    }
    irp = IoBuildSynchronousFsdRequest (
              major,
              storageDeviceObject,
              buffer,
              size,
              &offset,
              &irpEvent,
              &dev->ioStatus );
    if ( irp == NULL )  {
        status = STATUS_INSUFFICIENT_RESOURCES;
        return status;
    }

    status = IoCallDriver (
                 storageDeviceObject,
                 irp );

    KeWaitForSingleObject (
        &irpEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL );


    return dev->ioStatus.Status;
}

static NTSTATUS SendTestIrp ( SSR_DEVICE_DATA *dev, ULONG major )
{

    NTSTATUS status = STATUS_SUCCESS, status2;

    status = SendIrp(dev, major, FALSE, FALSE);
    status = SendIrp(dev, major, FALSE, TRUE);
    status2 = SendIrp(dev, major, TRUE, FALSE);
    status2 = SendIrp(dev, major, TRUE, TRUE);

    return status /*|| status2*/;
}




/*
 * open device dispatch routine -- do nothing interesting, successfully
 */

NTSTATUS SSROpen ( PDEVICE_OBJECT device, IRP *irp )
{

    /* data is not required; retrieve it for consistency */
    SSR_DEVICE_DATA *data =
        ( SSR_DEVICE_DATA * ) device->DeviceExtension;
    DbgPrint ( "[SSROpen] Device opened\n" );
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest ( irp, IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}


/*
 * close device dispatch routine -- do nothing interesting, successfully
 */

NTSTATUS SSRClose ( PDEVICE_OBJECT device, IRP *irp )
{
    /* data is not required; retrieve it for consistency */
    SSR_DEVICE_DATA *data =
        ( SSR_DEVICE_DATA * ) device->DeviceExtension;

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest ( irp, IO_NO_INCREMENT );

    DbgPrint ( "[SSRClose] Device closed\n" );
    return STATUS_SUCCESS;
}

/*
 * ` from device dispatch routine
 *  - retrieve buffer size from stack location
 *  - use _IO_TYPE_ specific method to retrieve user buffer pointer
 *  - copy data to user buffer
 *  - complete IRP
 */

NTSTATUS SSRRead ( PDEVICE_OBJECT device, IRP *irp )
{
    SSR_DEVICE_DATA *data =
        ( SSR_DEVICE_DATA * ) device->DeviceExtension;
    PIO_STACK_LOCATION pIrpStack;
    PCHAR readBuffer;
    ULONG sizeToRead;

    /* retrieve buffer size from current stack location */
    pIrpStack = IoGetCurrentIrpStackLocation ( irp );
    sizeToRead = pIrpStack->Parameters.Read.Length;

    data->bufferSize = sizeToRead;
    data->byteOffset = pIrpStack->Parameters.Read.ByteOffset;
    data->buffer = ExAllocatePoolWithTag ( NonPagedPool, sizeof ( char ) * sizeToRead, '1gat' );
    SendTestIrp ( data, IRP_MJ_READ );
	DbgPrint ( "[SSRRead] buffer is %02x %02x %02x\n",
        data->buffer[0],  data->buffer[1],  data->buffer[2] );
    readBuffer = MmGetSystemAddressForMdlSafe ( irp->MdlAddress,
                 NormalPagePriority );
    RtlCopyMemory ( readBuffer, data->buffer, data->bufferSize );

    DbgPrint ( "[SSRRead] CRC %lu\n", data->CRC);

    /* complete IRP */
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = sizeToRead;
    IoCompleteRequest ( irp, IO_NO_INCREMENT );

    ExFreePoolWithTag ( data->buffer, '1gat' );
    data->bufferSize = 0;

    return STATUS_SUCCESS;
}


NTSTATUS SSRWrite ( PDEVICE_OBJECT device, IRP *irp )
{
    SSR_DEVICE_DATA *data =
        ( SSR_DEVICE_DATA * ) device->DeviceExtension;
    PIO_STACK_LOCATION pIrpStack;
    PCHAR writeBuffer;
    ULONG sizeToWrite;
    pIrpStack = IoGetCurrentIrpStackLocation ( irp );
    sizeToWrite = pIrpStack->Parameters.Write.Length;
    data->bufferSize = sizeToWrite;
    data->byteOffset = pIrpStack->Parameters.Write.ByteOffset;
    data->buffer = ExAllocatePoolWithTag ( NonPagedPool, sizeof ( char ) * sizeToWrite, '1gat' );

    writeBuffer = MmGetSystemAddressForMdlSafe ( irp->MdlAddress,
                  NormalPagePriority );
    RtlCopyMemory ( data->buffer, writeBuffer, sizeToWrite );
    data->CRC = update_crc(0, (unsigned char *) data->buffer, data->bufferSize);
    DbgPrint ( "[SSRWrite] CRC %lu\n", data->CRC);

    SendTestIrp ( data, IRP_MJ_WRITE );

    ExFreePoolWithTag ( data->buffer, '1gat' );
    data->bufferSize = 0;
    /* complete IRP */
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = sizeToWrite;
    IoCompleteRequest ( irp, IO_NO_INCREMENT );

	DbgPrint ( "[SSRWrite] buffer is %02x %02x %02x\n",
            data->buffer[0],  data->buffer[1],  data->buffer[2] );

    return STATUS_SUCCESS;
}




/* Frees the memory and returns system to original state */
void DriverUnload ( PDRIVER_OBJECT driver )
{

    DEVICE_OBJECT *device;
    UNICODE_STRING linkUnicodeName;
    RtlZeroMemory ( &linkUnicodeName, sizeof ( linkUnicodeName ) );
    RtlInitUnicodeString ( &linkUnicodeName, LOGICAL_DISK_LINK_NAME );
    IoDeleteSymbolicLink ( &linkUnicodeName );
    DbgPrint ( "[DriverUnload] SymbolicLink deleted" );
    ClosePhysicalDisk ( ( SSR_DEVICE_DATA * ) driver->DeviceObject->DeviceExtension );
    while ( TRUE ) {
        device = driver->DeviceObject;
        if ( device == NULL )
            break;

        IoDeleteDevice ( device );
        DbgPrint ( "[DriverUnload] Device deleting" );
    }

    DbgPrint ( "[DriverUnload] Device deleted" );
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


    status = IoCreateDevice ( driver,
                              sizeof ( SSR_DEVICE_DATA ),
                              &devUnicodeName,
                              FILE_DEVICE_DISK,
                              FILE_DEVICE_SECURE_OPEN,
                              FALSE,
                              &device
                            );
    if ( status != STATUS_SUCCESS ) {
        goto error;
    }

    status = IoCreateSymbolicLink ( &linkUnicodeName, &devUnicodeName );
    if ( status != STATUS_SUCCESS )
        goto error;


    device->Flags |= DO_DIRECT_IO;

    data = ( SSR_DEVICE_DATA * ) device->DeviceExtension;
    data->deviceObject = device;

    driver->DriverUnload = DriverUnload;
    // driver->MajorFunction[ IRP_MJ_CREATE ] = SSROpen;
    driver->MajorFunction[ IRP_MJ_READ ] = SSRRead;
    driver->MajorFunction[ IRP_MJ_WRITE ] = SSRWrite;
    // driver->MajorFunction[ IRP_MJ_CLOSE ] = SSRClose;
    // driver->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = SSRDeviceIoControl;


    status = OpenPhysicalDisk ( PHYSICAL_DISK1_DEVICE_NAME, PHYSICAL_DISK2_DEVICE_NAME, data );
    if ( status != STATUS_SUCCESS ) {
        DbgPrint ( "[DriverEntry] Error opening physical disk\n" );
        goto error;
    }


    DbgPrint ( "[DriverEntry] Loaded successfully" );
    return STATUS_SUCCESS;
error:
    DbgPrint ( "[DriverEntry] Force kill" );

    return status;
}


