/*
 * User: Alexandru George Burghelea
 * 342C5
 * SO2 2013
 * Tema 2
 */

#include <ntddk.h>
#include "ssr.h"
#include "crc32.h"

#define CRC_SIZE 4
#define SECTOR_SIZE        KERNEL_SECTOR_SIZE
#define SECTOR_MASK     (KERNEL_SECTOR_SIZE-1)

typedef struct _SSR_DEVICE_DATA {
    PDEVICE_OBJECT deviceObject;

    PDEVICE_OBJECT mainPhysicalDeviceObject;
    PDEVICE_OBJECT backUpPhysicalDeviceObject;

    PFILE_OBJECT mainFileObject;
    PFILE_OBJECT backUpFileObject;

    char *buffer;
    ULONG bufferSize;
    LARGE_INTEGER byteOffset;

} SSR_DEVICE_DATA, *PSSR_DEVICE_DATA;


static LONGLONG ssr_get_crc_offset(LONGLONG data_sector)
{
    return LOGICAL_DISK_SIZE + data_sector * CRC_SIZE;
}

static LONGLONG ssr_get_crc_offset_in_sector(LONGLONG data_sector)
{
    return ssr_get_crc_offset(data_sector) & SECTOR_MASK;
}

static LONGLONG ssr_get_crc_sector(LONGLONG data_sector)
{
    return ssr_get_crc_offset(data_sector) & ~SECTOR_MASK;
}

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


static NTSTATUS SendIrp (ULONG major, PDEVICE_OBJECT device, 
                         LARGE_INTEGER offset,PVOID buffer, 
                         ULONG size)
{
    PIRP irp = NULL;
    KEVENT irpEvent;
    NTSTATUS status = STATUS_SUCCESS;
    IO_STATUS_BLOCK ioStatus;

    KeInitializeEvent (
        &irpEvent,
        NotificationEvent,
        FALSE );

    irp = IoBuildSynchronousFsdRequest (
              major,
              device,
              buffer,
              size,
              &offset,
              &irpEvent,
              &ioStatus );
    if ( irp == NULL )  {
        status = STATUS_INSUFFICIENT_RESOURCES;
        return status;
    }

    status = IoCallDriver ( device, irp );

    KeWaitForSingleObject (
        &irpEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL );


    return ioStatus.Status;
}
#define GET_CRC_SECTOR(do, offset)      \
        SendIrp(IRP_MJ_READ,            \
                do,                     \
                offset,                 \
                CRC_BUFFER,             \
                SECTOR_SIZE);

#define SET_CRC_SECTOR(do, offset)      \
        SendIrp(IRP_MJ_WRITE,           \
                do,                     \
                offset,                 \
                CRC_BUFFER,             \
                SECTOR_SIZE);
static NTSTATUS SendTestIrp ( SSR_DEVICE_DATA *dev, ULONG major )
{

    NTSTATUS status = STATUS_SUCCESS;
    unsigned char data_buffer[SECTOR_SIZE];
    unsigned char CRC_BUFFER[SECTOR_SIZE];

    LONGLONG offset_in_sector;
    LARGE_INTEGER initialOffset;

    LONGLONG i = 0;

    unsigned int CRC, CRC_CALC;
    LONGLONG sector_disk_offset;
    sector_disk_offset = dev->byteOffset.QuadPart / SECTOR_SIZE;


    if (major == IRP_MJ_WRITE) {
        for (i = 0 ; i < dev->bufferSize; i+= SECTOR_SIZE){
            initialOffset.QuadPart=ssr_get_crc_sector(sector_disk_offset + i / SECTOR_SIZE);
            offset_in_sector = ssr_get_crc_offset_in_sector(
                        sector_disk_offset + i / SECTOR_SIZE
                        );

            RtlCopyMemory(data_buffer, dev->buffer + i, SECTOR_SIZE);
            CRC = update_crc(0, data_buffer, SECTOR_SIZE);

            // Update main crc============
            GET_CRC_SECTOR(dev->mainPhysicalDeviceObject, initialOffset);
            memcpy(CRC_BUFFER + offset_in_sector, &CRC, sizeof(CRC));
            SET_CRC_SECTOR(dev->mainPhysicalDeviceObject, initialOffset);

            // Update backup CRC
            GET_CRC_SECTOR(dev->backUpPhysicalDeviceObject, initialOffset);
            memcpy(CRC_BUFFER + offset_in_sector, &CRC, sizeof(CRC));
            SET_CRC_SECTOR(dev->backUpPhysicalDeviceObject, initialOffset);
        }
    }

    status = SendIrp(major,
        dev->mainPhysicalDeviceObject,
        dev->byteOffset,
        dev->buffer,
        dev->bufferSize);
    if (major == IRP_MJ_READ) {
        for (i = 0 ; i < dev->bufferSize; i+= SECTOR_SIZE){
            initialOffset.QuadPart=ssr_get_crc_sector(sector_disk_offset + i / SECTOR_SIZE);
            offset_in_sector = ssr_get_crc_offset_in_sector(
                        sector_disk_offset + i / SECTOR_SIZE
                        );

            RtlCopyMemory(data_buffer, dev->buffer + i, SECTOR_SIZE);
            CRC_CALC = update_crc(0, data_buffer, SECTOR_SIZE);

            // Update main crc============
            GET_CRC_SECTOR(dev->mainPhysicalDeviceObject, initialOffset);
            memcpy(&CRC, CRC_BUFFER + offset_in_sector, sizeof(CRC));
            if (CRC != CRC_CALC){
                DbgPrint("Crc master gresit");
                status = SendIrp(major,
                                dev->backUpPhysicalDeviceObject,
                                dev->byteOffset,
                                data_buffer,
                                SECTOR_SIZE);
                DbgPrint("De disc 1 %lu \n", CRC_CALC);
                CRC_CALC = update_crc(0, data_buffer, SECTOR_SIZE);
                DbgPrint("Pe disc 1 %lu \n", CRC);
                GET_CRC_SECTOR(dev->backUpPhysicalDeviceObject, initialOffset);
                DbgPrint("Pe disc 2 %lu \n", CRC);
                RtlCopyMemory( dev->buffer + i, data_buffer,SECTOR_SIZE);
                // RtlCopyMemory(data_buffer, dev->buffer + i, SECTOR_SIZE);

                DbgPrint("De disc 2 %lu \n", CRC_CALC);
                if (CRC != CRC_CALC){
                    DbgPrint("Tot gresit gresit %lu", CRC_CALC);
                }
                status = SendIrp(IRP_MJ_WRITE,
                                dev->mainPhysicalDeviceObject,
                                dev->byteOffset,
                                data_buffer,
                                SECTOR_SIZE);
                memcpy(CRC_BUFFER + offset_in_sector, &CRC, sizeof(CRC));
                SET_CRC_SECTOR(dev->mainPhysicalDeviceObject, initialOffset);
            }
            // SET_CRC_SECTOR(dev->mainPhysicalDeviceObject, initialOffset);

            // // Update backup CRC
            // GET_CRC_SECTOR(dev->backUpPhysicalDeviceObject, initialOffset);
            // memcpy(CRC_BUFFER + offset_in_sector, &CRC, sizeof(CRC));
            // SET_CRC_SECTOR(dev->backUpPhysicalDeviceObject, initialOffset);
        }
        return status;
    }
    status = SendIrp(major,
        dev->backUpPhysicalDeviceObject,
        dev->byteOffset,
        dev->buffer,
        dev->bufferSize);


    return status ;
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
    readBuffer = MmGetSystemAddressForMdlSafe ( irp->MdlAddress,
                 NormalPagePriority );
    RtlCopyMemory ( readBuffer, data->buffer, data->bufferSize );

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

    SendTestIrp ( data, IRP_MJ_WRITE );

    ExFreePoolWithTag ( data->buffer, '1gat' );
    data->bufferSize = 0;
    /* complete IRP */
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = sizeToWrite;
    IoCompleteRequest ( irp, IO_NO_INCREMENT );


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


    status = OpenPhysicalDisk ( PHYSICAL_DISK1_DEVICE_NAME,
                                PHYSICAL_DISK2_DEVICE_NAME,
                                data );
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


