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
#define MTAG 'trss'

typedef struct _SSR_DEVICE_DATA
{
    PDEVICE_OBJECT deviceObject;

    PDEVICE_OBJECT mainPhysicalDeviceObject;
    PDEVICE_OBJECT backUpPhysicalDeviceObject;

    PFILE_OBJECT mainFileObject;
    PFILE_OBJECT backUpFileObject;

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

static NTSTATUS OpenPhysicalDisk ( PCWSTR diskName,
                                   PCWSTR backupName,
                                   SSR_DEVICE_DATA *data )
{
    UNICODE_STRING diskDeviceName;
    UNICODE_STRING backupDeviceName;
    NTSTATUS mainStatus, backUpStatus;
    RtlInitUnicodeString ( &diskDeviceName, diskName );
    RtlInitUnicodeString ( &backupDeviceName, backupName );
    mainStatus = IoGetDeviceObjectPointer (
                     &diskDeviceName,
                     GENERIC_READ | GENERIC_WRITE,
                     &data->mainFileObject,
                     &data->mainPhysicalDeviceObject );

    backUpStatus = IoGetDeviceObjectPointer (
                       &backupDeviceName,
                       GENERIC_READ | GENERIC_WRITE,
                       &data->backUpFileObject,
                       &data->backUpPhysicalDeviceObject );
    return mainStatus && backUpStatus;
}

static void ClosePhysicalDisk ( SSR_DEVICE_DATA *data )
{
    ObDereferenceObject ( data->mainFileObject );
    ObDereferenceObject ( data->backUpFileObject );
    DbgPrint ( "[DriverUnload] DisksDeleting deleting" );
}

#define GET_CRC_SECTOR(do, offset)  \
    SendIrp(IRP_MJ_READ,            \
            do,                     \
            offset,                 \
            CRC_BUFFER,             \
            SECTOR_SIZE);

#define SET_CRC_SECTOR(do, offset)  \
    SendIrp(IRP_MJ_WRITE,           \
            do,                     \
            offset,                 \
            CRC_BUFFER,             \
            SECTOR_SIZE);
#define GET_DATA_SECTOR(do, off, buff) \
        SendIrp(IRP_MJ_READ,           \
            do,                         \
            off,                        \
            buff,                        \
            SECTOR_SIZE);
#define SET_DATA_SECTOR(do, off, buff) \
        SendIrp(IRP_MJ_WRITE,           \
            do,                         \
            off,                        \
            buff,                        \
            SECTOR_SIZE);
#define SS(i) (i) * SECTOR_SIZE

static NTSTATUS SendIrp (ULONG major, PDEVICE_OBJECT device,
                         LARGE_INTEGER offset, PVOID buffer,
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
    if ( irp == NULL )
    {
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

static NTSTATUS DelegateWriteIrp(SSR_DEVICE_DATA *data, PCHAR c_buff,
                                 ULONG c_size, LARGE_INTEGER c_off)
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned char CRC_BUFFER[SECTOR_SIZE];

    LONGLONG crc_offset;
    LARGE_INTEGER crc_sector, anotherOffset;

    LONGLONG i = 0;

    unsigned int crc_read, crc_comp;
    LONGLONG sector_disk_offset;
    sector_disk_offset = c_off.QuadPart / SECTOR_SIZE;

    for (i = 0 ; i < c_size/SECTOR_SIZE; i ++)
    {
        crc_sector.QuadPart = ssr_get_crc_sector(sector_disk_offset + i);
        crc_offset = ssr_get_crc_offset_in_sector(
                               sector_disk_offset + i
                           );
        crc_read = update_crc(0, c_buff + SS(i), SECTOR_SIZE);


        GET_CRC_SECTOR(data->mainPhysicalDeviceObject, crc_sector);
        memcpy(CRC_BUFFER + crc_offset, &crc_read, sizeof(crc_read));
        SET_CRC_SECTOR(data->mainPhysicalDeviceObject, crc_sector);

        GET_CRC_SECTOR(data->backUpPhysicalDeviceObject, crc_sector);
        memcpy(CRC_BUFFER + crc_offset, &crc_read, sizeof(crc_read));
        SET_CRC_SECTOR(data->backUpPhysicalDeviceObject, crc_sector);

        SET_DATA_SECTOR(data->mainPhysicalDeviceObject,c_off, c_buff + SS(i));
        SET_DATA_SECTOR(data->backUpPhysicalDeviceObject,c_off, c_buff + SS(i) );
        c_off.QuadPart += SECTOR_SIZE;
    }


    return status;
}

static NTSTATUS DelegateReadIrp ( SSR_DEVICE_DATA *data, PCHAR c_buff,
                                  ULONG c_size, LARGE_INTEGER c_off )
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned char data_buffer[SECTOR_SIZE];
    unsigned char CRC_BUFFER[SECTOR_SIZE];

    LONGLONG crc_offset;
    LARGE_INTEGER crc_sector, anotherOffset;

    LONGLONG i = 0;

    unsigned int crc_read, CRC_2, crc_comp;
    LONGLONG sector_disk_offset;
    sector_disk_offset = c_off.QuadPart / SECTOR_SIZE;



    status = SendIrp(IRP_MJ_READ,
                     data->mainPhysicalDeviceObject,
                     c_off,
                     c_buff,
                     c_size);
    for (i = 0 ; i < c_size; i += SECTOR_SIZE)
    {
        crc_sector.QuadPart = ssr_get_crc_sector(sector_disk_offset + i / SECTOR_SIZE);
        crc_offset = ssr_get_crc_offset_in_sector(
                               sector_disk_offset + i / SECTOR_SIZE
                           );

        RtlCopyMemory(data_buffer, c_buff + i, SECTOR_SIZE);
        crc_comp = update_crc(0, data_buffer, SECTOR_SIZE);

        // Update main crc============
        GET_CRC_SECTOR(data->mainPhysicalDeviceObject, crc_sector);
        memcpy(&crc_read, CRC_BUFFER + crc_offset, sizeof(crc_read));
        anotherOffset.QuadPart = c_off.QuadPart + i;
        if (crc_read != crc_comp)
        {

            status = SendIrp(IRP_MJ_READ,
                             data->backUpPhysicalDeviceObject,
                             anotherOffset,
                             data_buffer,
                             SECTOR_SIZE);
            crc_comp = update_crc(0, data_buffer, SECTOR_SIZE);
            GET_CRC_SECTOR(data->backUpPhysicalDeviceObject, crc_sector);
            RtlCopyMemory( c_buff + i, data_buffer, SECTOR_SIZE);
            if (crc_comp != crc_read)
            {
                DbgPrint("Gresit pe ambele discuri");
                return STATUS_DEVICE_DATA_ERROR;
            }
            status = SendIrp(IRP_MJ_WRITE,
                             data->mainPhysicalDeviceObject,
                             anotherOffset,
                             data_buffer,
                             SECTOR_SIZE);
            memcpy(CRC_BUFFER + crc_offset, &crc_read, sizeof(crc_read));
            SET_CRC_SECTOR(data->mainPhysicalDeviceObject, crc_sector);
        }
        else
        {
            status = SendIrp(IRP_MJ_READ,
                             data->backUpPhysicalDeviceObject,
                             anotherOffset,
                             data_buffer,
                             SECTOR_SIZE);
            crc_comp = update_crc(0, data_buffer, SECTOR_SIZE);
            GET_CRC_SECTOR(data->backUpPhysicalDeviceObject, crc_sector);
            memcpy(&CRC_2, CRC_BUFFER + crc_offset, sizeof(crc_read));
            if (crc_comp != CRC_2)
            {
                RtlCopyMemory(data_buffer, c_buff + i, SECTOR_SIZE);
                status = SendIrp(IRP_MJ_WRITE,
                                 data->backUpPhysicalDeviceObject,
                                 anotherOffset,
                                 data_buffer,
                                 SECTOR_SIZE);
                memcpy(CRC_BUFFER + crc_offset, &CRC_2, sizeof(crc_read));
                GET_CRC_SECTOR(data->backUpPhysicalDeviceObject, crc_sector);
                DbgPrint("Sclav corupt");

            }
        }
    }

    return status;
}

NTSTATUS SSRRead ( PDEVICE_OBJECT device, IRP *irp )
{
    SSR_DEVICE_DATA *data =
        ( SSR_DEVICE_DATA * ) device->DeviceExtension;
    PIO_STACK_LOCATION pIrpStack;
    PCHAR readBuffer, c_buff;
    LARGE_INTEGER c_off;
    ULONG sizeToRead;

    /* retrieve buffer size from current stack location */
    pIrpStack = IoGetCurrentIrpStackLocation ( irp );
    sizeToRead = pIrpStack->Parameters.Read.Length;

    c_off = pIrpStack->Parameters.Read.ByteOffset;
    if (c_off.QuadPart + sizeToRead > LOGICAL_DISK_SIZE)
    {
        sizeToRead = 0;
        goto exit;
    }
    c_buff = ExAllocatePoolWithTag ( NonPagedPool, sizeToRead, MTAG );

    DelegateReadIrp ( data, c_buff, sizeToRead, c_off);
    readBuffer = MmGetSystemAddressForMdlSafe ( irp->MdlAddress,
                 NormalPagePriority );
    RtlCopyMemory ( readBuffer, c_buff, sizeToRead);
    ExFreePoolWithTag ( c_buff, MTAG );
    /* complete IRP */
exit:
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = sizeToRead;
    IoCompleteRequest ( irp, IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}


NTSTATUS SSRWrite ( PDEVICE_OBJECT device, IRP *irp )
{
    SSR_DEVICE_DATA *data =
        ( SSR_DEVICE_DATA * ) device->DeviceExtension;
    PIO_STACK_LOCATION pIrpStack;
    PCHAR writeBuffer, c_buff;
    ULONG sizeToWrite;
    LARGE_INTEGER c_off;
    pIrpStack = IoGetCurrentIrpStackLocation ( irp );
    sizeToWrite = pIrpStack->Parameters.Write.Length;

    c_off = pIrpStack->Parameters.Write.ByteOffset;
    c_buff = ExAllocatePoolWithTag ( NonPagedPool, sizeToWrite, MTAG );
    if (c_off.QuadPart + sizeToWrite > LOGICAL_DISK_SIZE)
    {
        sizeToWrite = 0;
        goto exit;
    }
    writeBuffer = MmGetSystemAddressForMdlSafe ( irp->MdlAddress,
                  NormalPagePriority );
    RtlCopyMemory (c_buff, writeBuffer, sizeToWrite );

    DelegateWriteIrp ( data, c_buff, sizeToWrite, c_off);

    ExFreePoolWithTag ( c_buff, MTAG );
    /* complete IRP */

exit:
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
    while ( TRUE )
    {
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
    if ( status != STATUS_SUCCESS )
    {
        goto error;
    }

    status = IoCreateSymbolicLink ( &linkUnicodeName, &devUnicodeName );
    if ( status != STATUS_SUCCESS )
        goto error;


    device->Flags |= DO_DIRECT_IO;

    data = ( SSR_DEVICE_DATA * ) device->DeviceExtension;
    data->deviceObject = device;

    driver->DriverUnload = DriverUnload;
    driver->MajorFunction[ IRP_MJ_READ ] = SSRRead;
    driver->MajorFunction[ IRP_MJ_WRITE ] = SSRWrite;

    status = OpenPhysicalDisk ( PHYSICAL_DISK1_DEVICE_NAME,
                                PHYSICAL_DISK2_DEVICE_NAME,
                                data );
    if ( status != STATUS_SUCCESS )
    {
        DbgPrint ( "[DriverEntry] Error opening physical disk\n" );
        goto error;
    }


    DbgPrint ( "[DriverEntry] Loaded successfully" );
    return STATUS_SUCCESS;

error:
    DbgPrint ( "[DriverEntry] Force kill" );

    return status;
}


