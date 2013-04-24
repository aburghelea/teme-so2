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

    // ULONG bufferSize;
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


static NTSTATUS DelegateIrp ( SSR_DEVICE_DATA *data, ULONG major, PCHAR contentBuffer, ULONG contentSize )
{

    NTSTATUS status = STATUS_SUCCESS;
    unsigned char data_buffer[SECTOR_SIZE];
    unsigned char CRC_BUFFER[SECTOR_SIZE];

    LONGLONG offset_in_sector;
    LARGE_INTEGER initialOffset, anotherOffset;

    LONGLONG i = 0;

    unsigned int CRC,CRC_2, CRC_CALC;
    LONGLONG sector_disk_offset;
    sector_disk_offset = data->byteOffset.QuadPart / SECTOR_SIZE;


    if (major == IRP_MJ_WRITE) {
        for (i = 0 ; i < contentSize; i+= SECTOR_SIZE){
            initialOffset.QuadPart=ssr_get_crc_sector(sector_disk_offset + i / SECTOR_SIZE);
            offset_in_sector = ssr_get_crc_offset_in_sector(
                        sector_disk_offset + i / SECTOR_SIZE
                        );

            RtlCopyMemory(data_buffer, contentBuffer + i, SECTOR_SIZE);
            CRC = update_crc(0, data_buffer, SECTOR_SIZE);

            // Update main crc============
            GET_CRC_SECTOR(data->mainPhysicalDeviceObject, initialOffset);
            memcpy(CRC_BUFFER + offset_in_sector, &CRC, sizeof(CRC));
            SET_CRC_SECTOR(data->mainPhysicalDeviceObject, initialOffset);

            // Update backup CRC
            GET_CRC_SECTOR(data->backUpPhysicalDeviceObject, initialOffset);
            memcpy(CRC_BUFFER + offset_in_sector, &CRC, sizeof(CRC));
            SET_CRC_SECTOR(data->backUpPhysicalDeviceObject, initialOffset);
        }
    }

    status = SendIrp(major,
        data->mainPhysicalDeviceObject,
        data->byteOffset,
        contentBuffer,
        contentSize);
    if (major == IRP_MJ_READ) {
        for (i = 0 ; i < contentSize; i+= SECTOR_SIZE){
            initialOffset.QuadPart=ssr_get_crc_sector(sector_disk_offset + i / SECTOR_SIZE);
            offset_in_sector = ssr_get_crc_offset_in_sector(
                        sector_disk_offset + i / SECTOR_SIZE
                        );

            RtlCopyMemory(data_buffer, contentBuffer + i, SECTOR_SIZE);
            CRC_CALC = update_crc(0, data_buffer, SECTOR_SIZE);

            // Update main crc============
            GET_CRC_SECTOR(data->mainPhysicalDeviceObject, initialOffset);
            memcpy(&CRC, CRC_BUFFER + offset_in_sector, sizeof(CRC));
            anotherOffset.QuadPart = data->byteOffset.QuadPart + i;
            if (CRC != CRC_CALC){

                status = SendIrp(major,
                                data->backUpPhysicalDeviceObject,
                                anotherOffset,
                                data_buffer,
                                SECTOR_SIZE);
                CRC_CALC = update_crc(0, data_buffer, SECTOR_SIZE);
                GET_CRC_SECTOR(data->backUpPhysicalDeviceObject, initialOffset);
                RtlCopyMemory( contentBuffer + i, data_buffer,SECTOR_SIZE);
                if (CRC_CALC != CRC) {
                    DbgPrint("Gresit pe ambele discuri");
                    return STATUS_DEVICE_DATA_ERROR;
                }
                status = SendIrp(IRP_MJ_WRITE,
                                data->mainPhysicalDeviceObject,
                                anotherOffset,
                                data_buffer,
                                SECTOR_SIZE);
                memcpy(CRC_BUFFER + offset_in_sector, &CRC, sizeof(CRC));
                SET_CRC_SECTOR(data->mainPhysicalDeviceObject, initialOffset);
            } else {
                status = SendIrp(IRP_MJ_READ,
                                data->backUpPhysicalDeviceObject,
                                anotherOffset,
                                data_buffer,
                                SECTOR_SIZE);
                CRC_CALC = update_crc(0, data_buffer, SECTOR_SIZE);
                GET_CRC_SECTOR(data->backUpPhysicalDeviceObject, initialOffset);
                memcpy(&CRC_2, CRC_BUFFER + offset_in_sector, sizeof(CRC));
                if (CRC_CALC != CRC_2) {
                    RtlCopyMemory(data_buffer, contentBuffer + i, SECTOR_SIZE);
                    status = SendIrp(IRP_MJ_WRITE,
                            data->backUpPhysicalDeviceObject,
                            anotherOffset,
                            data_buffer,
                            SECTOR_SIZE);
                    memcpy(CRC_BUFFER + offset_in_sector,&CRC_2, sizeof(CRC));
                    GET_CRC_SECTOR(data->backUpPhysicalDeviceObject, initialOffset);
                    DbgPrint("Sclav corupt");

                }
            }
        }
        return status;
    }
    status = SendIrp(major,
        data->backUpPhysicalDeviceObject,
        data->byteOffset,
        contentBuffer,
        contentSize);


    return status ;
}

NTSTATUS SSRRead ( PDEVICE_OBJECT device, IRP *irp )
{
    SSR_DEVICE_DATA *data =
        ( SSR_DEVICE_DATA * ) device->DeviceExtension;
    PIO_STACK_LOCATION pIrpStack;
    PCHAR readBuffer, contentBuffer;
    ULONG sizeToRead;

    /* retrieve buffer size from current stack location */
    pIrpStack = IoGetCurrentIrpStackLocation ( irp );
    sizeToRead = pIrpStack->Parameters.Read.Length;

    data->byteOffset = pIrpStack->Parameters.Read.ByteOffset;
    if (data->byteOffset.QuadPart + sizeToRead > LOGICAL_DISK_SIZE) {
        sizeToRead = 0;
        goto exit;
    }
    contentBuffer = ExAllocatePoolWithTag ( NonPagedPool, sizeToRead, '1gat' );

    DelegateIrp ( data, IRP_MJ_READ, contentBuffer, sizeToRead );
    readBuffer = MmGetSystemAddressForMdlSafe ( irp->MdlAddress,
                 NormalPagePriority );
    RtlCopyMemory ( readBuffer, contentBuffer, sizeToRead);
    ExFreePoolWithTag ( contentBuffer, '1gat' );
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
    PCHAR writeBuffer, contentBuffer;
    ULONG sizeToWrite;
    pIrpStack = IoGetCurrentIrpStackLocation ( irp );
    sizeToWrite = pIrpStack->Parameters.Write.Length;

    data->byteOffset = pIrpStack->Parameters.Write.ByteOffset;
    contentBuffer = ExAllocatePoolWithTag ( NonPagedPool, sizeToWrite, '1gat' );
    if (data->byteOffset.QuadPart + sizeToWrite > LOGICAL_DISK_SIZE) {
        sizeToWrite = 0;
        goto exit;
    }
    writeBuffer = MmGetSystemAddressForMdlSafe ( irp->MdlAddress,
                  NormalPagePriority );
    RtlCopyMemory (contentBuffer, writeBuffer, sizeToWrite );

    DelegateIrp ( data, IRP_MJ_WRITE, contentBuffer,sizeToWrite );

    ExFreePoolWithTag ( contentBuffer, '1gat' );
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
    driver->MajorFunction[ IRP_MJ_READ ] = SSRRead;
    driver->MajorFunction[ IRP_MJ_WRITE ] = SSRWrite;

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


