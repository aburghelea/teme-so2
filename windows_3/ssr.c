/*
 * User: Alexandru George Burghelea
 * 342C5
 * SO2 2013
 * Tema 3
 */

#include <ntddk.h>
#include "ssr.h"
#include "crc32.h"

#define CRC_SIZE 4
#define SECTOR_SIZE        KERNEL_SECTOR_SIZE
#define SECTOR_MASK     (KERNEL_SECTOR_SIZE-1)
#define MTAG 'trss'

typedef struct _SSR_DE {
    PDEVICE_OBJECT deviceObject;

    PDEVICE_OBJECT mainPDO;
    PDEVICE_OBJECT backUpPDO;

    PFILE_OBJECT mainFileObject;
    PFILE_OBJECT backUpFileObject;

} SSR_DE, *PSSR_DE;

/* Wrappers for READ/WRITE for DATA/CRC over SendIrp */
#define GET_CRC_SECTOR(do, offset)  \
    SendIrp(IRP_MJ_READ,            \
            do,                     \
            offset,                 \
            crc_buff,               \
            SECTOR_SIZE);

#define SET_CRC_SECTOR(do, offset)  \
    SendIrp(IRP_MJ_WRITE,           \
            do,                     \
            offset,                 \
            crc_buff,               \
            SECTOR_SIZE);
#define GET_DATA_SECTOR(do, off, buff) \
    SendIrp(IRP_MJ_READ,               \
            do,                        \
            off,                       \
            buff,                      \
            SECTOR_SIZE);
#define SET_DATA_SECTOR(do, off, buff) \
    SendIrp(IRP_MJ_WRITE,              \
            do,                        \
            off,                       \
            buff,                      \
            SECTOR_SIZE);
#define SS(i) (i) * SECTOR_SIZE


/* Taken from test file */
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

/* Opens a physical disk (same as lab 05) */
static NTSTATUS OpenPhysicalDisk(PCWSTR diskName,
                                 PCWSTR backupName,
                                 PSSR_DE data)
{
    UNICODE_STRING diskDeviceName;
    UNICODE_STRING backupDeviceName;
    NTSTATUS mainStatus, backUpStatus;
    RtlInitUnicodeString(&diskDeviceName, diskName);
    RtlInitUnicodeString(&backupDeviceName, backupName);
    mainStatus = IoGetDeviceObjectPointer(
                     &diskDeviceName,
                     GENERIC_READ | GENERIC_WRITE,
                     &data->mainFileObject,
                     &data->mainPDO);

    backUpStatus = IoGetDeviceObjectPointer(
                       &backupDeviceName,
                       GENERIC_READ | GENERIC_WRITE,
                       &data->backUpFileObject,
                       &data->backUpPDO);
    return mainStatus && backUpStatus;
}

/* Closes a physical disk (same as lab 08) */
static void ClosePhysicalDisk(PSSR_DE data)
{
    ObDereferenceObject(data->mainFileObject);
    ObDereferenceObject(data->backUpFileObject);
    DbgPrint("[DriverUnload] DisksDeleting deleting");
}

/* Access to/from, disk. Data is always found in buffer param.
 * (same as lab 08)
 */
static NTSTATUS SendIrp(ULONG major, PDEVICE_OBJECT device,
                        LARGE_INTEGER offset, PVOID buffer,
                        ULONG size)
{
    PIRP irp = NULL;
    KEVENT irpEvent;
    NTSTATUS status = STATUS_SUCCESS;
    IO_STATUS_BLOCK ioStatus;

    KeInitializeEvent(
        &irpEvent,
        NotificationEvent,
        FALSE);

    irp = IoBuildSynchronousFsdRequest(
              major,
              device,
              buffer,
              size,
              &offset,
              &irpEvent,
              &ioStatus);
    if (irp == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        return status;
    }

    status = IoCallDriver(device, irp);

    KeWaitForSingleObject(
        &irpEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL);


    return ioStatus.Status;
}

/* Raid write operation */
static NTSTATUS RaidWrite(PSSR_DE data, PCHAR c_buff,
                          ULONG c_size, LARGE_INTEGER c_off)
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned char crc_buff[SECTOR_SIZE];

    LONGLONG crc_offset;
    LARGE_INTEGER crc_sector, anotherOffset;

    LONGLONG i = 0;

    unsigned int crc_read, crc_comp;
    LONGLONG sector_no;
    sector_no = c_off.QuadPart / SECTOR_SIZE;

    for (i = 0 ; i < c_size / SECTOR_SIZE; i ++) {
        /* Calculate offset and block containing the desired CRC */
        crc_sector.QuadPart = ssr_get_crc_sector(sector_no + i);
        crc_offset = ssr_get_crc_offset_in_sector(
                         sector_no + i
                     );
        crc_read = update_crc(0, c_buff + SS(i), SECTOR_SIZE);

        /* Fetch block from main */
        GET_CRC_SECTOR(data->mainPDO, crc_sector);
        /* Updata crc in block */
        memcpy(crc_buff + crc_offset, &crc_read, sizeof(crc_read));
        /* Push block to main disk */
        SET_CRC_SECTOR(data->mainPDO, crc_sector);

        /* Fetch block from backup */
        GET_CRC_SECTOR(data->backUpPDO, crc_sector);
        /* Updata crc in block */
        memcpy(crc_buff + crc_offset, &crc_read, sizeof(crc_read));
        /* Push block to backup disk */
        SET_CRC_SECTOR(data->backUpPDO, crc_sector);

        /* Push data blocks to both disks */
        SET_DATA_SECTOR(data->mainPDO, c_off, c_buff + SS(i));
        SET_DATA_SECTOR(data->backUpPDO, c_off, c_buff + SS(i));
        c_off.QuadPart += SECTOR_SIZE;
    }

    return status;
}

/* Update data from backup disk */
static NTSTATUS RecoverMain(PSSR_DE data, PCHAR c_buff,
                            ULONG c_size, LARGE_INTEGER c_off,
                            LONGLONG crc_offset, LARGE_INTEGER crc_sector,
                            unsigned int crc_read, LONGLONG i)
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned char crc_buff[SECTOR_SIZE];
    unsigned int crc_comp;

    /* Get backup data sector */
    status = GET_DATA_SECTOR(data->backUpPDO, c_off, c_buff + SS(i));
    if (!NT_SUCCESS(status))
        goto exit;

    crc_comp = update_crc(0, c_buff + SS(i), SECTOR_SIZE);
    /* Get backup CRC */
    GET_CRC_SECTOR(data->backUpPDO, crc_sector);

    if (crc_comp != crc_read) {
        DbgPrint("[RecoverMain] Both disks compromised");
        status = STATUS_DEVICE_DATA_ERROR;
        goto exit;
    }

    /* Update main data sector from backup disk */
    status = SET_DATA_SECTOR(data->mainPDO, c_off, c_buff + SS(i));
    if (!NT_SUCCESS(status))
        goto exit;

    RtlCopyMemory(crc_buff + crc_offset, &crc_read, sizeof(crc_read));
    /* Update main CRC sector from backup disk */
    SET_CRC_SECTOR(data->mainPDO, crc_sector);

exit:
    return status;
}

/* Recover backup disk from main disk, same logic as RecoverMain */
static NTSTATUS RecoverBackUp(PSSR_DE data, PCHAR c_buff,
                              ULONG c_size, LARGE_INTEGER c_off,
                              LONGLONG crc_offset, LARGE_INTEGER crc_sector,
                              unsigned int crc_read, LONGLONG i)
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned char crc_buff[SECTOR_SIZE], data_buff[SECTOR_SIZE];
    unsigned int crc_comp;

    status = GET_DATA_SECTOR(data->backUpPDO, c_off, data_buff);
    if (!NT_SUCCESS(status))
        goto exit;

    crc_comp = update_crc(0, data_buff, SECTOR_SIZE);
    GET_CRC_SECTOR(data->backUpPDO, crc_sector);
    memcpy(&crc_read, crc_buff + crc_offset, sizeof(crc_read));

    if (crc_comp != crc_read) {

        status = SET_DATA_SECTOR(data->backUpPDO, c_off, c_buff + SS(i));
        if (!NT_SUCCESS(status))
            goto exit;

        memcpy(crc_buff + crc_offset, &crc_read, sizeof(crc_read));
        GET_CRC_SECTOR(data->backUpPDO, crc_sector);
        DbgPrint("[RecoverMain] Sclav corupt");

    }

exit:
    return status;
}
/* Raid read operation (acts as real raid 1) */
static NTSTATUS RaidRead(PSSR_DE data, PCHAR c_buff,
                         ULONG c_size, LARGE_INTEGER c_off)
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned char data_buff[SECTOR_SIZE];
    unsigned char crc_buff[SECTOR_SIZE];
    LONGLONG crc_offset;
    LARGE_INTEGER crc_sector;
    LONGLONG i = 0;

    unsigned int crc_read, crc_comp;
    LONGLONG sector_no;
    sector_no = c_off.QuadPart / SECTOR_SIZE;


    for (i = 0 ; i < c_size / SECTOR_SIZE; i ++) {

        /* Read data sector from disk */
        status = GET_DATA_SECTOR(data->mainPDO, c_off, c_buff + SS(i));
        crc_sector.QuadPart = ssr_get_crc_sector(sector_no + i);
        crc_offset = ssr_get_crc_offset_in_sector(sector_no + i);


        crc_comp = update_crc(0, c_buff + SS(i), SECTOR_SIZE);

        /* Get the stored CRC for the data sector */
        GET_CRC_SECTOR(data->mainPDO, crc_sector);
        memcpy(&crc_read, crc_buff + crc_offset, sizeof(crc_read));

        /* Check if crs math */
        if (crc_comp != crc_read) {
            /* recover main disk sector from backup */
            status = RecoverMain(data, c_buff , c_size, c_off,
                                 crc_offset, crc_sector, crc_read, i);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[RaidRead] Could not recover main disk");
                goto exit;
            }
        } else {
            /* Test and recover backup if necessary */
            status = RecoverBackUp(data, c_buff , c_size, c_off,
                                   crc_offset, crc_sector, crc_read, i);

            if (!NT_SUCCESS(status)) {
                DbgPrint("[RaidRead] Could not recover backup disk");
                goto exit;
            }
        }
        c_off.QuadPart += SECTOR_SIZE;
    }

exit:
    return status;
}

/* Custom read over RAID device (same as lab 05) */
NTSTATUS SSRRead(PDEVICE_OBJECT device, IRP *irp)
{
    PSSR_DE data = (PSSR_DE) device->DeviceExtension;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    PIO_STACK_LOCATION pIrpStack;
    PCHAR readBuffer, c_buff;
    LARGE_INTEGER c_off;
    ULONG sizeToRead;

    /* retrieve buffer size from current stack location */
    pIrpStack = IoGetCurrentIrpStackLocation(irp);
    sizeToRead = pIrpStack->Parameters.Read.Length;

    c_off = pIrpStack->Parameters.Read.ByteOffset;
    if (c_off.QuadPart + sizeToRead > LOGICAL_DISK_SIZE) {
        sizeToRead = 0;
        goto exit;
    }
    c_buff = ExAllocatePoolWithTag(NonPagedPool, sizeToRead, MTAG);

    status = RaidRead(data, c_buff, sizeToRead, c_off);
    readBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                 NormalPagePriority);
    RtlCopyMemory(readBuffer, c_buff, sizeToRead);
    ExFreePoolWithTag(c_buff, MTAG);
    /* complete IRP */

exit:
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = sizeToRead;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/* Custom write over RAID device (same as lab 05) */
NTSTATUS SSRWrite(PDEVICE_OBJECT device, IRP *irp)
{
    PSSR_DE data = (PSSR_DE) device->DeviceExtension;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    PIO_STACK_LOCATION pIrpStack;
    PCHAR writeBuffer, c_buff;
    ULONG sizeToWrite;
    LARGE_INTEGER c_off;
    pIrpStack = IoGetCurrentIrpStackLocation(irp);
    sizeToWrite = pIrpStack->Parameters.Write.Length;


    c_off = pIrpStack->Parameters.Write.ByteOffset;
    c_buff = ExAllocatePoolWithTag(NonPagedPool, sizeToWrite, MTAG);
    if (c_off.QuadPart + sizeToWrite > LOGICAL_DISK_SIZE) {
        sizeToWrite = 0;
        goto exit;
    }
    writeBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                  NormalPagePriority);
    RtlCopyMemory(c_buff, writeBuffer, sizeToWrite);

    status = RaidWrite(data, c_buff, sizeToWrite, c_off);

    ExFreePoolWithTag(c_buff, MTAG);
    /* complete IRP */

exit:
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = sizeToWrite;
    IoCompleteRequest(irp, IO_NO_INCREMENT);


    return status;
}


/* Frees the memory and returns system to original state */
void DriverUnload(PDRIVER_OBJECT driver)
{

    DEVICE_OBJECT *device;
    UNICODE_STRING linkUnicodeName;
    RtlZeroMemory(&linkUnicodeName, sizeof(linkUnicodeName));
    RtlInitUnicodeString(&linkUnicodeName, LOGICAL_DISK_LINK_NAME);
    IoDeleteSymbolicLink(&linkUnicodeName);
    DbgPrint("[DriverUnload] SymbolicLink deleted");
    ClosePhysicalDisk(driver->DeviceObject->DeviceExtension);
    while (TRUE) {
        device = driver->DeviceObject;
        if (device == NULL)
            break;

        IoDeleteDevice(device);
        DbgPrint("[DriverUnload] Device deleting");
    }

    DbgPrint("[DriverUnload] Device deleted");
    return;
}

/* Driver Entry point , inits the Descriptor tables and spinlocks */
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    NTSTATUS status;
    UNICODE_STRING devUnicodeName, linkUnicodeName;
    DEVICE_OBJECT *device;
    PSSR_DE data;

    RtlZeroMemory(&devUnicodeName, sizeof(devUnicodeName));
    RtlZeroMemory(&linkUnicodeName, sizeof(linkUnicodeName));
    RtlInitUnicodeString(&devUnicodeName, LOGICAL_DISK_DEVICE_NAME);
    RtlInitUnicodeString(&linkUnicodeName, LOGICAL_DISK_LINK_NAME);


    status = IoCreateDevice(driver,
                            sizeof(SSR_DE),
                            &devUnicodeName,
                            FILE_DEVICE_DISK,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &device
                           );
    if (status != STATUS_SUCCESS) {
        goto error;
    }

    status = IoCreateSymbolicLink(&linkUnicodeName, &devUnicodeName);
    if (status != STATUS_SUCCESS)
        goto error;


    device->Flags |= DO_DIRECT_IO;

    data = (PSSR_DE) device->DeviceExtension;
    data->deviceObject = device;

    driver->DriverUnload = DriverUnload;
    driver->MajorFunction[ IRP_MJ_READ ] = SSRRead;
    driver->MajorFunction[ IRP_MJ_WRITE ] = SSRWrite;

    status = OpenPhysicalDisk(PHYSICAL_DISK1_DEVICE_NAME,
                              PHYSICAL_DISK2_DEVICE_NAME,
                              data);
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


