#include <ntddk.h>
#include <initguid.h>
#include <wdmguid.h>
#include <ntddvdeo.h>
#include <bcrypt.h>

#define PCI_VENDOR_INTEL   0x8086
#define PCI_CLASS_DISPLAY  0x03
#define ASLS_OFFSET        0xFC
#define OPREGION_SIG       "IntelGraphicsMem"
#define HASH_BYTES         0xFF

static NTSTATUS QueryBusInterface(PDEVICE_OBJECT devObj, PBUS_INTERFACE_STANDARD bus)
{
    KEVENT ev;
    IO_STATUS_BLOCK iosb = {0};
    KeInitializeEvent(&ev, NotificationEvent, FALSE);

    PIRP irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, devObj, NULL, 0, NULL, &ev, &iosb);
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;

    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    PIO_STACK_LOCATION s = IoGetNextIrpStackLocation(irp);
    s->MajorFunction = IRP_MJ_PNP;
    s->MinorFunction = IRP_MN_QUERY_INTERFACE;
    s->Parameters.QueryInterface.InterfaceType = &GUID_BUS_INTERFACE_STANDARD;
    s->Parameters.QueryInterface.Size = sizeof(*bus);
    s->Parameters.QueryInterface.Version = 1;
    s->Parameters.QueryInterface.Interface = reinterpret_cast<PINTERFACE>(bus);
    s->Parameters.QueryInterface.InterfaceSpecificData = NULL;

    NTSTATUS st = IoCallDriver(devObj, irp);
    if (st == STATUS_PENDING) {
        KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
        st = iosb.Status;
    }
    return st;
}

static NTSTATUS Sha1Two( PVOID data1, ULONG len1,
    PVOID data2, ULONG len2,
    UCHAR out[20] )
{
    BCRYPT_ALG_HANDLE  hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    NTSTATUS st = BCryptOpenAlgorithmProvider( &hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0 );
    if ( !NT_SUCCESS( st ) ) return st;

    st = BCryptCreateHash( hAlg, &hHash, NULL, 0, NULL, 0, 0 );
    if ( NT_SUCCESS( st ) )
    {
        st = BCryptHashData( hHash, static_cast<PUCHAR>(data1), len1, 0 );
        if ( NT_SUCCESS( st ) && data2 != NULL && len2 > 0 )
            st = BCryptHashData( hHash, static_cast<PUCHAR>(data2), len2, 0 );
        if ( NT_SUCCESS( st ) )
            st = BCryptFinishHash( hHash, out, 20, 0 );
        BCryptDestroyHash( hHash );
    }
    BCryptCloseAlgorithmProvider( hAlg, 0 );
    return st;
}

static VOID HashOpRegionAt(ULONG asls)
{
    PHYSICAL_ADDRESS pa; pa.QuadPart = asls;
    PUCHAR va = static_cast<PUCHAR>(MmMapIoSpaceEx(pa, 0x2000, PAGE_READONLY | PAGE_NOCACHE));
    if (!va) return;

    if (RtlCompareMemory(va, OPREGION_SIG, 16) != 16) {
        MmUnmapIoSpace(va, 0x2000);
        return;
    }

    ULONG     version = *reinterpret_cast<const ULONG*>    (va + 0x14);
    ULONGLONG rvda    = *reinterpret_cast<const ULONGLONG*>(va + 0x3BA);
    ULONG     rvds    = *reinterpret_cast<const ULONG*>    (va + 0x3C2);

    PUCHAR vbt   = NULL;
    SIZE_T vbtSz = 0;

    if (rvda != 0 && rvds != 0) {
        PHYSICAL_ADDRESS vbtPa;
        vbtPa.QuadPart = (version >= 0x00020001) ? (static_cast<ULONGLONG>(asls) + rvda) : rvda;
        vbtSz = rvds;

        vbt = static_cast<PUCHAR>(MmMapIoSpaceEx(vbtPa, vbtSz, PAGE_READONLY | PAGE_NOCACHE));
        if (vbt && RtlCompareMemory(vbt, "$VBT", 4) != 4) {
            MmUnmapIoSpace(vbt, vbtSz);
            vbt = NULL;
            vbtSz = 0;
        }
    }

    UCHAR    hash[20] = {0};
    NTSTATUS st = Sha1Two(va, 0x100, vbt, static_cast<ULONG>(vbtSz), hash);

    if (vbt) MmUnmapIoSpace(vbt, vbtSz);
    MmUnmapIoSpace(va, 0x2000);

    if (!NT_SUCCESS(st)) return;

    static const CHAR H[] = "0123456789abcdef";
    CHAR hex[41] = {0};
    for (ULONG i = 0; i < 20; i++) {
        hex[i * 2]     = H[hash[i] >> 4];
        hex[i * 2 + 1] = H[hash[i] & 0xF];
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "IntelOpRegionFingerprint: SHA1=%s\n", hex);
}

static VOID HandleAdapter(PUNICODE_STRING linkName)
{
    PFILE_OBJECT   fileObj = NULL;
    PDEVICE_OBJECT devObj  = NULL;
    if (!NT_SUCCESS(IoGetDeviceObjectPointer(linkName, FILE_READ_ACCESS, &fileObj, &devObj)))
        return;

    BUS_INTERFACE_STANDARD bus = {0};
    if (!NT_SUCCESS(QueryBusInterface(devObj, &bus))) {
        ObDereferenceObject(fileObj);
        return;
    }

    struct {
        USHORT VendorID, DeviceID, Command, Status;
        UCHAR  RevisionID, ProgIf, SubClass, BaseClass;
    } hdr = {0};

    ULONG got = bus.GetBusData(bus.Context, PCI_WHICHSPACE_CONFIG, &hdr, 0, sizeof(hdr));
    if (got == sizeof(hdr) &&
        hdr.VendorID  == PCI_VENDOR_INTEL &&
        hdr.BaseClass == PCI_CLASS_DISPLAY)
    {
        ULONG asls = 0;
        got = bus.GetBusData(bus.Context, PCI_WHICHSPACE_CONFIG, &asls, ASLS_OFFSET, sizeof(asls));
        if (got == sizeof(asls) && asls != 0)
            HashOpRegionAt(asls);
    }

    bus.InterfaceDereference(bus.Context);
    ObDereferenceObject(fileObj);
}

extern "C" DRIVER_UNLOAD     DriverUnload;
extern "C" DRIVER_INITIALIZE DriverEntry;

_Use_decl_annotations_
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DbgPrint( "LOADED\n" );
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    PWSTR list = NULL;
    NTSTATUS st = IoGetDeviceInterfaces(&GUID_DEVINTERFACE_DISPLAY_ADAPTER, NULL, 0, &list);
    if (!NT_SUCCESS(st) || !list)
        return STATUS_SUCCESS;

    for (PWSTR p = list; *p; ) {
        UNICODE_STRING u;
        RtlInitUnicodeString(&u, p);
        HandleAdapter(&u);
        p += (u.Length / sizeof(WCHAR)) + 1;
    }
    ExFreePool(list);
    return STATUS_SUCCESS;
}
