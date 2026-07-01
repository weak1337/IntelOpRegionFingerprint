# IntelOpRegionFingerprint

Small WDM kernel driver that produces a stable hardware fingerprint from the Intel
integrated graphics ACPI OpRegion.

## What it does

On load, the driver enumerates every registered display adapter interface
(`GUID_DEVINTERFACE_DISPLAY_ADAPTER`) and filters for Intel iGPUs
(`VID=0x8086`, PCI class `0x03`). For each match it reads the **ASLS** register
at PCI config offset `0xFC`. That register is the *ACPI OpRegion Base Address*
defined in Intel's IGD OpRegion spec; it holds the physical address of a memory
block the BIOS built for the graphics driver, containing platform data,
mailboxes, and (on modern platforms) a pointer to the extended VBT.

From there:

1. Map the OpRegion with `MmMapIoSpaceEx`.
2. Verify the `IntelGraphicsMem` signature at offset 0.
3. Read the header version and the ASLE `RVDA` / `RVDS` fields (extended-VBT
   pointer and size).
4. If RVDA/RVDS are populated, map that region too and check for the `$VBT`
   magic.
5. SHA-1 the concatenation of the first 0x100 bytes of the OpRegion header and
   the extended VBT.
6. Emit the digest via `DbgPrintEx`.

The runtime-mutable mailboxes are deliberately skipped so the hash stays stable
across boots. What ends up in the hash is:

- the OpRegion header, which is baked per platform + firmware + graphics driver
  version, and
- the VBT, which is baked into the system firmware and encodes panel/display
  topology.

Together those give a per-machine ID that survives reboots but differs across
hardware, which is what you want out of a fingerprint.

Output shows up in DbgView (Capture Kernel on, filter `IHVDRIVER`):

```
IntelOpRegionFingerprint: SHA1=<40 hex chars>
```
