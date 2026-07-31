// Copyright 2025 Google LLC.
//
// SPDX-License-Identifier: Apache-2.0
//

/// Cloud Hypervisor implementation of QEMU's fw_cfg spec
/// https://www.qemu.org/docs/master/specs/fw_cfg.html
/// Linux kernel fw_cfg driver header
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/qemu_fw_cfg.h
/// Uploading files to the guest via fw_cfg is supported for all kernels 4.6+ w/ CONFIG_FW_CFG_SYSFS enabled
/// https://cateee.net/lkddb/web-lkddb/FW_CFG_SYSFS.html
/// No kernel requirement if above functionality is not required,
/// only firmware must implement mechanism to interact with this fw_cfg device
#[cfg(all(feature = "fw_cfg", target_arch = "aarch64"))]
compile_error!(
    "fw_cfg is not supported on aarch64: the MMIO transport is incomplete and defective."
);

use std::{
    fs::File,
    io::{ErrorKind, Read, Result, Seek, SeekFrom},
    mem::offset_of,
    os::unix::fs::FileExt,
    sync::{Arc, Barrier},
};

use acpi_tables::rsdp::Rsdp;
use arch::RegionType;
#[cfg(target_arch = "aarch64")]
use arch::aarch64::layout::{
    MEM_32BIT_DEVICES_START, MEM_32BIT_RESERVED_START, RAM_64BIT_START, RAM_START as HIGH_RAM_START,
};
#[cfg(target_arch = "x86_64")]
use arch::layout::{
    EBDA_START, HIGH_RAM_START, MEM_32BIT_DEVICES_SIZE, MEM_32BIT_DEVICES_START,
    MEM_32BIT_RESERVED_START, PCI_MMCONFIG_SIZE, PCI_MMCONFIG_START, RAM_64BIT_START,
};
use bitfield_struct::bitfield;
#[cfg(target_arch = "x86_64")]
use linux_loader::bootparam::boot_params;
#[cfg(target_arch = "aarch64")]
use linux_loader::loader::pe::arm64_image_header as boot_params;
use log::{debug, error};
use thiserror::Error;
use vm_device::BusDevice;
use vm_memory::{Address, bitmap::AtomicBitmap};
use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap,
};
use vmm_sys_util::sock_ctrl_msg::IntoIovec;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[cfg(target_arch = "x86_64")]
// https://github.com/project-oak/oak/tree/main/stage0_bin#memory-layout
const STAGE0_START_ADDRESS: GuestAddress = GuestAddress(0xfffe_0000);
#[cfg(target_arch = "x86_64")]
const STAGE0_SIZE: usize = 0x2_0000;
const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_SELECTOR: u64 = 0x510;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DATA: u64 = 0x511;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DMA_HI: u64 = 0x514;
#[cfg(target_arch = "x86_64")]
const PORT_FW_CFG_DMA_LO: u64 = 0x518;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_BASE: u64 = 0x510;
#[cfg(target_arch = "x86_64")]
pub const PORT_FW_CFG_WIDTH: u64 = 0xc;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_SELECTOR: u64 = 0x9030008;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DATA: u64 = 0x9030000;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DMA_HI: u64 = 0x9030010;
#[cfg(target_arch = "aarch64")]
const PORT_FW_CFG_DMA_LO: u64 = 0x9030014;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_BASE: u64 = 0x9030000;
#[cfg(target_arch = "aarch64")]
pub const PORT_FW_CFG_WIDTH: u64 = 0x10;

const FW_CFG_SIGNATURE: u16 = 0x00;
const FW_CFG_ID: u16 = 0x01;
const FW_CFG_KERNEL_SIZE: u16 = 0x08;
const FW_CFG_INITRD_SIZE: u16 = 0x0b;
const FW_CFG_KERNEL_DATA: u16 = 0x11;
const FW_CFG_INITRD_DATA: u16 = 0x12;
const FW_CFG_CMDLINE_SIZE: u16 = 0x14;
const FW_CFG_CMDLINE_DATA: u16 = 0x15;
const FW_CFG_SETUP_SIZE: u16 = 0x17;
const FW_CFG_SETUP_DATA: u16 = 0x18;
const FW_CFG_FILE_DIR: u16 = 0x19;
const FW_CFG_KNOWN_ITEMS: usize = 0x20;

pub const FW_CFG_FILE_FIRST: u16 = 0x20;
pub const FW_CFG_DMA_SIGNATURE_CONTENT: [u8; 8] = *b"QEMU CFG";
pub const FW_CFG_SIGNATURE_CONTENT: [u8; 4] = *b"QEMU";
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/qemu_fw_cfg.h
pub const FW_CFG_ACPI_ID: &str = "QEMU0002";
// Reserved (must be enabled)
const FW_CFG_F_RESERVED: u8 = 1 << 0;
// DMA Toggle Bit (enabled by default)
const FW_CFG_F_DMA: u8 = 1 << 1;
pub const FW_CFG_FEATURE: [u8; 4] = [FW_CFG_F_RESERVED | FW_CFG_F_DMA, 0, 0, 0];

const COMMAND_ALLOCATE: u32 = 0x1;
const COMMAND_ADD_POINTER: u32 = 0x2;
const COMMAND_ADD_CHECKSUM: u32 = 0x3;

const ALLOC_ZONE_HIGH: u8 = 0x1;
const ALLOC_ZONE_FSEG: u8 = 0x2;

const FW_CFG_FILENAME_TABLE_LOADER: &str = "etc/table-loader";
const FW_CFG_FILENAME_RSDP: &str = "acpi/rsdp";
const FW_CFG_FILENAME_ACPI_TABLES: &str = "acpi/tables";

#[derive(Debug)]
pub enum FwCfgContent {
    Bytes(Vec<u8>),
    Slice(&'static [u8]),
    File(u64, File),
    U32(u32),
}

struct FwCfgContentAccess<'a> {
    content: &'a FwCfgContent,
    offset: u32,
}

impl Read for FwCfgContentAccess<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.content {
            FwCfgContent::File(offset, f) => {
                Seek::seek(&mut (&*f), SeekFrom::Start(offset + self.offset as u64))?;
                Read::read(&mut (&*f), buf)
            }
            FwCfgContent::Bytes(b) => match b.get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::Slice(b) => match b.get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
            FwCfgContent::U32(n) => match n.to_le_bytes().get(self.offset as usize..) {
                Some(mut s) => s.read(buf),
                None => Err(ErrorKind::UnexpectedEof)?,
            },
        }
    }
}

impl Default for FwCfgContent {
    fn default() -> Self {
        FwCfgContent::Slice(&[])
    }
}

impl FwCfgContent {
    fn size(&self) -> Result<u32> {
        let ret = match self {
            FwCfgContent::Bytes(v) => v.len(),
            FwCfgContent::File(offset, f) => (f.metadata()?.len() - offset) as usize,
            FwCfgContent::Slice(s) => s.len(),
            FwCfgContent::U32(n) => size_of_val(n),
        };
        u32::try_from(ret).map_err(|_| std::io::ErrorKind::InvalidInput.into())
    }
    fn access(&self, offset: u32) -> FwCfgContentAccess<'_> {
        FwCfgContentAccess {
            content: self,
            offset,
        }
    }
}

#[derive(Debug, Default)]
pub struct FwCfgItem {
    pub name: String,
    pub content: FwCfgContent,
}

/// https://www.qemu.org/docs/master/specs/fw_cfg.html
#[derive(Debug)]
pub struct FwCfg {
    selector: u16,
    data_offset: u32,
    dma_address: u64,
    items: Vec<FwCfgItem>,                           // 0x20 and above
    known_items: [FwCfgContent; FW_CFG_KNOWN_ITEMS], // 0x0 to 0x19
    memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>,
}

/// Representation of the FWCfgDmaAccess struct of QEMU with adapter functions.
///
/// The QEMU documentation defines the structure as follows:
/// ```C
/// typedef struct FWCfgDmaAccess {
///    uint32_t control;
///    uint32_t length;
///    uint64_t address;
/// } FWCfgDmaAccess;
/// ```
/// Each field of the structure is in big-endian format and control field is at the lowest address.
///
/// Our implementation uses the functions `from_be_bytes` and `to_be_bytes` for explicit conversion
/// from/to BE wire format so we can work with each field without individual conversion to native
/// endianness.
#[derive(Debug, Default)]
struct FwCfgDmaAccess {
    control: AccessControl,
    length: u32,
    address: u64,
}

impl FwCfgDmaAccess {
    // Wire size of the QEMU structure
    const WIRE_SIZE: usize = 16;

    /// Used to create a [`FwCfgDmaAccess`] from a bytes array containing data in big-endian format.
    fn from_be_bytes(bytes: &[u8; FwCfgDmaAccess::WIRE_SIZE]) -> Self {
        Self {
            control: AccessControl(u32::from_be_bytes(bytes[0..4].try_into().expect(
                "conversion of 4 random bytes should work and input is statically `[u8; 16]`",
            ))),
            length: u32::from_be_bytes(bytes[4..8].try_into().expect(
                "conversion of 4 random bytes should work and input is statically `[u8; 16]`",
            )),
            address: u64::from_be_bytes(bytes[8..16].try_into().expect(
                "conversion of 8 random bytes should work and input is statically `[u8; 16]`",
            )),
        }
    }

    /// Used to create a bytes array from [`FwCfgDmaAccess`]. Each field is transformed to BE
    /// representation.
    #[cfg(test)]
    fn to_be_bytes(&self) -> [u8; FwCfgDmaAccess::WIRE_SIZE] {
        let mut result = [0_u8; FwCfgDmaAccess::WIRE_SIZE];
        result[0..4].copy_from_slice(&self.control.0.to_be_bytes());
        result[4..8].copy_from_slice(&self.length.to_be_bytes());
        result[8..16].copy_from_slice(&self.address.to_be_bytes());
        result
    }
}

/// DMA access control bits
///
/// QEMU defines them as follows
/// ```C
/// #define FW_CFG_DMA_CTL_ERROR   0x01
/// #define FW_CFG_DMA_CTL_READ    0x02
/// #define FW_CFG_DMA_CTL_SKIP    0x04
/// #define FW_CFG_DMA_CTL_SELECT  0x08
/// #define FW_CFG_DMA_CTL_WRITE   0x10
/// ```
/// Sources:
/// https://github.com/torvalds/linux/blob/master/include/uapi/linux/qemu_fw_cfg.h#L67
/// https://github.com/qemu/qemu/blob/6e9a825c1d4e7b62d072e99a89ecd1a74c7f0d55/hw/nvram/fw_cfg.c#L52
#[bitfield(u32)]
struct AccessControl {
    // FW_CFG_DMA_CTL_ERROR = 0x01
    error: bool,
    // FW_CFG_DMA_CTL_READ = 0x02
    read: bool,
    // FW_CFG_DMA_CTL_SKIP = 0x04
    skip: bool,
    // FW_CFG_DMA_CTL_SELECT = 0x08
    select: bool,
    // FW_CFG_DMA_CTL_WRITE = 0x10
    write: bool,
    #[bits(11)]
    _unused: u16,
    #[bits(16)]
    selector: u16,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes)]
struct FwCfgFilesHeader {
    count_be: u32,
}

pub const FILE_NAME_SIZE: usize = 56;

pub fn create_file_name(name: &str) -> [u8; FILE_NAME_SIZE] {
    let mut c_name = [0u8; FILE_NAME_SIZE];
    let c_len = std::cmp::min(FILE_NAME_SIZE - 1, name.len());
    c_name[0..c_len].copy_from_slice(&name.as_bytes()[0..c_len]);
    c_name
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Debug, IntoBytes, FromBytes, Clone, Copy)]
struct BootE820Entry {
    addr: u64,
    size: u64,
    type_: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes)]
struct FwCfgFile {
    size_be: u32,
    select_be: u16,
    _reserved: u16,
    name: [u8; FILE_NAME_SIZE],
}

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
struct Allocate {
    command: u32,
    file: [u8; FILE_NAME_SIZE],
    align: u32,
    zone: u8,
    _pad: [u8; 63],
}

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
struct AddPointer {
    command: u32,
    dst: [u8; FILE_NAME_SIZE],
    src: [u8; FILE_NAME_SIZE],
    offset: u32,
    size: u8,
    _pad: [u8; 7],
}

#[repr(C, align(4))]
#[derive(Debug, IntoBytes, Immutable)]
struct AddChecksum {
    command: u32,
    file: [u8; FILE_NAME_SIZE],
    offset: u32,
    start: u32,
    len: u32,
    _pad: [u8; 56],
}

fn create_intra_pointer(name: &str, offset: usize, size: u8) -> AddPointer {
    AddPointer {
        command: COMMAND_ADD_POINTER,
        dst: create_file_name(name),
        src: create_file_name(name),
        offset: offset as u32,
        size,
        _pad: [0; 7],
    }
}

fn create_acpi_table_checksum(offset: usize, len: usize) -> AddChecksum {
    AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        offset: (offset + offset_of!(AcpiTableHeader, checksum)) as u32,
        start: offset as u32,
        len: len as u32,
        _pad: [0; 56],
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Default, FromBytes, IntoBytes)]
struct AcpiTableHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    asl_compiler_id: [u8; 4],
    asl_compiler_revision: u32,
}

struct AcpiTable {
    rsdp: Rsdp,
    tables: Vec<u8>,
    table_pointers: Vec<usize>,
    table_checksums: Vec<(usize, usize)>,
}

impl AcpiTable {
    fn pointers(&self) -> &[usize] {
        &self.table_pointers
    }

    fn checksums(&self) -> &[(usize, usize)] {
        &self.table_checksums
    }

    fn take(self) -> (Rsdp, Vec<u8>) {
        (self.rsdp, self.tables)
    }
}

// Creates fw_cfg items used by firmware to load and verify Acpi tables
// https://github.com/qemu/qemu/blob/master/hw/acpi/bios-linker-loader.c
fn create_acpi_loader(acpi_table: AcpiTable) -> [FwCfgItem; 3] {
    let mut table_loader_bytes: Vec<u8> = Vec::new();
    let allocate_rsdp = Allocate {
        command: COMMAND_ALLOCATE,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        align: 4,
        zone: ALLOC_ZONE_FSEG,
        _pad: [0; 63],
    };
    table_loader_bytes.extend(allocate_rsdp.as_bytes());

    let allocate_tables = Allocate {
        command: COMMAND_ALLOCATE,
        file: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        align: 4,
        zone: ALLOC_ZONE_HIGH,
        _pad: [0; 63],
    };
    table_loader_bytes.extend(allocate_tables.as_bytes());

    for pointer_offset in acpi_table.pointers().iter() {
        let pointer = create_intra_pointer(FW_CFG_FILENAME_ACPI_TABLES, *pointer_offset, 8);
        table_loader_bytes.extend(pointer.as_bytes());
    }
    for (offset, len) in acpi_table.checksums().iter() {
        let checksum = create_acpi_table_checksum(*offset, *len);
        table_loader_bytes.extend(checksum.as_bytes());
    }
    let pointer_rsdp_to_xsdt = AddPointer {
        command: COMMAND_ADD_POINTER,
        dst: create_file_name(FW_CFG_FILENAME_RSDP),
        src: create_file_name(FW_CFG_FILENAME_ACPI_TABLES),
        offset: offset_of!(Rsdp, xsdt_addr) as u32,
        size: 8,
        _pad: [0; 7],
    };
    table_loader_bytes.extend(pointer_rsdp_to_xsdt.as_bytes());
    let checksum_rsdp = AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        offset: offset_of!(Rsdp, checksum) as u32,
        start: 0,
        len: offset_of!(Rsdp, length) as u32,
        _pad: [0; 56],
    };
    let checksum_rsdp_ext = AddChecksum {
        command: COMMAND_ADD_CHECKSUM,
        file: create_file_name(FW_CFG_FILENAME_RSDP),
        offset: offset_of!(Rsdp, extended_checksum) as u32,
        start: 0,
        len: size_of::<Rsdp>() as u32,
        _pad: [0; 56],
    };
    table_loader_bytes.extend(checksum_rsdp.as_bytes());
    table_loader_bytes.extend(checksum_rsdp_ext.as_bytes());

    let table_loader = FwCfgItem {
        name: FW_CFG_FILENAME_TABLE_LOADER.to_owned(),
        content: FwCfgContent::Bytes(table_loader_bytes),
    };
    let (rsdp, tables) = acpi_table.take();
    let acpi_rsdp = FwCfgItem {
        name: FW_CFG_FILENAME_RSDP.to_owned(),
        content: FwCfgContent::Bytes(rsdp.as_bytes().to_owned()),
    };
    let apci_tables = FwCfgItem {
        name: FW_CFG_FILENAME_ACPI_TABLES.to_owned(),
        content: FwCfgContent::Bytes(tables),
    };
    [table_loader, acpi_rsdp, apci_tables]
}

#[derive(Error, Debug)]
pub enum FwCfgError {
    #[error("Collective error")]
    ReadError,
    #[error("Collective error")]
    GuestMemAccessError,
    #[error("Collective error")]
    IllegalGpa,
    #[error("Collective error")]
    GuestMemOutOfBoundsAccess(u32),
    #[error("Collective error")]
    IllegalSelector,
    #[error("Collective error")]
    CursorBehindContent,
}

impl FwCfg {
    pub fn new(memory: GuestMemoryAtomic<GuestMemoryMmap<AtomicBitmap>>) -> FwCfg {
        const DEFAULT_ITEM: FwCfgContent = FwCfgContent::Slice(&[]);
        let mut known_items = [DEFAULT_ITEM; FW_CFG_KNOWN_ITEMS];
        known_items[FW_CFG_SIGNATURE as usize] = FwCfgContent::Slice(&FW_CFG_SIGNATURE_CONTENT);
        known_items[FW_CFG_ID as usize] = FwCfgContent::Slice(&FW_CFG_FEATURE);
        let file_buf = Vec::from(FwCfgFilesHeader { count_be: 0 }.as_mut_bytes());
        known_items[FW_CFG_FILE_DIR as usize] = FwCfgContent::Bytes(file_buf);

        FwCfg {
            selector: 0,
            data_offset: 0,
            dma_address: 0,
            items: vec![],
            known_items,
            memory,
        }
    }

    pub fn populate_fw_cfg(
        &mut self,
        mem_size: Option<usize>,
        kernel: Option<File>,
        initramfs: Option<File>,
        cmdline: Option<std::ffi::CString>,
        fw_cfg_item_list: Option<Vec<FwCfgItem>>,
        #[cfg(target_arch = "x86_64")] kvm_sev_snp_enabled: bool,
    ) -> Result<()> {
        if let Some(mem_size) = mem_size {
            self.add_e820(mem_size)?;
        }
        if let Some(kernel) = kernel {
            self.add_kernel_data(
                &kernel,
                #[cfg(target_arch = "x86_64")]
                kvm_sev_snp_enabled,
            )?;
        }
        if let Some(cmdline) = cmdline {
            self.add_kernel_cmdline(cmdline);
        }
        if let Some(initramfs) = initramfs {
            self.add_initramfs_data(&initramfs)?;
        }
        if let Some(fw_cfg_item_list) = fw_cfg_item_list {
            for item in fw_cfg_item_list {
                self.add_item(item)?;
            }
        }
        Ok(())
    }

    pub fn add_e820(&mut self, mem_size: usize) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        let mut mem_regions = vec![
            (GuestAddress(0), EBDA_START.0 as usize, RegionType::Ram),
            (
                MEM_32BIT_DEVICES_START,
                MEM_32BIT_DEVICES_SIZE as usize,
                RegionType::Reserved,
            ),
            (
                PCI_MMCONFIG_START,
                PCI_MMCONFIG_SIZE as usize,
                RegionType::Reserved,
            ),
            (STAGE0_START_ADDRESS, STAGE0_SIZE, RegionType::Reserved),
        ];
        #[cfg(target_arch = "aarch64")]
        let mut mem_regions = arch::aarch64::arch_memory_regions();
        if mem_size < MEM_32BIT_DEVICES_START.0 as usize {
            mem_regions.push((
                HIGH_RAM_START,
                mem_size - HIGH_RAM_START.0 as usize,
                RegionType::Ram,
            ));
        } else {
            mem_regions.push((
                HIGH_RAM_START,
                MEM_32BIT_RESERVED_START.0 as usize - HIGH_RAM_START.0 as usize,
                RegionType::Ram,
            ));
            mem_regions.push((
                RAM_64BIT_START,
                mem_size - (MEM_32BIT_DEVICES_START.0 as usize),
                RegionType::Ram,
            ));
        }
        let mut bytes = vec![];
        for (addr, size, region) in mem_regions.iter() {
            let type_ = match region {
                RegionType::Ram => E820_RAM,
                RegionType::Reserved => E820_RESERVED,
                RegionType::SubRegion => continue,
            };
            let mut entry = BootE820Entry {
                addr: addr.0,
                size: *size as u64,
                type_,
            };
            bytes.extend_from_slice(entry.as_mut_bytes());
        }
        let item = FwCfgItem {
            name: "etc/e820".to_owned(),
            content: FwCfgContent::Bytes(bytes),
        };
        self.add_item(item)
    }

    fn file_dir_mut(&mut self) -> &mut Vec<u8> {
        let FwCfgContent::Bytes(file_buf) = &mut self.known_items[FW_CFG_FILE_DIR as usize] else {
            unreachable!("fw_cfg: selector {FW_CFG_FILE_DIR:#x} should be FwCfgContent::Byte!")
        };
        file_buf
    }

    fn update_count(&mut self) {
        let mut header = FwCfgFilesHeader {
            count_be: (self.items.len() as u32).to_be(),
        };
        self.file_dir_mut()[0..4].copy_from_slice(header.as_mut_bytes());
    }

    pub fn add_item(&mut self, item: FwCfgItem) -> Result<()> {
        let index = self.items.len();
        let c_name = create_file_name(&item.name);
        let size = item.content.size()?;
        let mut cfg_file = FwCfgFile {
            size_be: size.to_be(),
            select_be: (FW_CFG_FILE_FIRST + index as u16).to_be(),
            _reserved: 0,
            name: c_name,
        };
        self.file_dir_mut()
            .extend_from_slice(cfg_file.as_mut_bytes());
        self.items.push(item);
        self.update_count();
        Ok(())
    }

    const BUFFER_SIZE: usize = 0x400;

    // Returns Ok() with the total amount of payload bytes written if all payload write were
    // written. Else returns an error indicating what part of the write did not succeed.
    fn dma_read_content(
        &mut self,
        gpa: GuestAddress,
        dma_len: u32,
    ) -> std::result::Result<u32, FwCfgError> {
        let content = if let Some(known_item) = self.known_items.get(self.selector as usize) {
            known_item
        } else if let Some(item) = self.items.get((self.selector - FW_CFG_FILE_FIRST) as usize) {
            &item.content
        } else {
            return Err(FwCfgError::IllegalSelector);
        };

        let mut buffer = [0_u8; Self::BUFFER_SIZE];
        let content_size = content.size().unwrap() as usize;
        let mut read_size = usize::min(Self::BUFFER_SIZE, content_size);
        let mut offset = 0;
        let mut reached_eof = false;
        let remaining_content_bytes = ((content_size) as u32).saturating_sub(self.data_offset);
        let planned_end = self.data_offset + u32::min(dma_len, remaining_content_bytes);
        if content_size <= self.data_offset as usize {
            return Err(FwCfgError::CursorBehindContent);
        }
        while (dma_len - offset > 0) && !reached_eof {
            read_size = usize::min(read_size, (dma_len - offset) as usize);
            let content_bytes_read = content
                .access(self.data_offset)
                .read(buffer[..read_size].as_mut_bytes())
                .map_err(|_| FwCfgError::ReadError)?;

            if content_bytes_read == 0 {
                break;
            }

            if content_bytes_read < read_size {
                read_size = content_bytes_read;
                reached_eof = true;
            };

            let offset_gpa = gpa
                .checked_add(offset as u64)
                .ok_or(FwCfgError::IllegalGpa)
                .or_else(|e| {
                    self.data_offset = planned_end;
                    Err(e)
                })?;

            let bytes_written = self
                .memory
                .memory()
                .write(&buffer[..read_size], offset_gpa)
                .map_err(|_| FwCfgError::IllegalGpa)
                .or_else(|e| {
                    self.data_offset = planned_end;
                    Err(e)
                })?;

            offset += bytes_written as u32;
            if bytes_written != read_size {
                self.data_offset = planned_end;
                return Err(FwCfgError::GuestMemOutOfBoundsAccess(offset));
            }

            self.data_offset += read_size as u32;
        }
        Ok(offset)
    }

    fn dma_set_memory_to_zero(
        &self,
        gpa: GuestAddress,
        dma_len: u32,
    ) -> std::result::Result<u32, FwCfgError> {
        let buffer = [0_u8; Self::BUFFER_SIZE];
        let mut offset = 0;
        while dma_len - offset > 0 {
            let write_size = usize::min(Self::BUFFER_SIZE, (dma_len - offset) as usize);
            let offset_gpa = gpa
                .checked_add(offset as u64)
                .ok_or(FwCfgError::IllegalGpa)?;

            let bytes_written = self
                .memory
                .memory()
                .write(&buffer[..write_size], offset_gpa)
                .map_err(|_| FwCfgError::IllegalGpa)?;

            offset += bytes_written as u32;
            if bytes_written != write_size {
                return Err(FwCfgError::GuestMemOutOfBoundsAccess(offset));
            }
        }

        Ok(offset)
    }

    fn dma_read(&mut self, len: u32, address: u64) -> Result<usize> {
        let write_result = self.dma_read_content(GuestAddress(address), len);

        // Find the correct zero handling depending on what succeeded in the item write
        let operation_result = match write_result {
            Ok(written) if written == len => Ok(written),
            Ok(written) if written < len => GuestAddress(address)
                .checked_add(written as u64)
                .ok_or(FwCfgError::IllegalGpa)
                .and_then(|gpa| {
                    self.dma_set_memory_to_zero(gpa, len - written)
                        .map(|zeros_written| written + zeros_written)
                }),
            Ok(_) => unreachable!("Should never write more bytes"),
            Err(FwCfgError::IllegalSelector) | Err(FwCfgError::CursorBehindContent) => {
                self.dma_set_memory_to_zero(GuestAddress(address), len)
            }
            Err(FwCfgError::GuestMemOutOfBoundsAccess(written)) => Ok(written),
            Err(e) => Err(e),
        };

        match operation_result {
            Ok(dma_write_len) => Ok(dma_write_len as usize),
            Err(FwCfgError::IllegalGpa) => Err(ErrorKind::InvalidInput.into()),
            Err(FwCfgError::GuestMemOutOfBoundsAccess(n)) => Ok(n as usize),
            Err(_) => unreachable!(
                "All other error kinds can only occur in dma_read_content, which is handled above"
            ),
        }
    }

    fn do_dma(&mut self) {
        let dma_address = self.dma_address;
        self.dma_address = 0;
        let mut dma_access_buf = [0_u8; FwCfgDmaAccess::WIRE_SIZE];
        let dma_access = match self
            .memory
            .memory()
            .read(dma_access_buf.as_mut_bytes(), GuestAddress(dma_address))
        {
            Ok(FwCfgDmaAccess::WIRE_SIZE) => FwCfgDmaAccess::from_be_bytes(&dma_access_buf),
            Ok(n) => {
                error!("fw_cfg: Read an invalid amount of bytes: 0x{n:x}");
                // If QEMU cannot read the entire access descriptor it tries to write at least the
                // control field with the error bit set. We do the same by discarding the write
                // result and returning afterwards.
                let _ = self.memory.memory().write(
                    &AccessControl(0).with_error(true).0.to_be_bytes(),
                    GuestAddress(dma_address),
                );
                return;
            }
            Err(e) => {
                error!("fw_cfg: invalid address of dma access {dma_address:#x}: {e:?}");
                return;
            }
        };
        let control = dma_access.control;
        if control.select() {
            self.selector = control.selector();
            self.data_offset = 0;
        }
        let ret: Result<()> = if control.read() {
            let bytes_written = self.dma_read(dma_access.length, dma_access.address);
            match bytes_written {
                Ok(written) => {
                    if written == dma_access.length as usize {
                        Ok(())
                    } else {
                        Err(ErrorKind::InvalidInput.into())
                    }
                }
                Err(_) => Err(ErrorKind::InvalidInput.into()),
            }
        } else if control.write() {
            Err(ErrorKind::InvalidInput.into())
        } else if control.skip() {
            let item_size = if let Some(known_item) = self.known_items.get(self.selector as usize) {
                known_item.size().unwrap()
            } else if let Some(item) = self.items.get((self.selector - FW_CFG_FILE_FIRST) as usize)
            {
                item.content.size().unwrap()
            } else {
                0
            };
            self.data_offset += if (item_size.saturating_sub(self.data_offset)) < dma_access.length
            {
                item_size.saturating_sub(self.data_offset)
            } else {
                dma_access.length
            };
            Ok(())
        } else {
            // Every other operation is a no-op
            Ok(())
        };
        let mut access_resp = AccessControl(0);
        if let Err(e) = ret {
            error!("fw_cfg: dma operation {dma_access:x?}: {e:x?}");
            access_resp.set_error(true);
        }
        // Control field is defined to be on the lowest address, no offset calculation needed
        if let Err(e) = self
            .memory
            .memory()
            .write(&access_resp.0.to_be_bytes(), GuestAddress(dma_address))
        {
            error!("fw_cfg: finishing dma: {e:?}");
        }
    }

    pub fn add_kernel_data(
        &mut self,
        file: &File,
        #[cfg(target_arch = "x86_64")] kvm_sev_snp_enabled: bool,
    ) -> Result<()> {
        let mut buffer = vec![0u8; size_of::<boot_params>()];
        file.read_exact_at(&mut buffer, 0)?;
        let bp = boot_params::from_mut_slice(&mut buffer).unwrap();
        #[cfg(target_arch = "x86_64")]
        {
            // For SEV-SNP guests on KVM, don't modify the kernel header so the
            // bytes sent via fw_cfg match what the VMM hashes for the launch digest.
            // The guest firmware handles these fields itself.
            if !kvm_sev_snp_enabled {
                if bp.hdr.setup_sects == 0 {
                    bp.hdr.setup_sects = 4;
                }
                bp.hdr.type_of_loader = 0xff;
            }
        }
        #[cfg(target_arch = "aarch64")]
        let kernel_start = bp.text_offset;
        #[cfg(target_arch = "x86_64")]
        let kernel_start = {
            let sects = if bp.hdr.setup_sects == 0 {
                4
            } else {
                bp.hdr.setup_sects
            };
            (sects as usize + 1) * 512
        };

        #[cfg(target_arch = "x86_64")]
        if kernel_start <= buffer.len() {
            buffer.truncate(kernel_start);
        } else {
            buffer.resize(kernel_start, 0);
            file.read_exact_at(
                &mut buffer[size_of::<boot_params>()..],
                size_of::<boot_params>() as u64,
            )?;
        }

        self.known_items[FW_CFG_SETUP_SIZE as usize] = FwCfgContent::U32(buffer.len() as u32);
        self.known_items[FW_CFG_SETUP_DATA as usize] = FwCfgContent::Bytes(buffer);
        self.known_items[FW_CFG_KERNEL_SIZE as usize] =
            FwCfgContent::U32(file.metadata()?.len() as u32 - kernel_start as u32);
        self.known_items[FW_CFG_KERNEL_DATA as usize] =
            FwCfgContent::File(kernel_start as u64, file.try_clone()?);
        Ok(())
    }

    pub fn add_kernel_cmdline(&mut self, s: std::ffi::CString) {
        let bytes = s.into_bytes_with_nul();
        self.known_items[FW_CFG_CMDLINE_SIZE as usize] = FwCfgContent::U32(bytes.len() as u32);
        self.known_items[FW_CFG_CMDLINE_DATA as usize] = FwCfgContent::Bytes(bytes);
    }

    pub fn add_acpi(
        &mut self,
        rsdp: Rsdp,
        tables: Vec<u8>,
        table_checksums: Vec<(usize, usize)>,
        table_pointers: Vec<usize>,
    ) -> Result<()> {
        let acpi_table = AcpiTable {
            rsdp,
            tables,
            table_checksums,
            table_pointers,
        };
        let [table_loader, acpi_rsdp, apci_tables] = create_acpi_loader(acpi_table);
        self.add_item(table_loader)?;
        self.add_item(acpi_rsdp)?;
        self.add_item(apci_tables)
    }

    pub fn add_initramfs_data(&mut self, file: &File) -> Result<()> {
        let initramfs_size = file.metadata()?.len();
        self.known_items[FW_CFG_INITRD_SIZE as usize] = FwCfgContent::U32(initramfs_size as _);
        self.known_items[FW_CFG_INITRD_DATA as usize] = FwCfgContent::File(0, file.try_clone()?);
        Ok(())
    }

    fn read_content(&mut self, data: &mut [u8], size: u32) -> Option<u8> {
        let content = if let Some(content) = self.known_items.get(self.selector as usize) {
            Some(content)
        } else if let Some(item) = self.items.get((self.selector - FW_CFG_FILE_FIRST) as usize) {
            Some(&item.content)
        } else {
            error!("fw_cfg: selector {:#x} does not exist.", self.selector);
            None
        };

        let content_size = if let Some(content) = content {
            content.size().unwrap() as usize
        } else {
            0
        };
        let remaining_content_bytes = ((content_size) as u32).saturating_sub(self.data_offset);
        let mut content_bytes_to_copy = u32::min(remaining_content_bytes, size);
        let mut planned_end = self.data_offset + content_bytes_to_copy;
        let start = self.data_offset as usize;
        let end = start + content_bytes_to_copy as usize;
        match content {
            Some(FwCfgContent::Bytes(b)) => {
                data[..content_bytes_to_copy as usize].copy_from_slice(&b[start..end]);
            }
            Some(FwCfgContent::Slice(s)) => {
                data[..content_bytes_to_copy as usize].copy_from_slice(&s[start..end]);
            }
            Some(FwCfgContent::File(o, f)) => {
                if f.read_exact_at(
                    &mut data[..content_bytes_to_copy as usize],
                    o + self.data_offset as u64,
                )
                .is_err()
                {
                    content_bytes_to_copy = 0;
                    planned_end = self.data_offset;
                }
            }
            Some(FwCfgContent::U32(n)) => {
                let bytes = n.to_le_bytes();
                data[..content_bytes_to_copy as usize].copy_from_slice(&bytes[start..end]);
            }
            None => { /* Do Nothing. */ }
        };
        data[content_bytes_to_copy as usize..].fill(0x0);

        self.data_offset = planned_end;

        Some(content_bytes_to_copy as u8)
    }

    fn read_data(&mut self, data: &mut [u8], size: u32) {
        _ = self.read_content(data, size);
    }
}

impl BusDevice for FwCfg {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let port = offset + PORT_FW_CFG_BASE;
        let size = data.len();
        match (port, size) {
            (PORT_FW_CFG_SELECTOR, 1) => {
                // Selector register is actually defined write-only. QEMU’s combined PIO region
                // treats a 1-byte read at this offset as a data read. Bypass to mimic QEMU quirk.
                self.read_data(data, size as u32);
            }
            (PORT_FW_CFG_DATA, 1) => _ = self.read_data(data, size as u32),
            (port, 4) if port >= PORT_FW_CFG_DMA_HI && port <= PORT_FW_CFG_DMA_LO => {
                let offset_in_port_range = (port - PORT_FW_CFG_DMA_HI) as usize;
                data.copy_from_slice(
                    &FW_CFG_DMA_SIGNATURE_CONTENT[offset_in_port_range..offset_in_port_range + 4],
                );
            }
            (port, 2) if port >= PORT_FW_CFG_DMA_HI && port <= PORT_FW_CFG_DMA_LO + 2 => {
                let offset_in_port_range = (port - PORT_FW_CFG_DMA_HI) as usize;
                data.copy_from_slice(
                    &FW_CFG_DMA_SIGNATURE_CONTENT[offset_in_port_range..offset_in_port_range + 2],
                );
            }
            (port, 1) if port >= PORT_FW_CFG_DMA_HI && port <= PORT_FW_CFG_DMA_LO + 3 => {
                let offset_in_port_range = (port - PORT_FW_CFG_DMA_HI) as usize;
                data.copy_from_slice(
                    &FW_CFG_DMA_SIGNATURE_CONTENT[offset_in_port_range].as_bytes(),
                );
            }
            _ => {
                debug!("fw_cfg: Unsupported {size:#x}-byte read from port {port:#x}.");
                data.fill(0x0);
            }
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let port = offset + PORT_FW_CFG_BASE;
        let size = data.size();
        match (port, size) {
            (PORT_FW_CFG_SELECTOR, 2) => {
                let mut buf = [0u8; 2];
                buf[..size].copy_from_slice(&data[..size]);
                #[cfg(target_arch = "x86_64")]
                let val = u16::from_le_bytes(buf);
                #[cfg(target_arch = "aarch64")]
                let val = u16::from_be_bytes(buf);
                self.selector = val;
                self.data_offset = 0;
            }
            (PORT_FW_CFG_DATA, 1) => error!("fw_cfg: data register is read-only."),
            (PORT_FW_CFG_DMA_HI, 4) => {
                let mut buf = [0u8; 4];
                buf[..size].copy_from_slice(&data[..size]);
                let val = u32::from_be_bytes(buf);
                // After each DMA operation `dma_address` is reset to 0. A write to the lower 32 bit
                // triggers an operation. So when we write the upper 4 bytes the lower 4 will always
                // be zero. We do not need to handle them here.
                self.dma_address = (val as u64) << 32;
            }
            (PORT_FW_CFG_DMA_LO, 4) => {
                let mut buf = [0u8; 4];
                buf[..size].copy_from_slice(&data[..size]);
                let val = u32::from_be_bytes(buf);
                // self.dma_address has either only set the upper 32 bit if we first wrote to the
                // upper 4 byte or is zero if fw_cfg was reset or finished a DMA operation.
                // So no need for masking.
                self.dma_address |= val as u64;
                self.do_dma();
            }
            _ => debug!(
                "fw_cfg: write to unknown port {port:#x}: {size:#x} bytes and offset {offset:#x} ."
            ),
        }
        None
    }
}

#[cfg(test)]
mod unit_tests {
    use std::ffi::CString;
    use std::io::Write;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[cfg(target_arch = "x86_64")]
    const SELECTOR_OFFSET: u64 = 0;
    #[cfg(target_arch = "aarch64")]
    const SELECTOR_OFFSET: u64 = 8;
    #[cfg(target_arch = "x86_64")]
    const DATA_OFFSET: u64 = 1;
    #[cfg(target_arch = "aarch64")]
    const DATA_OFFSET: u64 = 0;
    #[cfg(target_arch = "x86_64")]
    const DMA_OFFSET: u64 = 4;
    #[cfg(target_arch = "aarch64")]
    const DMA_OFFSET: u64 = 16;

    const INIT_BYTE_VALUE: u8 = 0xAC;

    #[test]
    fn test_signature() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        let mut data = vec![0u8];

        let mut sig_iter = FW_CFG_SIGNATURE_CONTENT.into_iter();
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        loop {
            if let Some(char) = sig_iter.next() {
                fw_cfg.read(0, DATA_OFFSET, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }

    #[test]
    fn test_kernel_cmdline() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        let cmdline = *b"cmdline\0";

        fw_cfg.add_kernel_cmdline(CString::from_vec_with_nul(cmdline.to_vec()).unwrap());

        let mut data = vec![0u8];

        let mut cmdline_iter = cmdline.into_iter();
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_CMDLINE_DATA as u8, 0]);
        loop {
            if let Some(char) = cmdline_iter.next() {
                fw_cfg.read(0, DATA_OFFSET, &mut data);
                assert_eq!(data[0], char);
            } else {
                return;
            }
        }
    }

    #[test]
    fn test_initram_fs_and_reads_beyond_file_boundary() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        let temp = TempFile::new().unwrap();
        let mut temp_file = temp.as_file();

        let initram_content = b"this is the initramfs";
        let written = temp_file.write(initram_content);
        assert_eq!(written.unwrap(), 21);
        let _ = fw_cfg.add_initramfs_data(temp_file);

        let mut buffer = [0u8; 25];

        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_INITRD_DATA as u8, 0]);

        let max_offset = initram_content.len() as u32;
        for (offset, byte) in buffer.iter_mut().enumerate() {
            fw_cfg.read(0, DATA_OFFSET, byte.as_mut_bytes());
            let expected_offset = if (offset as u32 + 1) < max_offset {
                offset as u32 + 1
            } else {
                max_offset
            };
            assert_eq!(fw_cfg.data_offset, expected_offset);
        }
        assert_eq!(&buffer[..initram_content.len()], initram_content);
        assert_eq!(&buffer[initram_content.len()..], [0; 4]);
    }

    #[test]
    fn test_string_item() {
        let gm = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), RAM_64BIT_START.0 as usize)]).unwrap(),
        );

        let mut fw_cfg = FwCfg::new(gm);

        // Simulate OVMF X-PciMmio64Mb string item for GPU CC passthrough
        let item = FwCfgItem {
            name: "opt/ovmf/X-PciMmio64Mb".to_owned(),
            content: FwCfgContent::Bytes("262144".as_bytes().to_vec()),
        };
        fw_cfg.add_item(item).unwrap();

        let expected = b"262144";
        let mut data = vec![0u8];

        // Select the first file item (FW_CFG_FILE_FIRST = 0x20)
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_FILE_FIRST as u8, 0]);
        for &byte in expected.iter() {
            fw_cfg.read(0, DATA_OFFSET, &mut data);
            assert_eq!(data[0], byte);
        }
    }

    /// Creates a guest memory mapping and places `FwCfgDmaAccess` at the given address in the guest
    /// memory. Payload GPA is initialized with a bytes sequence of 0xAC to ensure not accidental
    /// zero writes happen
    fn setup_fw_cfg_dma_with_access_control(
        payload_len: usize,
        payload_gpa: GuestAddress,
        dma_gpa: GuestAddress,
        access_control: AccessControl,
    ) -> Result<(GuestMemoryMmap<AtomicBitmap>, FwCfg)> {
        let mem_size = 0x1000;
        // Create memory regions for the payload and the DmaAccess struct
        let mem: GuestMemoryMmap<AtomicBitmap> =
            GuestMemoryMmap::from_ranges(&[(payload_gpa, mem_size), (dma_gpa, mem_size)])
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let init_data = vec![INIT_BYTE_VALUE; mem_size];
        let _ = mem
            .write(init_data.as_bytes(), payload_gpa)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        // Create the fw_cfg device
        let fw_cfg = FwCfg::new(GuestMemoryAtomic::new(mem.clone()));
        // Create the FwCfgDmaAccess struct and place it in the guest memory on the given address
        update_fw_cfg_dma_access(&mem, payload_len, payload_gpa, dma_gpa, access_control)?;

        Ok((mem, fw_cfg))
    }

    // helper to update the access control struct in guest memory
    fn update_fw_cfg_dma_access(
        guest_mem: &GuestMemoryMmap<AtomicBitmap>,
        payload_len: usize,
        payload_gpa: GuestAddress,
        dma_gpa: GuestAddress,
        access_control: AccessControl,
    ) -> Result<()> {
        let access = FwCfgDmaAccess {
            control: access_control,
            length: payload_len as u32,
            address: payload_gpa.0,
        };
        let _ = guest_mem
            .write(&access.to_be_bytes(), dma_gpa)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        Ok(())
    }

    #[test]
    fn test_dma_byte_content_transfer() {
        let payload = [
            0xba, 0xf8, 0x03, 0x00, 0xd8, 0x04, b'0', 0xee, 0xb0, b'\n', 0xee, 0xf4,
        ];
        let payload_gpa = GuestAddress(0x1000);
        let dma_gpa = GuestAddress(0x2000);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            payload.len(),
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        // Add the payload as FwCfg item
        let content = FwCfgContent::Bytes(payload.to_vec());
        let cfg_item = FwCfgItem {
            name: "code".to_string(),
            content,
        };
        fw_cfg.add_item(cfg_item).unwrap();

        // Check that the payload is not already stored in guest memory
        let mut data = [0u8; 12];
        let _ = mem.read(&mut data, payload_gpa);
        assert_ne!(data, payload);
        // Do DMA
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_FILE_FIRST as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        // Check that the payload is not stored at the target GPA
        let _ = mem.read(&mut data, payload_gpa);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_dma_32bit_address_handling() {
        let mut data = [0u8; 4];
        let payload_addr = GuestAddress(0x0000_2000_u64);
        let dma_32_bit = GuestAddress(0xFEEA_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            FW_CFG_DMA_SIGNATURE_CONTENT.len(),
            payload_addr,
            dma_32_bit,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        // Ensure that the signature is not stored at the target location before we actually did DMA
        let _ = mem.read(data.as_mut_bytes(), payload_addr);
        assert_ne!(data, FW_CFG_SIGNATURE_CONTENT);
        // Perform DMA by calling `BusDevice` functions
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_32_bit.0 as u32).to_be_bytes());
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_32_bit);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0);
        // Check that fw_cfg wrote the correct bytes to the destination GPA
        let _ = mem.read(data.as_mut_bytes(), payload_addr);
        assert_eq!(data, FW_CFG_SIGNATURE_CONTENT);
        // We triggered an operation thus the address should be reset to zero
        assert_eq!(fw_cfg.dma_address, 0);
    }

    #[test]
    fn test_dma_64bit_address_handling() {
        let payload_addr = GuestAddress(0x0000_2000_u64);
        let dma_64_bit = GuestAddress(0x1_ACAC_1CC0_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            FW_CFG_SIGNATURE_CONTENT.len(),
            payload_addr,
            dma_64_bit,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        // Prepare the addresses to write into the DMA registers
        let address_bytes: [u8; 8] = dma_64_bit.0.to_be_bytes();
        let addr_hi_bytes: [u8; 4] = address_bytes[0..4].try_into().unwrap();
        let addr_lo_bytes: [u8; 4] = address_bytes[4..8].try_into().unwrap();

        // Ensure that the signature is not stored at the target location before we actually did DMA
        let mut data = [0u8; 4];
        let _ = mem.read(data.as_mut_bytes(), payload_addr);
        assert_ne!(data, FW_CFG_SIGNATURE_CONTENT);
        // Perform DMA by calling `BusDevice` functions
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET, &addr_hi_bytes);
        fw_cfg.write(0, DMA_OFFSET + 4, &addr_lo_bytes);
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(access_buffer.as_mut_bytes(), dma_64_bit);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0);
        // Check that fw_cfg wrote the correct bytes to the destination GPA
        let _ = mem.read(data.as_mut_bytes(), payload_addr);
        assert_eq!(data, FW_CFG_SIGNATURE_CONTENT);
        // We triggered an operation thus the address should be reset to zero
        assert_eq!(fw_cfg.dma_address, 0);
    }

    #[test]
    fn test_dma_skip_bytes() {
        let payload_gpa = GuestAddress(0x0000_2000_u64);
        let dma_gpa = GuestAddress(0xFEEA_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            FW_CFG_SIGNATURE_CONTENT.len(),
            payload_gpa,
            dma_gpa,
            AccessControl::new(),
        )
        .unwrap();

        let mut data = [0u8; 2];
        // Prepare to skip the first 4 bytes and ensure the offset is set accordingly
        update_fw_cfg_dma_access(
            &mem,
            2,
            payload_gpa,
            dma_gpa,
            AccessControl(0).with_skip(true),
        )
        .unwrap();
        // use the selector register to save one fwCfgDmaAccess update cycle
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        assert_eq!(fw_cfg.data_offset, 2);
        // Check that the memory is still contains the initial value
        let _ = mem.read(data.as_mut_bytes(), payload_gpa).unwrap();
        assert_eq!(data, [INIT_BYTE_VALUE; 2]);
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0);

        // Now read the last 4 bytes. This ensures a single read command doesn't reset the offset
        update_fw_cfg_dma_access(
            &mem,
            4,
            payload_gpa,
            dma_gpa,
            AccessControl(0).with_read(true),
        )
        .unwrap();
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        // Check that the data read is the data expected
        let _ = mem.read(data.as_mut_bytes(), payload_gpa);
        assert_eq!(data, FW_CFG_SIGNATURE_CONTENT[2..]);
        assert_eq!(
            fw_cfg.data_offset,
            u32::try_from(FW_CFG_SIGNATURE_CONTENT.len()).unwrap()
        );

        update_fw_cfg_dma_access(
            &mem,
            4,
            payload_gpa,
            dma_gpa,
            AccessControl(0).with_skip(true),
        )
        .unwrap();
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        assert_eq!(
            fw_cfg.data_offset,
            u32::try_from(FW_CFG_SIGNATURE_CONTENT.len()).unwrap()
        );
    }

    #[test]
    fn test_dma_no_control_bits_is_valid_no_op() {
        const OFFSET_INIT: u32 = 0x1234_5678_u32;
        const SELECTOR_INIT: u16 = 0xABCD_u16;
        let payload_gpa = GuestAddress(0x0000_2000_u64);
        let dma_gpa = GuestAddress(0xFEEA_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            FW_CFG_DMA_SIGNATURE_CONTENT.len(),
            payload_gpa,
            dma_gpa,
            AccessControl(0).with_selector(0xABCD),
        )
        .unwrap();
        // Write some data in the FwCfg register to verify none is overwritten
        fw_cfg.data_offset = OFFSET_INIT;
        fw_cfg.selector = SELECTOR_INIT;
        // Do DMA access with no operation bit set -> should result in no-op
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        // Check that fw_cfg state didn't change
        assert_eq!(fw_cfg.data_offset, OFFSET_INIT);
        assert_eq!(fw_cfg.selector, SELECTOR_INIT);
        // Check that the control field is reset to zero
        // This also means that the error bit must not be set
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0);
        // Check that the memory is still contains the initial value
        let mut data = [0x0_u8; 8];
        let _ = mem.read(data.as_mut_bytes(), payload_gpa).unwrap();
        assert_eq!(data, [INIT_BYTE_VALUE; 8]);
    }

    #[test]
    fn test_dma_select_through_selector_field_works() {
        let payload_gpa = GuestAddress(0x0000_2000_u64);
        let dma_gpa = GuestAddress(0xFEEA_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            FW_CFG_DMA_SIGNATURE_CONTENT.len(),
            payload_gpa,
            dma_gpa,
            AccessControl(0).with_select(true).with_selector(0x10),
        )
        .unwrap();
        // After initialization the selector field must be 0
        assert_eq!(fw_cfg.selector, 0);
        fw_cfg.data_offset = 0x10;
        // Do DMA access only setting the selector field
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        assert_eq!(fw_cfg.selector, 0x10);
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0);
        // Data offset has been reset
        assert_eq!(fw_cfg.data_offset, 0);
    }

    #[test]
    fn dma_access_control_bits_map_correctly() {
        // No bits set
        let ac = AccessControl(0x0000_0000);
        assert_eq!(ac.error(), false);
        assert_eq!(ac.read(), false);
        assert_eq!(ac.skip(), false);
        assert_eq!(ac.write(), false);
        assert_eq!(ac.select(), false);
        assert_eq!(ac.selector(), 0);

        // only error bit is set
        let ac = AccessControl(0x0000_0001);
        assert_eq!(ac.error(), true);
        assert_eq!(ac.read(), false);
        assert_eq!(ac.select(), false);
        assert_eq!(ac.skip(), false);
        assert_eq!(ac.write(), false);
        assert_eq!(ac.selector(), 0);

        // only read bit is set
        let ac = AccessControl(0x0000_0002);
        assert_eq!(ac.error(), false);
        assert_eq!(ac.read(), true);
        assert_eq!(ac.skip(), false);
        assert_eq!(ac.select(), false);
        assert_eq!(ac.write(), false);
        assert_eq!(ac.selector(), 0);

        // only skip bit is set
        let ac = AccessControl(0x0000_0004);
        assert_eq!(ac.error(), false);
        assert_eq!(ac.read(), false);
        assert_eq!(ac.skip(), true);
        assert_eq!(ac.select(), false);
        assert_eq!(ac.write(), false);
        assert_eq!(ac.selector(), 0);

        // only select bit is set
        let ac = AccessControl(0x0000_0008);
        assert_eq!(ac.error(), false);
        assert_eq!(ac.read(), false);
        assert_eq!(ac.skip(), false);
        assert_eq!(ac.select(), true);
        assert_eq!(ac.write(), false);
        assert_eq!(ac.selector(), 0);

        // only write bit is set
        let ac = AccessControl(0x0000_0010);
        assert_eq!(ac.error(), false);
        assert_eq!(ac.read(), false);
        assert_eq!(ac.skip(), false);
        assert_eq!(ac.select(), false);
        assert_eq!(ac.write(), true);
        assert_eq!(ac.selector(), 0);

        // only selector bits are set
        let ac = AccessControl(0xACAC_0000);
        assert_eq!(ac.error(), false);
        assert_eq!(ac.read(), false);
        assert_eq!(ac.skip(), false);
        assert_eq!(ac.select(), false);
        assert_eq!(ac.write(), false);
        assert_eq!(ac.selector(), 0xACAC);

        // all access bits and selector are set
        let ac = AccessControl(0xACAC_001F);
        assert_eq!(ac.error(), true);
        assert_eq!(ac.read(), true);
        assert_eq!(ac.skip(), true);
        assert_eq!(ac.select(), true);
        assert_eq!(ac.write(), true);
        assert_eq!(ac.selector(), 0xACAC);

        // Padding bits do not effect any other bits
        let ac = AccessControl(0x000_FFE0);
        assert_eq!(ac.error(), false);
        assert_eq!(ac.read(), false);
        assert_eq!(ac.skip(), false);
        assert_eq!(ac.select(), false);
        assert_eq!(ac.write(), false);
        assert_eq!(ac.selector(), 0x0);
    }

    #[test]
    fn test_fw_cfg_dma_access_from_wire() {
        let expected_control = 0x6767_6767_u32;
        let expected_length = 0x8989_8989_u32;
        let expected_address = 0xBCBC_BCBC_DEDE_DEDE_u64;

        let mut buffer = [0_u8; FwCfgDmaAccess::WIRE_SIZE];
        buffer[0..4].copy_from_slice(&expected_control.to_be_bytes());
        buffer[4..8].copy_from_slice(&expected_length.to_be_bytes());
        buffer[8..16].copy_from_slice(&expected_address.to_be_bytes());

        let access = FwCfgDmaAccess::from_be_bytes(&buffer);
        assert_eq!(access.control.0, expected_control);
        assert_eq!(access.length, expected_length);
        assert_eq!(access.address, expected_address);
    }

    #[test]
    fn test_fw_cfg_dma_access_to_wire() {
        let expected_control = 0x6767_6767_u32;
        let expected_length = 0x8989_8989_u32;
        let expected_address = 0xBCBC_BCBC_DEDE_DEDE_u64;

        let access = FwCfgDmaAccess {
            control: AccessControl(expected_control),
            length: expected_length,
            address: expected_address,
        };

        let mut buffer = [0_u8; FwCfgDmaAccess::WIRE_SIZE];
        buffer.copy_from_slice(&access.to_be_bytes());
        assert_eq!(buffer[0..4], expected_control.to_be_bytes());
        assert_eq!(buffer[4..8], expected_length.to_be_bytes());
        assert_eq!(buffer[8..16], expected_address.to_be_bytes());
    }

    #[test]
    fn test_dma_boundary_crossing_dma_access_structure_triggers_error() {
        // We test the case that the address for the FwCfgDmaAccess structure
        // points to the last 4 bytes of a writable guest memory region. So
        // reading the whole 16-byte structure fails but writing the control
        // field still is possible.
        let payload_addr = GuestAddress(0x0000_2000_u64);
        let dma_32_bit = GuestAddress(0x4000_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            FW_CFG_DMA_SIGNATURE_CONTENT.len(),
            payload_addr,
            dma_32_bit,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        // Perform DMA by calling `BusDevice` functions
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(0x5000_u32 - 4).to_be_bytes());
        let mut access_buffer = [0_u8; 16];
        // Only read 4 bytes at the end of the guest memory
        let bytes_read = mem
            .read(&mut access_buffer, GuestAddress(0x5000_u64 - 4))
            .unwrap();
        assert_eq!(bytes_read, 4_usize);
        // Check that the control field is reset to with only the error bit set
        assert_eq!(
            FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0,
            0x1_u32
        );
    }

    #[test]
    fn test_dma_read_exceeds_item_length() {
        const DATA_BUFFER_LEN: usize = FwCfg::BUFFER_SIZE * 3;
        let payload_gpa = GuestAddress(0x2000_u64);
        let dma_gpa = GuestAddress(0x4000_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            DATA_BUFFER_LEN, /* Defines the DMA read length */
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        let mut data = [INIT_BYTE_VALUE; DATA_BUFFER_LEN];
        // use the selector register to save one fwCfgDmaAccess update cycle
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        // Check that the item was read and remaining bytes set to 0
        let _ = mem.read(data.as_mut_bytes(), payload_gpa).unwrap();
        assert_eq!(
            data[0..FW_CFG_SIGNATURE_CONTENT.len()],
            FW_CFG_SIGNATURE_CONTENT
        );
        assert_eq!(
            data[FW_CFG_SIGNATURE_CONTENT.len()..],
            [0; DATA_BUFFER_LEN - FW_CFG_SIGNATURE_CONTENT.len()]
        );
        assert_eq!(
            fw_cfg.data_offset,
            u32::try_from(FW_CFG_SIGNATURE_CONTENT.len()).unwrap()
        );
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0);
        assert_eq!(fw_cfg.data_offset as usize, FW_CFG_SIGNATURE_CONTENT.len());
    }

    #[test]
    fn test_dma_read_guest_buffer_boundaries_respected() {
        const DATA_BUFFER_LEN: usize = FwCfg::BUFFER_SIZE * 3 + 512;
        let payload_gpa = GuestAddress(0x2000_u64);
        let dma_gpa = GuestAddress(0x4000_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            DATA_BUFFER_LEN, /* Defines the DMA read length */
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        let mut data = [0xCC; 0x1000];
        // use the selector register to save one fwCfgDmaAccess update cycle
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        // Check that the item was read and remaining bytes set to 0
        let _ = mem.read(data.as_mut_bytes(), payload_gpa).unwrap();
        assert_eq!(
            data[0..FW_CFG_SIGNATURE_CONTENT.len()],
            FW_CFG_SIGNATURE_CONTENT
        );
        assert_eq!(
            data[FW_CFG_SIGNATURE_CONTENT.len()..DATA_BUFFER_LEN],
            [0; DATA_BUFFER_LEN - FW_CFG_SIGNATURE_CONTENT.len()]
        );
        assert_eq!(
            data[DATA_BUFFER_LEN..],
            [INIT_BYTE_VALUE; 0x1000 - DATA_BUFFER_LEN]
        );
        assert_eq!(
            fw_cfg.data_offset,
            u32::try_from(FW_CFG_SIGNATURE_CONTENT.len()).unwrap()
        );
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0);
        assert_eq!(fw_cfg.data_offset as usize, FW_CFG_SIGNATURE_CONTENT.len());
    }

    #[test]
    fn test_dma_read_invalid_selector() {
        // If we encounter an invalid selector we expect fw_cfg to successfully override the entire
        // guest buffer with 0 and return success.
        const DATA_BUFFER_LEN: usize = FwCfg::BUFFER_SIZE;
        const CANARY_VALUE: u8 = 0xCC;
        let payload_gpa = GuestAddress(0x2000_u64);
        let dma_gpa = GuestAddress(0x4000_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            DATA_BUFFER_LEN, /* Defines the DMA read length */
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        let mut data = [CANARY_VALUE; 0x1000];
        // use the selector register to save one fwCfgDmaAccess update cycle
        fw_cfg.write(0, SELECTOR_OFFSET, &[255 as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        // Check that the item was read and remaining bytes set to 0
        let _ = mem.read(data.as_mut_bytes(), payload_gpa).unwrap();
        assert_eq!(data[..DATA_BUFFER_LEN], [0; DATA_BUFFER_LEN]);
        // Check that fw_cfg didn't touch any bytes behind the specified range
        assert_eq!(
            data[DATA_BUFFER_LEN..],
            [INIT_BYTE_VALUE; 0x1000 - DATA_BUFFER_LEN]
        );
        assert_eq!(fw_cfg.data_offset, 0);
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0);
        assert_eq!(fw_cfg.data_offset, 0);
    }

    #[test]
    fn test_dma_read_exceeds_guest_mem() {
        const DATA_BUFFER_LEN: usize = FwCfg::BUFFER_SIZE;
        const CANARY_VALUE: u8 = 0xCC;
        let payload_gpa_start = GuestAddress(0x2000_u64);
        let dma_gpa = GuestAddress(0x4000_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            0x1000, /* Defines the DMA read length */
            payload_gpa_start,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();
        // Move the address of the DMA target to the middle of the allocated page. We will be able
        // to write the first half of the page but not the second half.
        let payload_gpa = GuestAddress(payload_gpa_start.0.checked_add(0xD00).unwrap());
        update_fw_cfg_dma_access(
            &mem,
            DATA_BUFFER_LEN,
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        let mut data = [CANARY_VALUE; 0x1000];
        // use the selector register to save one fwCfgDmaAccess update cycle
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        // Check that the item was read and remaining bytes set to 0
        let l = mem.read(data.as_mut_bytes(), payload_gpa).unwrap();
        assert_eq!(l, 0x1000 - 0xd00);
        assert_eq!(
            data[0..FW_CFG_SIGNATURE_CONTENT.len()],
            FW_CFG_SIGNATURE_CONTENT
        );
        assert_eq!(
            data[FW_CFG_SIGNATURE_CONTENT.len()..0x1000 - 0xd00],
            [0; 0x1000 - 0xd00 - FW_CFG_SIGNATURE_CONTENT.len()]
        );
        assert_eq!(
            fw_cfg.data_offset,
            u32::try_from(FW_CFG_SIGNATURE_CONTENT.len()).unwrap()
        );
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(
            FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0,
            AccessControl(0).with_error(true).0
        );
    }

    #[test]
    fn test_dma_read_item_partly() {
        const DATA_BUFFER_LEN: usize = 4;
        let payload_gpa = GuestAddress(0x2000_u64);
        let dma_gpa = GuestAddress(0x4000_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            DATA_BUFFER_LEN, /* Defines the DMA read length */
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        let mut data = [INIT_BYTE_VALUE; DATA_BUFFER_LEN];
        // use the selector register to save one fwCfgDmaAccess update cycle
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        // Check that the item was read and remaining bytes set to 0
        let _ = mem.read(data.as_mut_bytes(), payload_gpa).unwrap();
        assert_eq!(data, FW_CFG_SIGNATURE_CONTENT[..DATA_BUFFER_LEN]);
        assert_eq!(fw_cfg.data_offset, DATA_BUFFER_LEN as u32);
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0);
    }

    #[test]
    fn test_dma_read_cursor_properly_advances_if_remaining_bytes_less_than_buffer() {
        const DMA_LEN: usize = FwCfg::BUFFER_SIZE + 1;
        let payload_bytes = [0xEF_u8; FwCfg::BUFFER_SIZE * 6];
        let payload_gpa = GuestAddress(0x2000_u64);
        let dma_gpa = GuestAddress(0x4000_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            DMA_LEN, /* Defines the DMA read length */
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        // Add the payloads as FwCfg item
        let content = FwCfgContent::Bytes(payload_bytes[0..FwCfg::BUFFER_SIZE * 2].to_vec());
        let cfg_item = FwCfgItem {
            name: "small_payload".to_string(),
            content,
        };
        fw_cfg.add_item(cfg_item).unwrap();

        let content = FwCfgContent::Bytes(payload_bytes.to_vec());
        let cfg_item = FwCfgItem {
            name: "big_payload".to_string(),
            content,
        };
        fw_cfg.add_item(cfg_item).unwrap();

        let mut data = [INIT_BYTE_VALUE; DMA_LEN];
        // use the selector register to save one fwCfgDmaAccess update cycle
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_FILE_FIRST as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        // Check that the item was read and remaining bytes set to 0
        let _ = mem.read(data.as_mut_bytes(), payload_gpa).unwrap();
        assert_eq!(data, payload_bytes[..DMA_LEN]);
        assert_eq!(fw_cfg.data_offset, DMA_LEN as u32);
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0);

        update_fw_cfg_dma_access(
            &mem,
            FwCfg::BUFFER_SIZE * 6,
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();
        let mut data = [INIT_BYTE_VALUE; FwCfg::BUFFER_SIZE * 6];
        // use the selector register to save one fwCfgDmaAccess update cycle
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_FILE_FIRST as u8 + 1, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        // Check that the item was read and remaining bytes set to 0
        let _ = mem.read(data.as_mut_bytes(), payload_gpa).unwrap();
        assert_eq!(data[..0x1000], payload_bytes[..0x1000]);
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0x1);
        assert_eq!(fw_cfg.data_offset, (FwCfg::BUFFER_SIZE * 6) as u32);

        update_fw_cfg_dma_access(
            &mem,
            FwCfg::BUFFER_SIZE * 6,
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();
        let mut data = [INIT_BYTE_VALUE; FwCfg::BUFFER_SIZE * 6];
        // use the selector register to save one fwCfgDmaAccess update cycle
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_FILE_FIRST as u8 + 1, 0]);
        fw_cfg.data_offset = 8;
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        // Check that the item was read and remaining bytes set to 0
        let _ = mem.read(data.as_mut_bytes(), payload_gpa).unwrap();
        assert_eq!(data[..0x1000], payload_bytes[..0x1000]);
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0x1);
        assert_eq!(fw_cfg.data_offset, (FwCfg::BUFFER_SIZE * 6) as u32);
    }

    #[test]
    fn test_dma_set_cursor_beyond_content() {
        let payload_gpa = GuestAddress(0x0000_2000_u64);
        let dma_gpa = GuestAddress(0xFEEA_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            FW_CFG_SIGNATURE_CONTENT.len() + 2,
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_skip(true),
        )
        .unwrap();

        // use the selector register to save one fwCfgDmaAccess update cycle
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        assert_eq!(
            fw_cfg.data_offset,
            u32::try_from(FW_CFG_SIGNATURE_CONTENT.len()).unwrap()
        );

        let mut data = [0xCC; 0x1000];
        // Prepare to skip the first 4 bytes and ensure the offset is set accordingly
        update_fw_cfg_dma_access(
            &mem,
            0x800,
            payload_gpa,
            dma_gpa,
            AccessControl(0).with_read(true),
        )
        .unwrap();
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        assert_eq!(
            fw_cfg.data_offset,
            u32::try_from(FW_CFG_SIGNATURE_CONTENT.len()).unwrap()
        );

        let _ = mem.read(data.as_mut_bytes(), payload_gpa).unwrap();
        assert_eq!(data[..0x800], [0x0; 0x800]);
        assert_eq!(data[0x800..], [INIT_BYTE_VALUE; 0x800]);

        // Check that the memory is still contains the initial value
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0);
    }

    #[test]
    fn test_dma_invalid_memory_cursor_does_not_advance_over_payload_length() {
        let payload_gpa = GuestAddress(0x2000_u64);
        let dma_gpa = GuestAddress(0x4000_u64);
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            0x1000, /* Defines the DMA read length */
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        update_fw_cfg_dma_access(
            &mem,
            0x1000,
            GuestAddress(0x6000),
            dma_gpa,
            AccessControl(0).with_read(true),
        )
        .unwrap();

        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        assert_eq!(fw_cfg.data_offset, FW_CFG_SIGNATURE_CONTENT.len() as u32);
        // Check that the control field is reset to zero
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0x1);
    }

    #[test]
    fn test_dma_read_short_guest_write_advances_cursor_to_planned_end() {
        const DMA_LEN: usize = (FwCfg::BUFFER_SIZE * 2) + 0x20;
        let payload_bytes = [0xEF_u8; DMA_LEN];
        let payload_page_gpa = GuestAddress(0x2000_u64);
        let dma_gpa = GuestAddress(0x4000_u64);

        // Set skip to 8
        let (mem, mut fw_cfg) = setup_fw_cfg_dma_with_access_control(
            8, /* Defines the DMA skip length */
            payload_page_gpa,
            dma_gpa,
            AccessControl::new().with_skip(true),
        )
        .unwrap();

        // Add an item to fw_cfg
        let content = FwCfgContent::Bytes(payload_bytes.to_vec());
        let cfg_item = FwCfgItem {
            name: "big_payload".to_string(),
            content,
        };
        fw_cfg.add_item(cfg_item).unwrap();
        // select and advance cursor through executing the skip defined above
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_FILE_FIRST as u8, 0]);
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());

        // Update the FwCfgDmaAccess so that we produce an error for the last 16 byte
        let payload_gpa = GuestAddress(payload_page_gpa.0 + 0x1000 - (DMA_LEN as u64) + 0x18);
        update_fw_cfg_dma_access(
            &mem,
            DMA_LEN - 0x10,
            payload_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();

        let mut data = [0xCB; 0x1000];
        // Execute failing read
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());

        // Read the entire allocated page
        let _ = mem.read(data.as_mut_bytes(), payload_page_gpa).unwrap();
        // Ensure bytes up to the target GPA were not touched
        assert_eq!(
            data[..0x1000 - DMA_LEN + 0x18],
            [INIT_BYTE_VALUE; 0x1000 - DMA_LEN + 0x18]
        );
        // Ensure the payload was written until the failing write
        assert_eq!(data[0x1000 + 0x18 - DMA_LEN..], [0xEF; DMA_LEN - 0x18]);
        // Nevertheless the cursor should indicate we read all but the last 8 bytes
        assert_eq!(fw_cfg.data_offset, DMA_LEN as u32 - 0x8);
        // Check that the control field is reset to zero but contains the error bit
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0x1);

        // Let's get the remaining 8 bytes!
        update_fw_cfg_dma_access(
            &mem,
            FwCfg::BUFFER_SIZE,
            payload_page_gpa,
            dma_gpa,
            AccessControl::new().with_read(true),
        )
        .unwrap();
        fw_cfg.write(0, DMA_OFFSET + 4, &(dma_gpa.0 as u32).to_be_bytes());
        let mut data = [0xCB_u8; FwCfg::BUFFER_SIZE];
        // Read the entire allocated page
        let _ = mem.read(data.as_mut_bytes(), payload_page_gpa).unwrap();
        // Ensure the first 8 bytes read contain the payload
        assert_eq!(data[..0x08], [0xEF; 0x08]);
        assert_eq!(data[0x08..], [0x0; FwCfg::BUFFER_SIZE - 0x08]);

        // This time the cursor should indicate we read all bytes
        assert_eq!(fw_cfg.data_offset, DMA_LEN as u32);
        // Check that the control field is reset to zero, this time with no error
        let mut access_buffer = FwCfgDmaAccess {
            control: AccessControl(0xFFFF_FFFF),
            ..Default::default()
        }
        .to_be_bytes();
        let _ = mem.read(&mut access_buffer, dma_gpa);
        assert_eq!(FwCfgDmaAccess::from_be_bytes(&access_buffer).control.0, 0x0);
    }

    #[test]
    fn test_dma_signature() {
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));

        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        let mut buff = [0xDD_u8; 4];
        fw_cfg.read(0, DMA_OFFSET, &mut buff);
        assert_eq!(*b"QEMU", buff);
        let mut buff = [0xDD_u8; 1];
        fw_cfg.read(0, DMA_OFFSET, &mut buff);
        assert_eq!(*b"Q", buff);
        let mut buff = [0xDD_u8; 4];
        fw_cfg.read(0, DMA_OFFSET + 2, &mut buff);
        assert_eq!(*b"MU C", buff);
        let mut buff = [0xDD_u8; 4];
        fw_cfg.read(0, DMA_OFFSET + 4, &mut buff);
        assert_eq!(*b" CFG", buff);
        let mut buff = [0xDD_u8; 2];
        fw_cfg.read(0, DMA_OFFSET + 4, &mut buff);
        assert_eq!(*b" C", buff);
        let mut buff = [0xDD_u8; 2];
        fw_cfg.read(0, DMA_OFFSET + 6, &mut buff);
        assert_eq!(*b"FG", buff);
        let mut buff = [0xDD_u8; 1];
        fw_cfg.read(0, DMA_OFFSET + 7, &mut buff);
        assert_eq!(*b"G", buff);
    }

    #[test]
    fn test_register_invalid_reads_zero_buffer() {
        // Reads with unsupported size zero the whole buffer in QEMU. We mimic this behavior.
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        // Two byte read forbidden
        let mut buff = [0xEF; 2];
        fw_cfg.read(0, DATA_OFFSET, &mut buff);
        assert_eq!(fw_cfg.data_offset, 0);
        assert_eq!(buff, [0x0; 2]);
        // 4-byte read forbidden
        let mut buff = [0xEF; 4];
        fw_cfg.read(0, DATA_OFFSET, &mut buff);
        assert_eq!(buff, [0x0; 4]);
        assert_eq!(fw_cfg.data_offset, 0);
        // 1-byte read returns actual data
        let mut buff = [0xEF; 1];
        fw_cfg.read(0, DATA_OFFSET, &mut buff);
        assert_eq!(fw_cfg.data_offset, 1);
        assert_eq!(buff, [b'Q']);
    }

    #[test]
    fn test_register_qemu_selector_read_quirk() {
        // While defined as write-only, QEMU uses a port-mapping that leaves the select register
        // readable. For full compatibility we also allow reading from the selector register as a
        // quirk.
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        // 1-byte read returns actual data
        let mut buff = [0xEF; 1];
        fw_cfg.read(0, SELECTOR_OFFSET, &mut buff);
        assert_eq!(fw_cfg.data_offset, 1);
        assert_eq!(buff, [b'Q']);
        // Forbidden access zeros buffer similar to data register access. Offset isn't moved.
        let mut buff = [0xEF; 2];
        fw_cfg.read(0, SELECTOR_OFFSET, &mut buff);
        assert_eq!(fw_cfg.data_offset, 1);
        assert_eq!(buff, [0x0; 2]);
    }

    #[test]
    fn test_register_reads_past_eof_return_zero() {
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));
        fw_cfg.write(0, SELECTOR_OFFSET, &[FW_CFG_SIGNATURE as u8, 0]);
        let mut buff = [0xEF; 8];
        let max_offset = FW_CFG_SIGNATURE_CONTENT.len() as u32;
        for (offset, byte) in buff.iter_mut().enumerate() {
            fw_cfg.read(0, DATA_OFFSET, byte.as_mut_bytes());
            let expected_offset = if (offset as u32 + 1) < max_offset {
                offset as u32 + 1
            } else {
                max_offset
            };
            assert_eq!(fw_cfg.data_offset, expected_offset);
        }
        assert_eq!(buff[..4], FW_CFG_SIGNATURE_CONTENT);
        assert_eq!(buff[4..], [0; 4]);
    }

    #[test]
    fn test_register_reads_with_invalid_selector() {
        const SELECTOR_INITIALIZED_WITH_DEFAULT: u16 = 0x08;
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));
        fw_cfg.known_items[SELECTOR_INITIALIZED_WITH_DEFAULT as usize] = FwCfgContent::Slice(&[]);
        fw_cfg.write(0, SELECTOR_OFFSET, &[0xFF, 0]);
        let mut buff = [0xEF_u8; 8];
        for byte in buff.iter_mut() {
            fw_cfg.read(0, DATA_OFFSET, byte.as_mut_bytes());
            assert_eq!(fw_cfg.data_offset, 0);
        }
        assert_eq!(buff, [0; 8]);

        fw_cfg.write(
            0,
            SELECTOR_OFFSET,
            &SELECTOR_INITIALIZED_WITH_DEFAULT.to_le_bytes(),
        );
        let mut buff = [0xEF_u8; 8];
        for byte in buff.iter_mut() {
            fw_cfg.read(0, DATA_OFFSET, byte.as_mut_bytes());
            assert_eq!(fw_cfg.data_offset, 0);
        }
        assert_eq!(buff, [0; 8]);
    }

    #[test]
    fn test_register_writing_select_resets_internal_cursor() {
        let mut fw_cfg = FwCfg::new(GuestMemoryAtomic::new(GuestMemoryMmap::new()));
        let payload_bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let content = FwCfgContent::Bytes(payload_bytes.to_vec());
        let cfg_item = FwCfgItem {
            name: "payload".to_string(),
            content,
        };
        fw_cfg.add_item(cfg_item).unwrap();

        // read the same bytes twice, demonstrating that we can reset the cursor by selecting a new item.
        for _ in 0..2 {
            fw_cfg.write(0, SELECTOR_OFFSET, &FW_CFG_FILE_FIRST.to_le_bytes());
            assert_eq!(fw_cfg.data_offset, 0);
            let mut buffer = [0xEF_u8; 6];
            const MAX_INDEX: usize = 4;
            for index in 0..MAX_INDEX {
                fw_cfg.read(0, DATA_OFFSET, buffer[index].as_mut_bytes());
                assert_eq!(fw_cfg.data_offset as usize, index + 1);
            }
            assert_eq!(buffer[..MAX_INDEX], payload_bytes[..MAX_INDEX]);
            assert_eq!(buffer[MAX_INDEX..], [0xEF; 2]);
            assert_eq!(fw_cfg.data_offset, MAX_INDEX as u32);
        }
    }
}
