//! Append `SHF_ALLOC=0` metadata sections to a little-endian ELF file
//! in place. Class-aware (ELF32 + ELF64) so it works for both x86-64
//! hosted and xtensa esp32s3.
//!
//! Rationale: `object::write::elf::Writer` would want us to rebuild the
//! whole ELF section by section — fine in principle, large in code.
//! Since we only need to *add* sections (never modify existing ones
//! except for relocating `.shstrtab` to pick up new names), the
//! append-at-end approach is short and direct.
//!
//! Layout after attach:
//! ```text
//! [0, e_shoff_original):          unchanged bytes (header, program
//!                                 headers, original section data)
//! [e_shoff_original, e_shoff_new): old section header table (dead)
//!                                  + our new section payloads +
//!                                  new .shstrtab
//! e_shoff_new..:                   new section header table
//! ```

use anyhow::{Context, Result, bail};
use object::elf::{ET_DYN, ET_EXEC, SHT_PROGBITS};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Elf32,
    Elf64,
}

impl Class {
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            1 => Ok(Class::Elf32),
            2 => Ok(Class::Elf64),
            c => bail!("unknown ELF class {c}"),
        }
    }
    fn shdr_size(self) -> usize {
        match self {
            Class::Elf32 => 40,
            Class::Elf64 => 64,
        }
    }
    /// (e_shoff, e_shoff_size, e_shentsize, e_shnum, e_shstrndx).
    fn header_offsets(self) -> (usize, usize, usize, usize, usize) {
        match self {
            Class::Elf32 => (32, 4, 46, 48, 50),
            Class::Elf64 => (40, 8, 58, 60, 62),
        }
    }
}

pub struct NewSection<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
}

pub fn append_sections(input: &[u8], sections: &[NewSection<'_>]) -> Result<Vec<u8>> {
    if input.len() < 64 || input[..4] != ELF_MAGIC {
        bail!("not an ELF file");
    }
    let class = Class::from_byte(input[4])?;
    if input[5] != 1 {
        bail!("only ELF little-endian supported");
    }

    let e_type = u16::from_le_bytes(input[16..18].try_into().unwrap());
    if !(e_type == ET_EXEC || e_type == ET_DYN) {
        bail!("unexpected ELF type {e_type:#x}; expected EXEC or DYN");
    }

    let (shoff_o, shoff_sz, shentsize_o, shnum_o, shstrndx_o) = class.header_offsets();
    let e_shoff = match shoff_sz {
        4 => u32::from_le_bytes(input[shoff_o..shoff_o + 4].try_into().unwrap()) as usize,
        8 => u64::from_le_bytes(input[shoff_o..shoff_o + 8].try_into().unwrap()) as usize,
        n => bail!("bad shoff_sz {n}"),
    };
    let e_shentsize =
        u16::from_le_bytes(input[shentsize_o..shentsize_o + 2].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(input[shnum_o..shnum_o + 2].try_into().unwrap()) as usize;
    let e_shstrndx =
        u16::from_le_bytes(input[shstrndx_o..shstrndx_o + 2].try_into().unwrap()) as usize;
    let expected_shentsize = class.shdr_size();
    if e_shentsize != expected_shentsize {
        bail!("unexpected e_shentsize {e_shentsize}; {class:?} should be {expected_shentsize}");
    }
    if e_shstrndx >= e_shnum {
        bail!("e_shstrndx out of range");
    }

    let sh_table_start = e_shoff;
    let sh_table_end = e_shoff + e_shnum * e_shentsize;
    if sh_table_end > input.len() {
        bail!("truncated section header table");
    }

    // Read .shstrtab's sh_offset / sh_size from its section header.
    // Field offsets within the shdr: sh_offset starts at byte 16
    // (ELF32) or 24 (ELF64); sh_size right after, same width.
    let shstrtab_hdr_off = e_shoff + e_shstrndx * e_shentsize;
    let (shoffset_field, sfield_size) = match class {
        Class::Elf32 => (16, 4),
        Class::Elf64 => (24, 8),
    };
    let shstrtab_sh_offset = read_field(input, shstrtab_hdr_off + shoffset_field, sfield_size)?;
    let shstrtab_sh_size =
        read_field(input, shstrtab_hdr_off + shoffset_field + sfield_size, sfield_size)?;
    if shstrtab_sh_offset + shstrtab_sh_size > input.len() {
        bail!("truncated .shstrtab");
    }
    let old_shstrtab = &input[shstrtab_sh_offset..shstrtab_sh_offset + shstrtab_sh_size];

    let mut new_shstrtab = old_shstrtab.to_vec();
    let mut name_offsets: Vec<u32> = Vec::with_capacity(sections.len());
    for s in sections {
        name_offsets.push(new_shstrtab.len() as u32);
        new_shstrtab.extend_from_slice(s.name.as_bytes());
        new_shstrtab.push(0);
    }

    let mut out = input[..sh_table_start].to_vec();

    let mut payload_offsets: Vec<usize> = Vec::with_capacity(sections.len());
    for s in sections {
        align_up(&mut out, 8);
        payload_offsets.push(out.len());
        out.extend_from_slice(s.data);
    }

    let new_shstrtab_offset = out.len();
    out.extend_from_slice(&new_shstrtab);

    let mut new_sh_table = input[sh_table_start..sh_table_end].to_vec();

    // Update shstrtab entry's sh_offset / sh_size in place.
    let shstrtab_in_new = e_shstrndx * e_shentsize;
    write_field(
        &mut new_sh_table,
        shstrtab_in_new + shoffset_field,
        sfield_size,
        new_shstrtab_offset as u64,
    );
    write_field(
        &mut new_sh_table,
        shstrtab_in_new + shoffset_field + sfield_size,
        sfield_size,
        new_shstrtab.len() as u64,
    );

    // Append new shdrs.
    for (i, s) in sections.iter().enumerate() {
        new_sh_table.extend_from_slice(&build_shdr(
            class,
            name_offsets[i],
            payload_offsets[i] as u64,
            s.data.len() as u64,
        ));
    }

    align_up(&mut out, 8);
    let new_shoff = out.len();
    out.extend_from_slice(&new_sh_table);

    let new_shnum = e_shnum + sections.len();
    write_field(&mut out, shoff_o, shoff_sz, new_shoff as u64);
    out[shnum_o..shnum_o + 2].copy_from_slice(&(new_shnum as u16).to_le_bytes());

    Ok(out)
}

/// Build one section header for a no-alloc PROGBITS section.
fn build_shdr(class: Class, sh_name: u32, sh_offset: u64, sh_size: u64) -> Vec<u8> {
    match class {
        Class::Elf32 => {
            let mut e = vec![0u8; 40];
            e[0..4].copy_from_slice(&sh_name.to_le_bytes());
            e[4..8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
            // sh_flags=0, sh_addr=0
            e[16..20].copy_from_slice(&(sh_offset as u32).to_le_bytes());
            e[20..24].copy_from_slice(&(sh_size as u32).to_le_bytes());
            // sh_link=0, sh_info=0
            e[32..36].copy_from_slice(&1u32.to_le_bytes()); // sh_addralign
            // sh_entsize=0
            e
        }
        Class::Elf64 => {
            let mut e = vec![0u8; 64];
            e[0..4].copy_from_slice(&sh_name.to_le_bytes());
            e[4..8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
            // sh_flags (8) = 0, sh_addr (8) = 0
            e[24..32].copy_from_slice(&sh_offset.to_le_bytes());
            e[32..40].copy_from_slice(&sh_size.to_le_bytes());
            // sh_link, sh_info = 0
            e[48..56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
            // sh_entsize=0
            e
        }
    }
}

fn read_field(buf: &[u8], offset: usize, size: usize) -> Result<usize> {
    Ok(match size {
        4 => u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize,
        8 => u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap()) as usize,
        n => bail!("bad read_field size {n}"),
    })
}

fn write_field(buf: &mut [u8], offset: usize, size: usize, value: u64) {
    match size {
        4 => buf[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes()),
        8 => buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes()),
        _ => unreachable!(),
    }
}

fn align_up(buf: &mut Vec<u8>, align: usize) {
    let pad = (align - (buf.len() % align)) % align;
    buf.resize(buf.len() + pad, 0);
}

/// Read a named SHF_ALLOC=0 metadata section back out of an ELF.
/// Inverse of `append_sections`.
pub fn read_section<'a>(input: &'a [u8], section_name: &str) -> Result<Option<&'a [u8]>> {
    let elf = object::File::parse(input).context("parse ELF")?;
    use object::{Object, ObjectSection};
    let Some(sec) = elf.section_by_name(section_name) else {
        return Ok(None);
    };
    let data = sec
        .data()
        .map_err(|e| anyhow::anyhow!("read section {section_name}: {e}"))?;
    Ok(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_against_e2e_fixture() {
        let app_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../e2e/x86/target/debug/app");
        if !app_path.is_file() {
            eprintln!("skipping: e2e fixture not built");
            return;
        }
        let input = std::fs::read(&app_path).unwrap();
        let sections = [
            NewSection {
                name: ".graft.test1",
                data: b"hello manifest",
            },
            NewSection {
                name: ".graft.test2",
                data: b"hello symhash \xAA\xBB\xCC",
            },
        ];
        let out = append_sections(&input, &sections).unwrap();

        object::File::parse(&*out).expect("output parses as ELF");

        let m = read_section(&out, ".graft.test1").unwrap().unwrap();
        assert_eq!(m, b"hello manifest");
        let s = read_section(&out, ".graft.test2").unwrap().unwrap();
        assert_eq!(s, b"hello symhash \xAA\xBB\xCC");

        assert!(read_section(&out, ".nope").unwrap().is_none());
    }
}
