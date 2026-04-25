//! Append `SHF_ALLOC=0` metadata sections to an ELF64-LE file in place.
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
//!
//! Limited to ELF64 little-endian for now — the host prototype only
//! needs this shape. Xtensa is LE32; we'll generalize when porting to
//! ESP32-S3 (M2/M3).

use anyhow::{Context, Result, bail};
use object::elf::{ET_DYN, ET_EXEC, SHT_PROGBITS};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

pub struct NewSection<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
}

pub fn append_sections(input: &[u8], sections: &[NewSection<'_>]) -> Result<Vec<u8>> {
    if input.len() < 64 || input[..4] != ELF_MAGIC {
        bail!("not an ELF file");
    }
    // ELFCLASS64=2, ELFDATA2LSB=1
    if input[4] != 2 { bail!("only ELF64 supported"); }
    if input[5] != 1 { bail!("only ELF little-endian supported"); }

    let e_type = u16::from_le_bytes(input[16..18].try_into().unwrap());
    if !(e_type == ET_EXEC || e_type == ET_DYN) {
        // Relocatable objects have their own conventions; we target final ELFs.
        bail!("unexpected ELF type {e_type:#x}; expected EXEC or DYN");
    }

    // ELF64 header fields we need.
    let e_shoff = u64::from_le_bytes(input[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(input[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(input[60..62].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_le_bytes(input[62..64].try_into().unwrap()) as usize;

    if e_shentsize != 64 { bail!("unexpected e_shentsize {e_shentsize}; ELF64 should be 64"); }
    if e_shstrndx >= e_shnum { bail!("e_shstrndx out of range"); }

    let sh_table_start = e_shoff;
    let sh_table_end = e_shoff + e_shnum * e_shentsize;
    if sh_table_end > input.len() { bail!("truncated section header table"); }

    // Extract old .shstrtab so we can re-emit it with new names appended.
    let shstrtab_hdr_off = e_shoff + e_shstrndx * e_shentsize;
    let shstrtab_sh_offset =
        u64::from_le_bytes(input[shstrtab_hdr_off + 24..shstrtab_hdr_off + 32].try_into().unwrap()) as usize;
    let shstrtab_sh_size =
        u64::from_le_bytes(input[shstrtab_hdr_off + 32..shstrtab_hdr_off + 40].try_into().unwrap()) as usize;
    if shstrtab_sh_offset + shstrtab_sh_size > input.len() {
        bail!("truncated .shstrtab");
    }
    let old_shstrtab = &input[shstrtab_sh_offset..shstrtab_sh_offset + shstrtab_sh_size];

    // Build new .shstrtab: old + our names (each null-terminated, record offset).
    let mut new_shstrtab = old_shstrtab.to_vec();
    let mut name_offsets: Vec<u32> = Vec::with_capacity(sections.len());
    for s in sections {
        name_offsets.push(new_shstrtab.len() as u32);
        new_shstrtab.extend_from_slice(s.name.as_bytes());
        new_shstrtab.push(0);
    }

    // Start with the unchanged prefix up to (but not including) the old
    // section header table. We'll append everything else.
    let mut out = input[..sh_table_start].to_vec();

    // Append each new section's payload, recording the file offset.
    let mut payload_offsets: Vec<usize> = Vec::with_capacity(sections.len());
    for s in sections {
        align_up(&mut out, 8);
        payload_offsets.push(out.len());
        out.extend_from_slice(s.data);
    }

    // Append new .shstrtab data (1-byte alignment is conventional).
    let new_shstrtab_offset = out.len();
    out.extend_from_slice(&new_shstrtab);

    // Build new section header table: original entries (with the
    // shstrtab entry's sh_offset/sh_size updated), then our new entries.
    let mut new_sh_table = input[sh_table_start..sh_table_end].to_vec();
    // Update shstrtab entry.
    let shstrtab_in_new = e_shstrndx * e_shentsize;
    new_sh_table[shstrtab_in_new + 24..shstrtab_in_new + 32]
        .copy_from_slice(&(new_shstrtab_offset as u64).to_le_bytes());
    new_sh_table[shstrtab_in_new + 32..shstrtab_in_new + 40]
        .copy_from_slice(&(new_shstrtab.len() as u64).to_le_bytes());

    // Append new entries.
    for (i, s) in sections.iter().enumerate() {
        let mut entry = vec![0u8; 64];
        // sh_name
        entry[0..4].copy_from_slice(&name_offsets[i].to_le_bytes());
        // sh_type = SHT_PROGBITS
        entry[4..8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
        // sh_flags = 0 (no SHF_ALLOC, no SHF_WRITE, no SHF_EXEC)
        // sh_addr = 0 (not loaded)
        // sh_offset
        entry[24..32].copy_from_slice(&(payload_offsets[i] as u64).to_le_bytes());
        // sh_size
        entry[32..40].copy_from_slice(&(s.data.len() as u64).to_le_bytes());
        // sh_link / sh_info = 0
        // sh_addralign = 1
        entry[48..56].copy_from_slice(&1u64.to_le_bytes());
        // sh_entsize = 0
        new_sh_table.extend_from_slice(&entry);
    }

    // Place the new section header table at the current end of file,
    // 8-aligned.
    align_up(&mut out, 8);
    let new_shoff = out.len();
    out.extend_from_slice(&new_sh_table);

    // Patch ELF header.
    let new_shnum = e_shnum + sections.len();
    out[40..48].copy_from_slice(&(new_shoff as u64).to_le_bytes());
    out[60..62].copy_from_slice(&(new_shnum as u16).to_le_bytes());

    Ok(out)
}

fn align_up(buf: &mut Vec<u8>, align: usize) {
    let pad = (align - (buf.len() % align)) % align;
    buf.resize(buf.len() + pad, 0);
}

/// Read a named SHF_ALLOC=0 metadata section back out of an ELF.
/// Inverse of `append_sections` — used by overlay mode to load base's
/// `.graft.manifest` / `.graft.symhash`.
pub fn read_section<'a>(input: &'a [u8], section_name: &str) -> Result<Option<&'a [u8]>> {
    let elf = object::File::parse(input).context("parse ELF")?;
    use object::{Object, ObjectSection};
    let Some(sec) = elf.section_by_name(section_name) else {
        return Ok(None);
    };
    let data = sec.data().map_err(|e| anyhow::anyhow!("read section {section_name}: {e}"))?;
    Ok(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_against_e2e_fixture() {
        // If the e2e fixture is built, take its app binary, attach two
        // dummy sections, verify (a) the output still parses as an ELF
        // via the object crate and (b) the sections we added can be
        // read back.
        let app_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../e2e/x86/target/debug/app");
        if !app_path.is_file() {
            eprintln!("skipping: e2e fixture not built");
            return;
        }
        let input = std::fs::read(&app_path).unwrap();
        // Use names that won't collide with anything a `GRAFT=base` build
        // would have already attached to the fixture.
        let sections = [
            NewSection { name: ".graft.test1", data: b"hello manifest" },
            NewSection { name: ".graft.test2", data: b"hello symhash \xAA\xBB\xCC" },
        ];
        let out = append_sections(&input, &sections).unwrap();

        // Must still parse as an ELF.
        object::File::parse(&*out).expect("output parses as ELF");

        // Read both sections back.
        let m = read_section(&out, ".graft.test1").unwrap().unwrap();
        assert_eq!(m, b"hello manifest");
        let s = read_section(&out, ".graft.test2").unwrap().unwrap();
        assert_eq!(s, b"hello symhash \xAA\xBB\xCC");

        // Non-existent section returns Ok(None).
        assert!(read_section(&out, ".nope").unwrap().is_none());
    }
}
