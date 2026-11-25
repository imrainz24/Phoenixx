//! PE loader-lifecycle audit for Project Phoenix.
//!
//! Builds a data-only plan for section protections, TLS callbacks, x64 exception
//! metadata, and entry-point readiness. It deliberately does not change host
//! page protections, invoke callbacks, register unwind tables, or execute code.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    Truncated(&'static str),
    Invalid(&'static str),
    Overflow,
    UnsupportedMachine(u16),
    UnsupportedOptionalHeader(u16),
    DirectoryOutsideImage { index: usize },
    RvaNotFileBacked { rva: u32 },
    UnterminatedTlsCallbackArray,
    InvalidTlsCallbackVa(u64),
    InvalidRuntimeFunction { index: u32 },
    InvalidUnwindInfo { rva: u32 },
    InvalidTlsAddress { field: &'static str, va: u64 },
    TlsCallbackNotExecutable { rva: u32 },
    InvalidLoadConfig(&'static str),
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for LifecycleError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionProtection {
    pub name: [u8; 8],
    pub virtual_address: u32,
    pub mapped_size: u32,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPlan {
    pub directory: DataDirectory,
    pub raw_data_start_rva: Option<u32>,
    pub raw_data_size: u64,
    pub index_rva: Option<u32>,
    pub zero_fill_size: u32,
    pub callback_array_rva: Option<u32>,
    pub callback_rvas: Vec<u32>,
    pub callback_array_terminated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadConfigPlan {
    pub directory: DataDirectory,
    pub declared_size: u32,
    pub security_cookie_rva: Option<u32>,
    pub guard_cf_check_rva: Option<u32>,
    pub guard_cf_dispatch_rva: Option<u32>,
    pub guard_cf_function_table_rva: Option<u32>,
    pub guard_cf_function_count: u64,
    pub guard_flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionPlan {
    pub directory: DataDirectory,
    pub runtime_function_entries: u32,
    pub validated_unwind_info_records: u32,
    pub chained_records: u32,
    pub handler_records: u32,
    pub directory_size_aligned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderLifecyclePlan {
    pub preferred_base: u64,
    pub image_size: u32,
    pub entry_point_rva: u32,
    pub sections: Vec<SectionProtection>,
    pub tls: Option<TlsPlan>,
    pub exception: Option<ExceptionPlan>,
    pub import_directory: DataDirectory,
    pub relocation_directory: DataDirectory,
    pub load_config_directory: DataDirectory,
    pub load_config: Option<LoadConfigPlan>,
    pub entry_point_in_executable_section: bool,
    pub requires_relocations: bool,
}

fn u16_at(data: &[u8], off: usize) -> Result<u16, LifecycleError> {
    let b=data.get(off..off.checked_add(2).ok_or(LifecycleError::Overflow)?)
        .ok_or(LifecycleError::Truncated("u16"))?;
    Ok(u16::from_le_bytes([b[0],b[1]]))
}
fn u32_at(data: &[u8], off: usize) -> Result<u32, LifecycleError> {
    let b=data.get(off..off.checked_add(4).ok_or(LifecycleError::Overflow)?)
        .ok_or(LifecycleError::Truncated("u32"))?;
    Ok(u32::from_le_bytes([b[0],b[1],b[2],b[3]]))
}
fn u64_at(data: &[u8], off: usize) -> Result<u64, LifecycleError> {
    let b=data.get(off..off.checked_add(8).ok_or(LifecycleError::Overflow)?)
        .ok_or(LifecycleError::Truncated("u64"))?;
    Ok(u64::from_le_bytes(b.try_into().unwrap()))
}

struct PeLayout {
    image_base: u64,
    image_size: u32,
    headers_size: u32,
    entry_rva: u32,
    directories: Vec<DataDirectory>,
    sections: Vec<(u32,u32,u32,u32,u32,[u8;8])>, // VA, virtual size, raw size, raw pointer, characteristics, name
}

fn parse_layout(file: &[u8]) -> Result<PeLayout, LifecycleError> {
    if file.get(0..2) != Some(&b"MZ"[..]) { return Err(LifecycleError::Invalid("missing DOS signature")); }
    let pe = u32_at(file,0x3c)? as usize;
    if file.get(pe..pe.checked_add(4).ok_or(LifecycleError::Overflow)?) != Some(&b"PE\0\0"[..]) {
        return Err(LifecycleError::Invalid("missing PE signature"));
    }
    let coff=pe.checked_add(4).ok_or(LifecycleError::Overflow)?;
    let machine=u16_at(file,coff)?;
    if machine != 0x8664 { return Err(LifecycleError::UnsupportedMachine(machine)); }
    let count=u16_at(file,coff+2)? as usize;
    let opt_size=u16_at(file,coff+16)? as usize;
    let opt=coff.checked_add(20).ok_or(LifecycleError::Overflow)?;
    if u16_at(file,opt)? != 0x20b { return Err(LifecycleError::UnsupportedOptionalHeader(u16_at(file,opt)?)); }
    let entry=u32_at(file,opt+16)?;
    let image_base=u64_at(file,opt+24)?;
    let image_size=u32_at(file,opt+56)?;
    let headers_size=u32_at(file,opt+60)?;
    if image_size==0 || entry>=image_size { return Err(LifecycleError::Invalid("invalid image size or entry point")); }
    let dir_count=u32_at(file,opt+108)? as usize;
    let dirs_start=opt.checked_add(112).ok_or(LifecycleError::Overflow)?;
    let max_dirs=opt_size.saturating_sub(112)/8;
    if dir_count>max_dirs { return Err(LifecycleError::Truncated("data directories")); }
    let mut directories=Vec::with_capacity(dir_count);
    for i in 0..dir_count {
        let off=dirs_start.checked_add(i.checked_mul(8).ok_or(LifecycleError::Overflow)?)
            .ok_or(LifecycleError::Overflow)?;
        directories.push(DataDirectory { rva:u32_at(file,off)?, size:u32_at(file,off+4)? });
    }
    let section_table=opt.checked_add(opt_size).ok_or(LifecycleError::Overflow)?;
    let table_end=section_table.checked_add(count.checked_mul(40).ok_or(LifecycleError::Overflow)?)
        .ok_or(LifecycleError::Overflow)?;
    if table_end>file.len() { return Err(LifecycleError::Truncated("section table")); }
    let mut sections=Vec::with_capacity(count);
    for i in 0..count {
        let off=section_table+i*40;
        let mut name=[0u8;8]; name.copy_from_slice(&file[off..off+8]);
        sections.push((u32_at(file,off+12)?,u32_at(file,off+8)?,u32_at(file,off+16)?,u32_at(file,off+20)?,u32_at(file,off+36)?,name));
    }
    Ok(PeLayout { image_base,image_size,headers_size,entry_rva:entry,directories,sections })
}

fn directory(layout:&PeLayout,index:usize)->DataDirectory {
    layout.directories.get(index).copied().unwrap_or(DataDirectory{rva:0,size:0})
}

fn rva_to_offset(layout:&PeLayout,file:&[u8],rva:u32,length:usize)->Result<usize,LifecycleError> {
    let end=rva.checked_add(u32::try_from(length).map_err(|_|LifecycleError::Overflow)?)
        .ok_or(LifecycleError::Overflow)?;
    if end>layout.image_size { return Err(LifecycleError::RvaNotFileBacked{rva}); }
    if rva<layout.headers_size {
        let off=rva as usize;
        if off.checked_add(length).filter(|v|*v<=file.len()).is_some(){return Ok(off);}
    }
    for (va,vs,raw,raw_pointer,_,_) in &layout.sections {
        let span=(*vs).max(*raw);
        if rva>=*va {
            let delta=rva-*va;
            let requested = u32::try_from(length).map_err(|_| LifecycleError::Overflow)?;
            if delta.checked_add(requested).is_some_and(|v|v<=*raw) {
                let raw_off=*raw_pointer as usize;
                return raw_off.checked_add(delta as usize)
                    .filter(|off|off.checked_add(length).is_some_and(|v|v<=file.len()))
                    .ok_or(LifecycleError::RvaNotFileBacked{rva});
            }
            if delta<span { return Err(LifecycleError::RvaNotFileBacked{rva}); }
        }
    }
    Err(LifecycleError::RvaNotFileBacked{rva})
}


fn va_to_rva(layout: &PeLayout, va: u64, field: &'static str) -> Result<u32, LifecycleError> {
    let delta = va.checked_sub(layout.image_base)
        .ok_or(LifecycleError::InvalidTlsAddress { field, va })?;
    let rva = u32::try_from(delta)
        .map_err(|_| LifecycleError::InvalidTlsAddress { field, va })?;
    if rva >= layout.image_size {
        return Err(LifecycleError::InvalidTlsAddress { field, va });
    }
    Ok(rva)
}

fn is_executable_rva(sections: &[SectionProtection], rva: u32) -> bool {
    sections.iter().any(|s| s.execute && rva >= s.virtual_address
        && rva < s.virtual_address.saturating_add(s.mapped_size))
}

// TLS AddressOfIndex points to a 4-byte variable in the mapped image. It may
// live in a section's zero-initialized virtual tail, so it must not be required
// to have corresponding bytes in the on-disk file.
fn is_writable_mapped_range(sections: &[SectionProtection], rva: u32, length: u32) -> bool {
    let Some(end) = rva.checked_add(length) else { return false; };
    sections.iter().any(|s| {
        let Some(section_end) = s.virtual_address.checked_add(s.mapped_size) else {
            return false;
        };
        s.write && rva >= s.virtual_address && end <= section_end && length != 0
    })
}

fn optional_load_config_va(
    layout: &PeLayout, sections: &[SectionProtection], file: &[u8],
    base_off: usize, declared_size: u32, field_off: usize,
    field_name: &'static str, writable: bool, executable: bool,
) -> Result<Option<u32>, LifecycleError> {
    if (declared_size as usize) < field_off + 8 { return Ok(None); }
    let va = u64_at(file, base_off.checked_add(field_off).ok_or(LifecycleError::Overflow)?)?;
    if va == 0 { return Ok(None); }
    let rva = va_to_rva(layout, va, field_name)
        .map_err(|_| LifecycleError::InvalidLoadConfig(field_name))?;
    if writable && !is_writable_mapped_range(sections, rva, 8) {
        return Err(LifecycleError::InvalidLoadConfig(field_name));
    }
    if executable && !is_executable_rva(sections, rva) {
        return Err(LifecycleError::InvalidLoadConfig(field_name));
    }
    Ok(Some(rva))
}

fn parse_load_config(
    layout: &PeLayout, sections: &[SectionProtection], file: &[u8],
    directory: DataDirectory,
) -> Result<Option<LoadConfigPlan>, LifecycleError> {
    if directory.rva == 0 || directory.size == 0 { return Ok(None); }
    if directory.size < 4 { return Err(LifecycleError::InvalidLoadConfig("directory smaller than Size")); }
    let off = rva_to_offset(layout, file, directory.rva, 4)
        .map_err(|_| LifecycleError::InvalidLoadConfig("directory is not file-backed"))?;
    let declared_size = u32_at(file, off)?;
    if declared_size < 4 || declared_size > directory.size {
        return Err(LifecycleError::InvalidLoadConfig("invalid declared structure size"));
    }
    let security_cookie_rva = optional_load_config_va(layout, sections, file, off, declared_size, 88,
        "SecurityCookie", true, false)?;
    // These are image VAs naming Guard CF pointer locations. Validate that each
    // target belongs to the image, but do not assume its section must be writable:
    // toolchains/platform images can place these slots in different mapped sections.
    let guard_cf_check_rva = optional_load_config_va(layout, sections, file, off, declared_size, 112,
        "GuardCFCheckFunctionPointer", false, false)?;
    let guard_cf_dispatch_rva = optional_load_config_va(layout, sections, file, off, declared_size, 120,
        "GuardCFDispatchFunctionPointer", false, false)?;
    let guard_cf_function_table_rva = optional_load_config_va(layout, sections, file, off, declared_size, 128,
        "GuardCFFunctionTable", false, false)?;
    let guard_cf_function_count = if declared_size as usize >= 144 {
        u64_at(file, off.checked_add(136).ok_or(LifecycleError::Overflow)?)?
    } else { 0 };
    let guard_flags = if declared_size as usize >= 148 {
        u32_at(file, off.checked_add(144).ok_or(LifecycleError::Overflow)?)?
    } else { 0 };
    if guard_cf_function_count != 0 {
        let table_rva = guard_cf_function_table_rva
            .ok_or(LifecycleError::InvalidLoadConfig("Guard CF count without function table"))?;
        let extra = ((guard_flags >> 28) & 0x0f) as usize;
        let stride = 4usize.checked_add(extra).ok_or(LifecycleError::Overflow)?;
        let bytes = usize::try_from(guard_cf_function_count).map_err(|_| LifecycleError::Overflow)?
            .checked_mul(stride).ok_or(LifecycleError::Overflow)?;
        rva_to_offset(layout, file, table_rva, bytes)
            .map_err(|_| LifecycleError::InvalidLoadConfig("Guard CF function table is not file-backed"))?;
    }
    Ok(Some(LoadConfigPlan { directory, declared_size, security_cookie_rva,
        guard_cf_check_rva, guard_cf_dispatch_rva, guard_cf_function_table_rva,
        guard_cf_function_count, guard_flags }))
}

fn validate_unwind_info(
    layout: &PeLayout,
    file: &[u8],
    unwind_rva: u32,
) -> Result<(bool, bool), LifecycleError> {
    let off = rva_to_offset(layout, file, unwind_rva, 4)
        .map_err(|_| LifecycleError::InvalidUnwindInfo { rva: unwind_rva })?;
    let version_flags = file[off];
    let version = version_flags & 0x07;
    let flags = version_flags >> 3;
    if version != 1 && version != 2 { return Err(LifecycleError::InvalidUnwindInfo { rva: unwind_rva }); }
    // UNW_FLAG_CHAININFO cannot be combined with an exception/unwind handler.
    if flags & !0x07 != 0 || (flags & 0x04 != 0 && flags & 0x03 != 0) {
        return Err(LifecycleError::InvalidUnwindInfo { rva: unwind_rva });
    }
    let code_count = file[off + 2] as usize;
    let codes_bytes = code_count.checked_mul(2).ok_or(LifecycleError::Overflow)?;
    let aligned_codes = codes_bytes.checked_add(3).ok_or(LifecycleError::Overflow)? & !3;
    let trailer_rva = unwind_rva.checked_add(4)
        .and_then(|v| v.checked_add(u32::try_from(aligned_codes).ok()?))
        .ok_or(LifecycleError::Overflow)?;
    let trailer_len = if flags & 0x04 != 0 { 12 } else if flags & 0x03 != 0 { 4 } else { 0 };
    if trailer_len != 0 {
        let trailer_off = rva_to_offset(layout, file, trailer_rva, trailer_len)
            .map_err(|_| LifecycleError::InvalidUnwindInfo { rva: unwind_rva })?;
        if flags & 0x04 != 0 {
            let begin = u32_at(file, trailer_off)?;
            let end = u32_at(file, trailer_off + 4)?;
            let chained_unwind = u32_at(file, trailer_off + 8)?;
            if begin >= end || end > layout.image_size || chained_unwind >= layout.image_size {
                return Err(LifecycleError::InvalidUnwindInfo { rva: unwind_rva });
            }
        } else {
            let handler = u32_at(file, trailer_off)?;
            if handler >= layout.image_size {
                return Err(LifecycleError::InvalidUnwindInfo { rva: unwind_rva });
            }
        }
    } else {
        // Ensure the complete unwind-code array is file-backed even without a trailer.
        let total = 4usize.checked_add(aligned_codes).ok_or(LifecycleError::Overflow)?;
        rva_to_offset(layout, file, unwind_rva, total)
            .map_err(|_| LifecycleError::InvalidUnwindInfo { rva: unwind_rva })?;
    }
    Ok((flags & 0x04 != 0, flags & 0x03 != 0))
}

pub fn build_loader_lifecycle_plan(file:&[u8])->Result<LoaderLifecyclePlan,LifecycleError>{
    let layout=parse_layout(file)?;
    let mut sections=Vec::with_capacity(layout.sections.len());
    for (va,vs,raw,_raw_pointer,chars,name) in &layout.sections {
        sections.push(SectionProtection {
            name:*name, virtual_address:*va, mapped_size:(*vs).max(*raw),
            read:chars&0x4000_0000!=0, write:chars&0x8000_0000!=0,
            execute:chars&0x2000_0000!=0,
        });
    }
    let import_directory=directory(&layout,1);
    let exception_dir=directory(&layout,3);
    let relocation_directory=directory(&layout,5);
    let tls_dir=directory(&layout,9);
    let load_config_directory=directory(&layout,10);
    let load_config=parse_load_config(&layout,&sections,file,load_config_directory)?;

    let tls=if tls_dir.rva==0 || tls_dir.size==0 {None} else {
        if tls_dir.size<40 {return Err(LifecycleError::Invalid("TLS directory smaller than IMAGE_TLS_DIRECTORY64"));}
        let off=rva_to_offset(&layout,file,tls_dir.rva,40)?;
        let raw_start_va=u64_at(file,off)?;
        let raw_end_va=u64_at(file,off+8)?;
        let index_va=u64_at(file,off+16)?;
        let callbacks_va=u64_at(file,off+24)?;
        let zero_fill_size=u32_at(file,off+32)?;
        let (raw_data_start_rva,raw_data_size)=if raw_start_va==0 && raw_end_va==0 {(None,0)} else {
            let start=va_to_rva(&layout,raw_start_va,"TLS raw-data start")?;
            let end_delta=raw_end_va.checked_sub(layout.image_base)
                .ok_or(LifecycleError::InvalidTlsAddress{field:"TLS raw-data end",va:raw_end_va})?;
            let end=u32::try_from(end_delta)
                .map_err(|_|LifecycleError::InvalidTlsAddress{field:"TLS raw-data end",va:raw_end_va})?;
            if end<start || end>layout.image_size {
                return Err(LifecycleError::InvalidTlsAddress{field:"TLS raw-data end",va:raw_end_va});
            }
            (Some(start),(end-start) as u64)
        };
        let index_rva=if index_va==0 {None} else {
            let rva=va_to_rva(&layout,index_va,"TLS index")?;
            if !is_writable_mapped_range(&sections, rva, 4) {
                return Err(LifecycleError::InvalidTlsAddress{field:"TLS index",va:index_va});
            }
            Some(rva)
        };
        let (callback_array_rva,callback_rvas,terminated)=if callbacks_va==0 {(None,Vec::new(),true)} else {
            let array_rva=va_to_rva(&layout,callbacks_va,"TLS callback array")?;
            let mut callbacks=Vec::new();
            let mut terminated=false;
            for i in 0..4096usize {
                let rva=array_rva.checked_add(u32::try_from(i*8).map_err(|_|LifecycleError::Overflow)?)
                    .ok_or(LifecycleError::Overflow)?;
                let ptr_off=rva_to_offset(&layout,file,rva,8)?;
                let callback_va=u64_at(file,ptr_off)?;
                if callback_va==0 {terminated=true;break;}
                let cb_rva=va_to_rva(&layout,callback_va,"TLS callback")?;
                if !is_executable_rva(&sections,cb_rva) {
                    return Err(LifecycleError::TlsCallbackNotExecutable{rva:cb_rva});
                }
                callbacks.push(cb_rva);
            }
            (Some(array_rva),callbacks,terminated)
        };
        if !terminated {return Err(LifecycleError::UnterminatedTlsCallbackArray);}
        Some(TlsPlan{directory:tls_dir,raw_data_start_rva,raw_data_size,index_rva,zero_fill_size,
            callback_array_rva,callback_rvas,callback_array_terminated:terminated})
    };

    let exception=if exception_dir.rva==0 || exception_dir.size==0 {None} else {
        if exception_dir.size%12!=0 {return Err(LifecycleError::Invalid("x64 exception directory size is not a multiple of 12"));}
        let count=exception_dir.size/12;
        let off=rva_to_offset(&layout,file,exception_dir.rva,exception_dir.size as usize)?;
        let mut previous_begin=0u32;
        let mut validated=0u32;
        let mut chained=0u32;
        let mut handlers=0u32;
        for i in 0..count {
            let entry_off=off.checked_add((i as usize).checked_mul(12).ok_or(LifecycleError::Overflow)?)
                .ok_or(LifecycleError::Overflow)?;
            let begin=u32_at(file,entry_off)?;
            let end=u32_at(file,entry_off+4)?;
            let unwind=u32_at(file,entry_off+8)?;
            if begin>=end || end>layout.image_size || unwind>=layout.image_size
                || (i>0 && begin<previous_begin) {
                return Err(LifecycleError::InvalidRuntimeFunction{index:i});
            }
            let (has_chain,has_handler)=validate_unwind_info(&layout,file,unwind)
                .map_err(|_|LifecycleError::InvalidRuntimeFunction{index:i})?;
            if has_chain {chained+=1;} if has_handler {handlers+=1;}
            validated+=1;
            previous_begin=begin;
        }
        Some(ExceptionPlan{directory:exception_dir,runtime_function_entries:count,
            validated_unwind_info_records:validated,chained_records:chained,
            handler_records:handlers,directory_size_aligned:true})
    };
    let entry_point_in_executable_section=is_executable_rva(&sections,layout.entry_rva);
    Ok(LoaderLifecyclePlan{
        preferred_base:layout.image_base,image_size:layout.image_size,
        entry_point_rva:layout.entry_rva,sections,tls,exception,
        import_directory,relocation_directory,load_config_directory,load_config,
        entry_point_in_executable_section,
        requires_relocations:relocation_directory.rva!=0 && relocation_directory.size!=0,
    })
}

pub fn print_loader_lifecycle_plan(plan:&LoaderLifecyclePlan){
    println!("\n=== PE LOADER LIFECYCLE AUDIT ===");
    println!("Sections with planned permissions: {}",plan.sections.len());
    for s in &plan.sections {
        let mut p=String::new();
        if s.read {p.push('R');} if s.write {p.push('W');} if s.execute {p.push('X');}
        println!("  {:8} RVA {:#010x} size {:#x} permissions {}",String::from_utf8_lossy(&s.name),s.virtual_address,s.mapped_size,p);
    }
    println!("TLS directory: {}",if plan.tls.is_some(){"present"}else{"absent"});
    if let Some(tls)=&plan.tls {
        println!("TLS raw data: RVA {:?}, {} bytes; zero-fill {} bytes",tls.raw_data_start_rva,tls.raw_data_size,tls.zero_fill_size);
        println!("TLS index RVA: {:?}",tls.index_rva);
        println!("TLS callbacks discovered and executable: {}",tls.callback_rvas.len());
    }
    println!("x64 exception directory: {}",match &plan.exception {Some(e)=>format!("present ({} RUNTIME_FUNCTION entries; {} unwind records validated; {} chained; {} handlers)",e.runtime_function_entries,e.validated_unwind_info_records,e.chained_records,e.handler_records),None=>"absent".into()});
    println!("Relocation directory: {}",if plan.requires_relocations{"present"}else{"absent"});
    println!("Load-config directory: {}",if plan.load_config.is_some(){"validated"}else{"absent"});
    if let Some(config)=&plan.load_config {
        println!("  structure size: {:#x}; GuardFlags: {:#010x}",config.declared_size,config.guard_flags);
        println!("  security cookie RVA: {:?}",config.security_cookie_rva);
        println!("  Guard CF check/dispatch RVAs: {:?} / {:?}",config.guard_cf_check_rva,config.guard_cf_dispatch_rva);
        println!("  Guard CF function table RVA/count: {:?} / {}",config.guard_cf_function_table_rva,config.guard_cf_function_count);
    }
    println!("Entry point RVA: {:#010x}; executable section: {}",plan.entry_point_rva,plan.entry_point_in_executable_section);
    println!("NOTE: permissions are a plan only; TLS callbacks and entry point were not executed; unwind data was not registered.");
}

#[cfg(test)]
mod tests{
    use super::*;
    fn tiny_pe()->Vec<u8>{
        let mut b=vec![0u8;0x500];
        b[0..2].copy_from_slice(b"MZ");b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());b[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        let o=0x98;b[o..o+2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[o+16..o+20].copy_from_slice(&0x1000u32.to_le_bytes());
        b[o+24..o+32].copy_from_slice(&0x140000000u64.to_le_bytes());
        b[o+56..o+60].copy_from_slice(&0x3000u32.to_le_bytes());b[o+60..o+64].copy_from_slice(&0x200u32.to_le_bytes());
        b[o+108..o+112].copy_from_slice(&16u32.to_le_bytes());
        let s=o+0xf0;b[s..s+5].copy_from_slice(b".text");b[s+8..s+12].copy_from_slice(&0x100u32.to_le_bytes());
        b[s+12..s+16].copy_from_slice(&0x1000u32.to_le_bytes());b[s+16..s+20].copy_from_slice(&0x200u32.to_le_bytes());
        b[s+20..s+24].copy_from_slice(&0x200u32.to_le_bytes());b[s+36..s+40].copy_from_slice(&0x60000020u32.to_le_bytes());
        b
    }
    #[test]
    fn parses_load_config_security_cookie_and_guard_cf_metadata() {
        let mut b=tiny_pe();
        let o=0x98;
        let d=o+112+10*8;
        b[d..d+4].copy_from_slice(&0x1000u32.to_le_bytes());
        b[d+4..d+8].copy_from_slice(&148u32.to_le_bytes());
        b[0x200..0x204].copy_from_slice(&148u32.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        let section_table=o+0xf0;
        b[section_table+40..section_table+45].copy_from_slice(b".data");
        b[section_table+48..section_table+52].copy_from_slice(&0x100u32.to_le_bytes());
        b[section_table+52..section_table+56].copy_from_slice(&0x2000u32.to_le_bytes());
        b[section_table+56..section_table+60].copy_from_slice(&0x100u32.to_le_bytes());
        b[section_table+60..section_table+64].copy_from_slice(&0x400u32.to_le_bytes());
        b[section_table+76..section_table+80].copy_from_slice(&0xc0000040u32.to_le_bytes());
        b[0x200+88..0x200+96].copy_from_slice(&(0x140002000u64).to_le_bytes());
        b[0x200+112..0x200+120].copy_from_slice(&(0x140002008u64).to_le_bytes());
        b[0x200+120..0x200+128].copy_from_slice(&(0x140002010u64).to_le_bytes());
        let plan=build_loader_lifecycle_plan(&b).unwrap();
        let config=plan.load_config.unwrap();
        assert_eq!(config.security_cookie_rva,Some(0x2000));
        assert_eq!(config.guard_cf_check_rva,Some(0x2008));
        assert_eq!(config.guard_cf_dispatch_rva,Some(0x2010));
    }

    #[test]fn plans_section_permissions_and_entry_point(){let p=build_loader_lifecycle_plan(&tiny_pe()).unwrap();assert_eq!(p.sections.len(),1);assert!(p.sections[0].read);assert!(p.sections[0].execute);assert!(!p.sections[0].write);assert!(p.entry_point_in_executable_section);}
    #[test]fn rejects_non_amd64(){let mut b=tiny_pe();b[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());assert_eq!(build_loader_lifecycle_plan(&b),Err(LifecycleError::UnsupportedMachine(0x14c)));}
    #[test]fn rejects_truncated_section_table(){let mut b=tiny_pe();b.truncate(0x180);assert!(matches!(build_loader_lifecycle_plan(&b),Err(LifecycleError::Truncated(_))));}
    #[test]fn detects_relocation_directory(){let mut b=tiny_pe();let o=0x98;b[o+112+5*8..o+112+5*8+4].copy_from_slice(&0x1100u32.to_le_bytes());b[o+112+5*8+4..o+112+5*8+8].copy_from_slice(&12u32.to_le_bytes());let p=build_loader_lifecycle_plan(&b).unwrap();assert!(p.requires_relocations);}
    #[test]fn rejects_malformed_exception_directory_size(){let mut b=tiny_pe();let o=0x98;b[o+112+3*8..o+112+3*8+4].copy_from_slice(&0x1100u32.to_le_bytes());b[o+112+3*8+4..o+112+3*8+8].copy_from_slice(&13u32.to_le_bytes());assert!(matches!(build_loader_lifecycle_plan(&b),Err(LifecycleError::Invalid(_))));}
    #[test]fn tls_index_may_live_in_zero_initialized_writable_section_tail(){
        let sections=[SectionProtection{name:*b".data\0\0\0",virtual_address:0x2000,mapped_size:0x3000,read:true,write:true,execute:false}];
        assert!(is_writable_mapped_range(&sections,0x4ffc,4));
        assert!(!is_writable_mapped_range(&sections,0x4ffd,4));
    }
    #[test]fn tls_index_must_be_in_writable_mapped_memory(){
        let sections=[SectionProtection{name:*b".rdata\0\0",virtual_address:0x2000,mapped_size:0x1000,read:true,write:false,execute:false}];
        assert!(!is_writable_mapped_range(&sections,0x2100,4));
    }
}
