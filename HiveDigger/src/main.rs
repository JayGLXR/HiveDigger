use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem,
    path::Path,
};

// Struct representing the base block of a registry file.
#[repr(C)]
#[derive(Debug)]
struct BaseBlock {
    signature: [u8; 4],         // Offset 0:  "regf"
    primary_seq_num: u32,       // Offset 4
    secondary_seq_num: u32,     // Offset 8
    last_written_timestamp: u64, // Offset 12
    major_version: u32,         // Offset 20: 1
    minor_version: u32,         // Offset 24: 3, 4, 5, or 6
    file_type: u32,           // Offset 28: 0 means primary file
    file_format: u32,          // Offset 32: 1 means direct memory load
    root_cell_offset: u32,       // Offset 36: Offset of the root cell in the hive bins data
    hive_bins_data_size: u32,      // Offset 40: Size of the hive bins data
    clustering_factor: u32,      // Offset 44: Logical sector size / 512
    file_name: [u16; 64],       // Offset 48
    reserved1: [u8; 396],         // Offset 112
    checksum: u32,           // Offset 508: XOR-32 checksum of the previous 508 bytes
    reserved2: [u8; 3576],        // Offset 512
    boot_type: u32,        // Offset 4088
    boot_recover: u32        // Offset 4092
}


// Struct representing a hive bin header
#[repr(C)]
#[derive(Debug)]
#[allow(dead_code)]
struct HiveBinHeader {
    signature: [u8; 4],
    offset: u32,
    size: u32,
    reserved: [u8; 8],
    timestamp: u64,
    spare: u32,
}

// Struct representing a cell header
#[repr(C)]
#[derive(Debug)]
struct CellHeader {
    size: i32, // Use i32 because size can be negative
}

// Struct representing a key node
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct KeyNode {
    signature: [u8; 2],
    flags: u16,
    last_written_timestamp: u64,
    access_bits: u32,
    parent: u32,
    number_of_subkeys: u32,
    number_of_volatile_subkeys: u32,
    subkeys_list_offset: u32,
    volatile_subkeys_list_offset: u32,
    number_of_key_values: u32,
    key_values_list_offset: u32,
    key_security_offset: u32,
    class_name_offset: u32,
    largest_subkey_name_length: u32, //This field can be split
    largest_subkey_class_name_length: u32,
    largest_value_name_length: u32,
    largest_value_data_size: u32,
    workvar: u32,
    key_name_length: u16,
    class_name_length: u16,
    // Key name string (variable length) - this is handled with an unsafe byte slice
}

// Struct representing a key value
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct KeyValue {
    signature: [u8; 2],
    name_length: u16,
    data_size: u32,
    data_offset: u32,
    data_type: u32,
    flags: u16,
    spare: u16
    // Value name string (variable length) - this is handled with an unsafe byte slice
}

// Enum for subkey list type
#[derive(Debug, PartialEq)]
enum SubkeyListType {
    IndexLeaf,
    FastLeaf,
    HashLeaf,
    IndexRoot,
    Unknown,
}

// Function to extract the syskey from the registry hive
pub fn extract_syskey(hive_path: &Path) -> Result<Vec<u8>, std::io::Error> {
    // Open the hive file
    let mut file = File::open(hive_path)?;

    // Read base block
    let mut base_block_bytes = [0u8; 4096];
    file.read_exact(&mut base_block_bytes)?;
    let base_block: &BaseBlock = unsafe { mem::transmute(&base_block_bytes) };

    // Validate signature
    if &base_block.signature != b"regf" {
      return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid hive signature"))
    }

    //Check file format, ensure it's 1 (direct memory load)
    if base_block.file_format != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Unsupported file format",
        ));
    }

    // Calculate hive bins offset
    let hive_bins_offset = 4096;
    let root_cell_offset = base_block.root_cell_offset;

    // Find the root key node
    let root_key_node_offset = hive_bins_offset + root_cell_offset;
    let root_key_node = read_key_node(&mut file, root_key_node_offset.into())?;

    // Find CurrentControlSet subkey
    let current_control_set_key =
        find_subkey(&mut file, &root_key_node, "CurrentControlSet")?;

    // Find Control subkey
    let control_key = find_subkey(&mut file, &current_control_set_key, "Control")?;

    // Find Lsa subkey
    let lsa_key = find_subkey(&mut file, &control_key, "Lsa")?;

    // Find JD key value
    let jd_key_value = find_key_value(&mut file, &lsa_key, "JD")?;


    // Extract Syskey
     let syskey = extract_key_value_data(&mut file, &jd_key_value, base_block.minor_version)?;


    Ok(syskey)
}

// Function to read a key node from the file
fn read_key_node(file: &mut File, offset: u64) -> Result<KeyNode, std::io::Error> {
    file.seek(SeekFrom::Start(offset))?;

    let mut key_node_bytes = [0u8; mem::size_of::<KeyNode>()];
    file.read_exact(&mut key_node_bytes)?;

    let key_node: &KeyNode = unsafe { mem::transmute(&key_node_bytes) };

    //Validate key node signature
    if &key_node.signature != b"nk" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid key node signature",
        ));
    }


    Ok(*key_node)
}

// Function to read a key value from the file
fn read_key_value(file: &mut File, offset: u64) -> Result<KeyValue, std::io::Error> {
    file.seek(SeekFrom::Start(offset))?;

    let mut key_value_bytes = [0u8; mem::size_of::<KeyValue>()];
    file.read_exact(&mut key_value_bytes)?;

    let key_value: &KeyValue = unsafe { mem::transmute(&key_value_bytes) };

    if &key_value.signature != b"vk" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid key value signature",
        ));
    }

    Ok(*key_value)
}

// Function to find a subkey with a given name
fn find_subkey(
    file: &mut File,
    parent_key_node: &KeyNode,
    subkey_name: &str,
) -> Result<KeyNode, std::io::Error> {
    if parent_key_node.subkeys_list_offset == 0xFFFFFFFF {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Subkey list is not present for the parent key node"),
        ));
    }
    let subkeys_list_type = get_subkey_list_type(file, parent_key_node.subkeys_list_offset)?;


    match subkeys_list_type {
        SubkeyListType::IndexLeaf | SubkeyListType::FastLeaf | SubkeyListType::HashLeaf => {
          let subkey_offset = find_subkey_in_list(file, parent_key_node.subkeys_list_offset, subkey_name, subkeys_list_type)?;

          let subkey_node = read_key_node(file, subkey_offset as u64)?;
          Ok(subkey_node)
        },
        SubkeyListType::IndexRoot => {
          let subkey_offset = find_subkey_in_index_root(file, parent_key_node.subkeys_list_offset, subkey_name)?;

          let subkey_node = read_key_node(file, subkey_offset as u64)?;
          Ok(subkey_node)

        }
      _ => Err(std::io::Error::new(
          std::io::ErrorKind::Other,
          format!("Unsupported subkey list type: {:?}", subkeys_list_type),
      )),
    }
}
fn find_subkey_in_index_root(file: &mut File, index_root_offset: u32, subkey_name: &str) -> Result<u32, std::io::Error>{
    file.seek(SeekFrom::Start(index_root_offset as u64))?;
    let mut index_root_signature = [0u8; 2];
    file.read_exact(&mut index_root_signature)?;
     if &index_root_signature != b"ri" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid index root signature",
        ));
    }

    let mut num_elements_bytes = [0u8; 2];
    file.read_exact(&mut num_elements_bytes)?;
    let num_elements = u16::from_le_bytes(num_elements_bytes);
    for _ in 0..num_elements {
        let mut subkeys_list_offset_bytes = [0u8; 4];
        file.read_exact(&mut subkeys_list_offset_bytes)?;
        let subkeys_list_offset = u32::from_le_bytes(subkeys_list_offset_bytes);
        let subkey_list_type = get_subkey_list_type(file, subkeys_list_offset)?;
        let subkey_offset = find_subkey_in_list(file, subkeys_list_offset, subkey_name, subkey_list_type);
        match subkey_offset {
          Ok(offset) => return Ok(offset),
          Err(_) => continue,
        }
    }
    Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Subkey with name \"{}\" not found in Index Root", subkey_name),
        ))

}

fn find_subkey_in_list(file: &mut File, subkeys_list_offset: u32, subkey_name: &str, subkey_list_type: SubkeyListType) -> Result<u32, std::io::Error>{
  file.seek(SeekFrom::Start(subkeys_list_offset as u64))?;

    let mut signature = [0u8; 2];
    file.read_exact(&mut signature)?;

    let mut num_elements_bytes = [0u8; 2];
    file.read_exact(&mut num_elements_bytes)?;
    let num_elements = u16::from_le_bytes(num_elements_bytes);

    for _ in 0..num_elements {

        let subkey_offset = match subkey_list_type {
          SubkeyListType::IndexLeaf => {
            let mut key_node_offset_bytes = [0u8; 4];
            file.read_exact(&mut key_node_offset_bytes)?;
             u32::from_le_bytes(key_node_offset_bytes)
          },
          SubkeyListType::FastLeaf => {
            let mut key_node_offset_bytes = [0u8; 4];
            file.read_exact(&mut key_node_offset_bytes)?;
             u32::from_le_bytes(key_node_offset_bytes)
          },
          SubkeyListType::HashLeaf => {
            let mut key_node_offset_bytes = [0u8; 4];
            file.read_exact(&mut key_node_offset_bytes)?;
             u32::from_le_bytes(key_node_offset_bytes)
          },
          _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Subkey list type {:?} is not supported", subkey_list_type)))
        };
      
        //Read the key node and compare the name
        let key_node = read_key_node(file, subkey_offset as u64)?;

        let key_name = read_key_name(file, &key_node)?;

        if key_name == subkey_name {
            return Ok(subkey_offset);
        }
       match subkey_list_type {
         SubkeyListType::FastLeaf => {
           file.seek(SeekFrom::Current(4))?; //Skip name hint
         },
         SubkeyListType::HashLeaf => {
            file.seek(SeekFrom::Current(4))?; //Skip Name Hash
         }
         _ => continue
       };
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("Subkey with name \"{}\" not found", subkey_name),
    ))

}

fn get_subkey_list_type(file: &mut File, subkeys_list_offset: u32) -> Result<SubkeyListType, std::io::Error>{
    file.seek(SeekFrom::Start(subkeys_list_offset as u64))?;
    let mut signature = [0u8; 2];
    file.read_exact(&mut signature)?;

    match &signature {
      b"li" => Ok(SubkeyListType::IndexLeaf),
      b"lf" => Ok(SubkeyListType::FastLeaf),
      b"lh" => Ok(SubkeyListType::HashLeaf),
      b"ri" => Ok(SubkeyListType::IndexRoot),
      _ => Ok(SubkeyListType::Unknown)
    }
}

// Function to read the name string of a key node
fn read_key_name(file: &mut File, key_node: &KeyNode) -> Result<String, std::io::Error> {
    let key_name_offset = file.seek(SeekFrom::Current(0))?;
    file.seek(SeekFrom::Start(key_name_offset + mem::size_of::<KeyNode>() as u64))?;
    let mut name_bytes = vec![0u8; key_node.key_name_length as usize];
    file.read_exact(&mut name_bytes)?;

    let name_string = if key_node.flags & 0x0020 == 0x0020 {
        //ASCII or Extended ASCII string
        String::from_utf8(name_bytes).map_err(|_| {
          std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8 data")
        })?
    } else {
        // UTF-16LE string
         let name_utf16: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

         String::from_utf16(&name_utf16).map_err(|_| {
          std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-16 data")
        })?
    };


    // Return file cursor to the location it was at
    file.seek(SeekFrom::Start(key_name_offset))?;


    Ok(name_string)
}


// Function to find a key value with a given name
fn find_key_value(
    file: &mut File,
    key_node: &KeyNode,
    value_name: &str,
) -> Result<KeyValue, std::io::Error> {
     if key_node.key_values_list_offset == 0xFFFFFFFF {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Key Value list not present for key node"),
        ));
    }

    let list_offset = key_node.key_values_list_offset as u64;
    file.seek(SeekFrom::Start(list_offset))?;

    for _ in 0..key_node.number_of_key_values{
        let mut key_value_offset_bytes = [0u8; 4];
        file.read_exact(&mut key_value_offset_bytes)?;
        let key_value_offset = u32::from_le_bytes(key_value_offset_bytes);

         let key_value = read_key_value(file, key_value_offset as u64)?;

        let current_file_offset = file.seek(SeekFrom::Current(0))?;
        let value_name_string = read_key_value_name(file, &key_value)?;

        if value_name_string == value_name {
            // Return file cursor to the location it was at
            file.seek(SeekFrom::Start(current_file_offset))?;

            return Ok(key_value);
        }

        // Return file cursor to the location it was at before reading value name
        file.seek(SeekFrom::Start(current_file_offset))?;

    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("Key value with name \"{}\" not found", value_name),
    ))
}

// Function to read the name of a key value
fn read_key_value_name(file: &mut File, key_value: &KeyValue) -> Result<String, std::io::Error>{

    let value_name_offset = file.seek(SeekFrom::Current(0))?;
    file.seek(SeekFrom::Start(value_name_offset + mem::size_of::<KeyValue>() as u64))?;

    let mut name_bytes = vec![0u8; key_value.name_length as usize];
    file.read_exact(&mut name_bytes)?;
     let name_string = if key_value.flags & 0x0001 == 0x0001 {
        //ASCII or Extended ASCII string
          String::from_utf8(name_bytes).map_err(|_| {
          std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8 data")
        })?
    } else {
        // UTF-16LE string
         let name_utf16: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        String::from_utf16(&name_utf16).map_err(|_| {
          std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-16 data")
        })?
    };


    // Return file cursor to the location it was at
    file.seek(SeekFrom::Start(value_name_offset))?;

    Ok(name_string)


}


// Function to extract the data of a key value.
fn extract_key_value_data(
  file: &mut File,
  key_value: &KeyValue,
  minor_version: u32
) -> Result<Vec<u8>, std::io::Error> {
  let data_size = key_value.data_size & 0x7FFFFFFF; // Clear the most significant bit

    if key_value.data_size & 0x80000000 != 0 {
        // Data is stored in the Data Offset field itself (up to 4 bytes)
        let data_bytes = key_value.data_offset.to_le_bytes();
        Ok(data_bytes[..data_size as usize].to_vec())

    } else {
        // Data is stored in a separate cell
        let data_offset = key_value.data_offset as u64;
        if data_size <= 16344 || minor_version <= 3 {
          let mut data_bytes = vec![0u8; data_size as usize];
          file.seek(SeekFrom::Start(data_offset))?;
          file.read_exact(&mut data_bytes)?;
          Ok(data_bytes)
        } else {
            // Data is stored as Big Data structure
            let big_data_bytes = read_big_data(file, data_offset as u64)?;
            Ok(big_data_bytes)
        }

    }
}

fn read_big_data(file: &mut File, offset: u64) -> Result<Vec<u8>, std::io::Error>{
  file.seek(SeekFrom::Start(offset))?;
  let mut big_data_signature = [0u8; 2];
  file.read_exact(&mut big_data_signature)?;
    if &big_data_signature != b"db" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid big data signature",
        ));
    }

  let mut num_segments_bytes = [0u8; 2];
  file.read_exact(&mut num_segments_bytes)?;
  let num_segments = u16::from_le_bytes(num_segments_bytes);

  let mut segment_list_offset_bytes = [0u8; 4];
  file.read_exact(&mut segment_list_offset_bytes)?;
  let segment_list_offset = u32::from_le_bytes(segment_list_offset_bytes);

    file.seek(SeekFrom::Start(segment_list_offset as u64))?;
    let mut data = Vec::new();
    for _ in 0..num_segments {
        let mut data_segment_offset_bytes = [0u8; 4];
        file.read_exact(&mut data_segment_offset_bytes)?;
        let data_segment_offset = u32::from_le_bytes(data_segment_offset_bytes);
        let mut data_segment_cell_header_bytes = [0u8; 4];
        file.seek(SeekFrom::Start(data_segment_offset as u64))?;
        file.read_exact(&mut data_segment_cell_header_bytes)?;
        let data_segment_cell_header: &CellHeader = unsafe { mem::transmute(&data_segment_cell_header_bytes) };
        let segment_size = data_segment_cell_header.size.abs();
        let mut segment_bytes = vec![0u8; segment_size as usize - 4];
         file.seek(SeekFrom::Start(data_segment_offset as u64 + 4))?;
        file.read_exact(&mut segment_bytes)?;
        data.extend(segment_bytes)
    }
    Ok(data)


}

fn main() -> Result<(), std::io::Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <path_to_hive_file>", args[0]);
        std::process::exit(1);
    }

    let hive_path = std::path::Path::new(&args[1]);
    let syskey = extract_syskey(hive_path)?;
    println!("Extracted syskey: {:?}", syskey);
    Ok(())
}