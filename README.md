# HiveDigger-in-Rust

**Offline SYSTEM Hive Syskey Extractor**

This repository contains a Rust program (`HiveDigger-in-Rust`) designed to parse a Windows `SYSTEM` registry hive file offline and extract the system's Syskey. The Syskey is a critical piece of data used to encrypt user account passwords and other sensitive information, and thus it is important to keep it secret.

This tool is intended for security research, forensic analysis, and educational purposes and should be used with caution and within legal and ethical guidelines.

## How It Works:

`HiveDigger-in-Rust` operates by directly interpreting the binary data stored within the `SYSTEM` hive file. It does not rely on Windows APIs or any running Windows system. Here's a high-level overview of the process:

1.  **File Reading:** The program first opens the specified `SYSTEM` hive file in read-only binary mode.

2.  **Base Block Parsing:** The first 4096 bytes of the hive file contains a structure named the `base block` which contains information about the hive file. The program reads this block, verifies the signature (`regf`) and that the file format is `direct memory load`, and then extracts important fields like the:
    *   `root_cell_offset`: The location (offset) of the root registry key within the file.
    *   `minor_version`:  The minor version of the registry writer. This affects some data structures within the hive.

3.  **Root Key Node Navigation:**
    *   The program uses the `root_cell_offset` from the base block to find the root key node in the file.
    *   It then parses the root key node structure to find information about the subkeys, specifically the location of the `CurrentControlSet` subkey.

4. **Subkey Traversal:**
    * The program uses the subkey location to read the associated subkey node structure. The program proceeds to read the `Control` subkey under `CurrentControlSet` and then the `Lsa` subkey under the `Control` key.

5.  **Key Value Lookup:**
    *   Under the `Lsa` key the program attempts to find a key value named `JD`.

6.  **Syskey Extraction:**
    *   If found, the program extracts the binary data associated with the `JD` key value. *This data is the syskey.* The extraction process handles different types of data, including small, inline data; standard data cell data; and big data cell data.

7.  **Output:** Finally the program prints the extracted Syskey to standard output, both as a raw byte vector, and as a hexadecimal string.

## Registry File Internals:

The `SYSTEM` hive file is a complex binary file containing a hierarchy of keys, subkeys and key values.  The following are key concepts to understanding how the program works:

*   **Base Block:** The header of the registry file, contains metadata about the hive.
*   **Hive Bins:** The data section of the hive file which contains the registry data.
*   **Cells:** Variable length containers of data within a hive bin, cells contain key nodes, values and lists.
*   **Key Node (`nk`):**  A node representing a registry key, which may contain subkeys and values. Key nodes point to their parent key node, and have an offset to their subkey list and value list.
*   **Key Value (`vk`):**  A name-value pair, which contains data of different types and sizes. Key values can point to data within their own structures, to another cell, or to a "big data" structure.
*   **Subkey Lists (`li`, `lf`, `lh`, `ri`):** Structures for organizing child keys (subkeys) of a key node. The code handles several variations of these (Index Leaf, Fast Leaf, Hash Leaf and Index Root). These list types store offsets to the key nodes that are subkeys of their parent key node.

**Important Considerations:**

*   **Unsafe Code:** The code uses `unsafe` blocks due to the need to interpret binary data from memory. Incorrect assumptions about offsets or sizes can lead to crashes.
*   **Endianness:** The code assumes a little-endian system architecture.
*   **Windows Version Dependencies:** Slight variations in the registry format between Windows versions may break the code. Be sure to test on your target Windows version.
*   **Error Handling:** Error handling is basic but the program does try to handle the most common failure modes.
*   **Security:** Accessing the `SYSTEM` hive requires sufficient file system privileges.

**Building and Running:**

1.  Ensure you have Rust installed (`https://www.rust-lang.org/tools/install`).
2.  Clone this repository.
3.  Navigate to the repository folder in your terminal
4.  Run `cargo build --release` to build the optimized executable.
5.  Run the executable with `cargo run --release -- <path-to-your-SYSTEM-hive>`, replace `<path-to-your-SYSTEM-hive>` with the full path of the registry hive you want to parse.
6. The syskey will be output to standard output.

**Disclaimer:**

This project is for educational and research purposes only. Use it responsibly and within legal and ethical boundaries.

This tool is not a replacement for professional security analysis tools. Do not use this tool to do anything illegal.

**Contributions:**

Contributions are welcome! Feel free to fork the repository, make improvements, and submit pull requests.

**License:**

This project is licensed under the [MIT License](LICENSE).
