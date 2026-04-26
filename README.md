# NTFS Master File Table (MFT) Forensic Recovery Tool

This project is a Python-based, enterprise-grade digital forensics utility designed to interact directly with raw storage media to reconstruct the NTFS file system. By bypassing the operating system's logical file parsing, this tool reads the raw hexadecimal data of a physical drive, making it capable of recovering permanently deleted files, bypassing encryption environments via live analysis, and reconstructing directories from severely corrupted or formatted partitions.

## Core Capabilities

* **Dual-Mode Acquisition:** Supports both static forensic image analysis (`.dd`, `.E01`) for court-admissible preservation, and Live Disk Analysis (`\\.\PhysicalDriveX`) for rapid triage and BitLocker bypass.
* **Architecture Agnostic:** Successfully parses traditional Master Boot Record (MBR) partition tables and detects modern GUID Partition Table (GPT) Protective MBRs to locate the NTFS Volume Boot Record (VBR).
* **Deep MFT Parsing:** Translates raw 1024-byte MFT records into structured metadata, extracting timestamps, resident data, and complex `data_runs` for non-resident files.
* **Orphaned Directory Reconstruction:** Reads native parent-child node references (`$FILE_NAME` attribute) to rebuild the complete file system tree natively within a PySide6 GUI.
* **Deleted File Extraction:** Analyzes MFT flags to instantly identify permanently deleted artifacts (highlighted in red) and reconstructs them to the local investigator's machine.
* **"Scenario 3" Signature Carving:** Features a raw hexadecimal carving engine that sweeps disks byte-by-byte for the `FILE` signature, allowing full data recovery even if the MBR and VBR are completely destroyed.

---

## Under the Hood: The Algorithmic Execution Flow

To understand this tool, you must look at a hard drive the way a forensic investigator does: as a continuous ocean of raw bytes, not a collection of logical folders. The Python engine executes a strict, step-by-step mathematical pipeline to navigate this ocean. Here is exactly what the code does, in order, from the moment you click "Scan."

### Phase 1: Gaining Access (The Raw Read)
1. **The Target Lock:** The tool bypasses Windows Explorer and uses Python's `open()` function in Read-Binary (`'rb'`) mode to target the raw physical device (e.g., `\\.\PhysicalDrive2`) or forensic image.
2. **The Sector Read:** The tool reads the absolute first 512 bytes of the drive. This is known as **Sector 0**.

### Phase 2: The Map Crossroad (MBR vs. GPT)
Once inside Sector 0, the tool jumps to byte offset `446` to read the partition table. 
1. **The MBR Check:** If it sees the byte `0x07`, it knows it is dealing with a classic **MBR** drive. It reads the Start LBA (Logical Block Address) directly and moves to Phase 3.
2. **The GPT Handoff:** If it sees the byte `0xEE`, it triggers the **GPT** protocol. It realizes Sector 0 is a dummy map (Protective MBR). 
3. **Parsing the GUIDs:** The code jumps to Sector 1 (offset `512`), verifies the `EFI PART` signature, and locates the partition array. It scans the array for the Microsoft Basic Data GUID (`EBD0A0A2...`) to extract the true Start LBA.

### Phase 3: The Front Door (The Volume Boot Record)
With the correct Start LBA acquired, the code calculates the absolute byte offset (`Start LBA * 512`) and jumps to the very beginning of the Windows partition. 
1. **The VBR Read:** It reads the first sector of this partition, known as the Volume Boot Record (VBR).
2. **Extracting the Keys:** From the VBR, the code extracts vital math variables: `Bytes Per Sector` (usually 512), `Sectors Per Cluster` (usually 8), and calculates the `Cluster Size` (usually 4096 bytes).
3. **The Target Address:** Most importantly, it reads the `$MFT Starting Cluster`, which points directly to the master ledger.

### Phase 4: Reading the Ledger (The Master File Table)
The code calculates the exact physical byte offset of the MFT and jumps there. 
1. **The 1024-Byte Chunk:** Every file and folder on the computer gets exactly one entry. The code reads these entries in strict 1024-byte chunks.
2. **Signature Verification:** It verifies it is looking at a real file record by checking the first 4 bytes for the ASCII signature `FILE` (`46 49 4C 45` in hex).
3. **The Deleted Flag Check:** It checks the status flag at offset `0x16`. If the flag is `0x01`, the file is Active. If the flag is `0x00`, the file is **Deleted** (and the GUI instantly paints it red).

### Phase 5: Attribute Extraction (Finding the Evidence)
Inside the 1024-byte record, the code acts as a hexadecimal translator, reading specific attribute blocks:
1. **`0x10` ($STANDARD_INFORMATION):** The code extracts the precise Created, Modified, and Accessed timestamps.
2. **`0x30` ($FILE_NAME):** The code extracts the actual name of the file (e.g., `secret.pdf`) and the ID of its "Parent Folder." This parent ID is what allows the GUI to reconstruct the nested directory tree perfectly.
3. **`0x80` ($DATA):** The code locates the file's contents.

### Phase 6: Data Recovery & Extraction
When the code hits the `$DATA` attribute, it makes a final calculation based on the file's size:
1. **Resident Data (Small Files):** If the file is tiny (under ~700 bytes), NTFS stuffs the actual text directly inside the MFT record. The code extracts it immediately.
2. **Non-Resident Data (Large Files):** If the file is large, the MFT only holds map coordinates called `data_runs`. The code decodes these runs, jumps to those specific physical clusters on the disk, reads the raw bytes, and saves the reconstructed file to the investigator's local desktop.

---

## Prerequisites & Installation

To run this tool, ensure you have the following installed on your machine:
* **Python 3.8+**
* **PySide6** (For the interactive desktop GUI and Hex Viewer)
* *(Optional)* `pyewf` for reading EnCase image formats.
* *(Optional)* `reportlab` for exporting analysis reports in PDF format.

### Installation

1. Clone or download this repository to your local machine.
2. Install the required dependencies:
   ```bash
   pip install PySide6 reportlab
   ```

## How to Run & Use the Tool

**Important:** If you intend to use the **Live Disk Analysis** mode to scan attached physical drives, you **must run the application with Administrator Privileges**. Without it, Windows will block the raw disk read access.

1. Launch the tool using Python:
   ```bash
   python mft_recovery_tool.py
   ```

2. **Select a Target:**
   * Go to `File > Open Forensic Image` to select a `.dd` or `.E01` disk image file.
   * Go to `File > Open Live Disk` to target a physical drive currently attached to your machine (e.g., `C:` or physical drive indices).

3. **Partition Selection:**
   * If multiple partitions are detected (MBR or GPT), a dialog box will appear. Select the NTFS partition you wish to analyze.

4. **Initiate Scan:**
   * Use the `Tools > Scan for MFT` or click the "Scan" button in the toolbar to begin parsing the MFT.
   * Alternatively, use `Scan for FILE Signatures` if the partition boot sectors are severely damaged and you want to carve the disk sequentially.

5. **Review Results:**
   * Recovered artifacts will appear in the directory tree panel on the left.
   * Deleted files and folders will be visually distinguished.
   * Click on any item to view its metadata (timestamps, attributes, recovery confidence) in the right panel, and view its raw hex data in the center hex viewer.

6. **Export Reports:**
   * Go to the `Report` menu to export your findings as a CSV, JSON, or PDF summary for documentation and chain of custody.

---

## Platform Compatibility

* **Operating System:** Designed primarily for **Windows** environments, as it interfaces with Windows physical drives (`\\.\PhysicalDriveX`) and focuses on the NTFS file system.
* **Forensic Images:** The tool can parse static forensic images (`.dd`, `.E01`) on **Linux or macOS** systems as well, provided the raw hexadecimal data structure remains intact, but live analysis requires a Windows environment.

## Troubleshooting

* **PermissionError (Access is denied):** This happens when you try to open a Live Disk without running the command prompt or IDE as an Administrator. Right-click your terminal and select "Run as Administrator."
* **Missing Dependencies:** Ensure you have activated your virtual environment (if using one) and successfully run `pip install PySide6`. If PDF exports fail, make sure `reportlab` is installed.
* **Corrupted or Unreadable MFT:** If the standard "Scan for MFT" fails, the MFT may be severely overwritten. Use the "Scan for FILE Signatures" tool to bypass the MFT dependency and carve directly from the raw disk.
