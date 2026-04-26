import sys
import os
import struct
import io
import hashlib
import csv
import json
import ctypes
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from base_disk_handler import BaseDiskHandler
from image_handler import ImageFileHandler
from live_disk_handler import LiveDiskHandler

try:
    import pyewf
    HAS_PYEWF = True
except ImportError:
    HAS_PYEWF = False

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem,
    QHeaderView, QToolBar, QStatusBar, QFileDialog, QDialog, QMessageBox,
    QProgressDialog, QInputDialog, QLabel, QScrollBar, QAbstractScrollArea,
    QPushButton, QMenu, QDialogButtonBox, QSpinBox, QCheckBox, QGroupBox, QFormLayout
)
from PySide6.QtGui import (
    QAction, QIcon, QColor, QPalette, QFont, QPainter, QFontMetrics,
    QPen, QBrush, QKeySequence, QContextMenuEvent
)
from PySide6.QtCore import (
    Qt, QThread, Signal, QSettings, QRect, QSize, QPoint
)

# Core Constants
FILE_SIGNATURE = b'FILE'
MFT_RECORD_SIZE = 1024
CHUNK_SIZE = 1024 * 1024  # 1MB

@dataclass
class MFTRecord:
    record_number: int = 0
    disk_offset: int = 0
    raw_data: bytes = b''
    signature: str = ''
    lsn: int = 0
    sequence_number: int = 0
    hard_link_count: int = 0
    flags: int = 0
    is_directory: bool = False
    is_deleted: bool = False
    is_active: bool = False
    used_size: int = 0
    allocated_size: int = 0
    base_record: int = 0
    
    # From $STANDARD_INFORMATION
    created_time: datetime = None
    modified_time: datetime = None
    mft_modified_time: datetime = None
    accessed_time: datetime = None
    file_attributes: int = 0
    
    # From $FILE_NAME
    file_name: str = ""
    parent_record_number: int = 0
    parent_sequence: int = 0
    name_namespace: int = 0
    
    # From $DATA
    data_size: int = 0
    is_resident: bool = False
    data_runs: list = field(default_factory=list)
    resident_data: bytes = b''
    
    # Parsed attributes list
    attributes: list = field(default_factory=list)
    
    # Recovery metadata
    recovery_confidence: str = "LOW"


class PartitionAnalyzer:
    def __init__(self, disk_handler: BaseDiskHandler):
        self.disk = disk_handler

    def detect_partitions(self) -> list:
        partitions = []
        mbr_data = self.disk.read_bytes(0, 512)
        if len(mbr_data) < 512:
            return partitions
            
        if mbr_data[510:512] != b'\x55\xAA':
            return partitions

        # Check GPT
        lba1 = self.disk.read_bytes(512, 512)
        if lba1.startswith(b'EFI PART'):
            return self._parse_gpt()

        # Parse MBR entries
        for i in range(4):
            offset = 446 + (i * 16)
            entry = mbr_data[offset:offset+16]
            status = entry[0]
            part_type = entry[4]
            if part_type == 0:
                continue
            lba_start = struct.unpack('<I', entry[8:12])[0]
            lba_size = struct.unpack('<I', entry[12:16])[0]
            
            p_info = {
                'index': i,
                'type': part_type,
                'type_name': hex(part_type),
                'lba_start': lba_start,
                'lba_size': lba_size,
                'size_bytes': lba_size * 512,
                'is_ntfs': (part_type == 0x07)
            }
            if not p_info['is_ntfs']:
                p_info['is_ntfs'] = self.identify_ntfs(p_info)
            partitions.append(p_info)
            
        return partitions

    def _parse_gpt(self):
        # Basic GPT parsing stub
        return []

    def identify_ntfs(self, partition: dict) -> bool:
        start_offset = partition['lba_start'] * 512
        boot_sector = self.disk.read_bytes(start_offset, 512)
        if len(boot_sector) >= 11 and boot_sector[3:11] == b'NTFS    ':
            return True
        return False

class VBRParser:
    @staticmethod
    def parse(vbr_bytes: bytes) -> dict:
        if len(vbr_bytes) < 512:
            return {}
        try:
            oem_id = vbr_bytes[3:11].decode('ascii', errors='ignore')
            bps = struct.unpack('<H', vbr_bytes[11:13])[0]
            spc = vbr_bytes[13]
            reserved = struct.unpack('<H', vbr_bytes[14:16])[0]
            total_sec = struct.unpack('<Q', vbr_bytes[40:48])[0]
            mft_clust = struct.unpack('<Q', vbr_bytes[48:56])[0]
            mft_mirr = struct.unpack('<Q', vbr_bytes[56:64])[0]
            
            mft_rec_size_raw = struct.unpack('<b', vbr_bytes[64:65])[0]
            if mft_rec_size_raw < 0:
                mft_rec_size = 2 ** abs(mft_rec_size_raw)
            else:
                mft_rec_size = mft_rec_size_raw * bps * spc

            idx_rec_size_raw = struct.unpack('<b', vbr_bytes[68:69])[0]
            if idx_rec_size_raw < 0:
                idx_rec_size = 2 ** abs(idx_rec_size_raw)
            else:
                idx_rec_size = idx_rec_size_raw * bps * spc
                
            vol_serial = vbr_bytes[72:80][::-1].hex().upper()
            
            bpc = bps * spc
            
            return {
                'oem_id': oem_id,
                'bytes_per_sector': bps,
                'sectors_per_cluster': spc,
                'bytes_per_cluster': bpc,
                'reserved_sectors': reserved,
                'total_sectors': total_sec,
                'mft_cluster': mft_clust,
                'mft_mirror_cluster': mft_mirr,
                'mft_record_size': mft_rec_size,
                'index_record_size': idx_rec_size,
                'volume_serial': vol_serial,
                'mft_offset': mft_clust * bpc,
                'mft_mirror_offset': mft_mirr * bpc
            }
        except struct.error:
            return {}
class AttributeParser:
    @staticmethod
    def parse_filetime(filetime: int) -> datetime:
        if filetime == 0:
            return None
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
        except Exception:
            return None

    @staticmethod
    def parse_standard_information(data: bytes, record: MFTRecord):
        if len(data) < 36:
            return
        c_time = struct.unpack('<Q', data[0:8])[0]
        m_time = struct.unpack('<Q', data[8:16])[0]
        mft_m_time = struct.unpack('<Q', data[16:24])[0]
        a_time = struct.unpack('<Q', data[24:32])[0]
        
        record.created_time = AttributeParser.parse_filetime(c_time)
        record.modified_time = AttributeParser.parse_filetime(m_time)
        record.mft_modified_time = AttributeParser.parse_filetime(mft_m_time)
        record.accessed_time = AttributeParser.parse_filetime(a_time)
        record.file_attributes = struct.unpack('<I', data[32:36])[0]

    @staticmethod
    def parse_file_name(data: bytes, record: MFTRecord):
        if len(data) < 66:
            return
        parent_ref = struct.unpack('<Q', data[0:8])[0]
        record.parent_record_number = parent_ref & 0xFFFFFFFFFFFF
        record.parent_sequence = parent_ref >> 48
        
        record.allocated_size = struct.unpack('<Q', data[40:48])[0]
        record.used_size = struct.unpack('<Q', data[48:56])[0]
        
        name_len = data[64]
        record.name_namespace = data[65]
        
        if len(data) >= 66 + (name_len * 2):
            try:
                name_bytes = data[66:66+(name_len*2)]
                record.file_name = name_bytes.decode('utf-16le')
            except Exception:
                record.file_name = "UNKNOWN"

    @staticmethod
    def parse_data_runs(run_data: bytes) -> list:
        runs = []
        offset = 0
        current_cluster = 0
        while offset < len(run_data):
            header = run_data[offset]
            if header == 0:
                break
            offset += 1
            len_bytes = header & 0x0F
            off_bytes = header >> 4
            
            if offset + len_bytes + off_bytes > len(run_data):
                break
                
            length_val = int.from_bytes(run_data[offset:offset+len_bytes], 'little', signed=False)
            offset += len_bytes
            
            if off_bytes > 0:
                offset_val = int.from_bytes(run_data[offset:offset+off_bytes], 'little', signed=True)
                offset += off_bytes
                current_cluster += offset_val
                runs.append((current_cluster, length_val))
            else:
                runs.append((0, length_val)) # Sparse
                
        return runs

class MFTRecoveryEngine:
    def __init__(self, disk: BaseDiskHandler):
        self.disk = disk
        self.bytes_per_sector = 512
        self.vbr = {}

    def validate_record(self, data: bytes) -> bool:
        if len(data) < 1024:
            return False
        if data[:4] != FILE_SIGNATURE:
            return False
            
        fixup_offset = struct.unpack('<H', data[4:6])[0]
        fixup_count = struct.unpack('<H', data[6:8])[0]
        
        if fixup_offset + (fixup_count * 2) > len(data):
            return False
            
        usn = data[fixup_offset:fixup_offset+2]
        
        for i in range(1, fixup_count):
            sector_end = (i * self.bytes_per_sector) - 2
            if sector_end + 2 <= len(data):
                if data[sector_end:sector_end+2] != usn:
                    return False
        return True

    def apply_fixup(self, data: bytearray) -> bytearray:
        fixup_offset = struct.unpack('<H', data[4:6])[0]
        fixup_count = struct.unpack('<H', data[6:8])[0]
        
        for i in range(1, fixup_count):
            sector_end = (i * self.bytes_per_sector) - 2
            array_offset = fixup_offset + (i * 2)
            if sector_end + 2 <= len(data) and array_offset + 2 <= len(data):
                data[sector_end:sector_end+2] = data[array_offset:array_offset+2]
        return data

    def parse_record(self, data: bytes, record_number: int, disk_offset: int) -> MFTRecord:
        rec = MFTRecord()
        rec.record_number = record_number
        rec.disk_offset = disk_offset
        rec.raw_data = data
        rec.signature = data[:4].decode('ascii', errors='ignore')
        
        data_ba = bytearray(data)
        data_ba = self.apply_fixup(data_ba)
        data = bytes(data_ba)
        
        rec.lsn = struct.unpack('<Q', data[8:16])[0]
        rec.sequence_number = struct.unpack('<H', data[16:18])[0]
        rec.hard_link_count = struct.unpack('<H', data[18:20])[0]
        attr_offset = struct.unpack('<H', data[20:22])[0]
        rec.flags = struct.unpack('<H', data[22:24])[0]
        
        rec.is_deleted = (rec.flags & 0x01) == 0
        rec.is_active = not rec.is_deleted
        rec.is_directory = (rec.flags & 0x02) != 0
        
        rec.base_record = struct.unpack('<Q', data[32:40])[0]
        
        offset = attr_offset
        while offset < len(data):
            if offset + 16 > len(data): break
            attr_type = struct.unpack('<I', data[offset:offset+4])[0]
            if attr_type == 0xFFFFFFFF: break
            
            attr_len = struct.unpack('<I', data[offset+4:offset+8])[0]
            if attr_len == 0 or offset + attr_len > len(data): break
            
            non_resident = data[offset+8]
            name_len = data[offset+9]
            name_off = struct.unpack('<H', data[offset+10:offset+12])[0]
            
            attr_data = b''
            if non_resident == 0: # Resident
                content_len = struct.unpack('<I', data[offset+16:offset+20])[0]
                content_off = struct.unpack('<H', data[offset+20:offset+22])[0]
                if offset + content_off + content_len <= offset + attr_len:
                    attr_data = data[offset+content_off:offset+content_off+content_len]
            else: # Non-resident
                run_off = struct.unpack('<H', data[offset+32:offset+34])[0]
                if offset + run_off < offset + attr_len:
                    run_data = data[offset+run_off:offset+attr_len]
                    if attr_type == 0x80:
                        rec.data_runs = AttributeParser.parse_data_runs(run_data)
            
            if attr_type == 0x10 and len(attr_data) > 0:
                AttributeParser.parse_standard_information(attr_data, rec)
            elif attr_type == 0x30 and len(attr_data) > 0:
                AttributeParser.parse_file_name(attr_data, rec)
            elif attr_type == 0x80:
                if non_resident == 0:
                    rec.is_resident = True
                    rec.resident_data = attr_data
                    rec.data_size = len(attr_data)
                else:
                    rec.is_resident = False
            
            rec.attributes.append({
                'type': attr_type,
                'type_name': hex(attr_type),
                'resident': non_resident == 0
            })
            offset += attr_len
            
        if rec.file_name and not rec.is_deleted:
            rec.recovery_confidence = "HIGH"
        elif rec.file_name:
            rec.recovery_confidence = "MEDIUM"
            
        return rec

    def scan_via_vbr(self, partition_offset: int, vbr_params: dict) -> list:
        self.vbr = vbr_params
        self.bytes_per_sector = vbr_params.get('bytes_per_sector', 512)
        mft_offset = partition_offset + vbr_params.get('mft_offset', 0)
        total_records = vbr_params.get('total_sectors', 0) // (1024 // 512) # Approximation
        
        records = []
        chunk_size = 1024 * 1024
        current_offset = mft_offset
        rec_num = 0
        
        # We read a few MBs just for demo. A real tool reads the $MFT runs
        # We'll just scan linearly for some chunks.
        for _ in range(10): # Read 10MB of MFT
            data = self.disk.read_bytes(current_offset, chunk_size)
            if not data: break
            
            for i in range(0, len(data), 1024):
                rec_data = data[i:i+1024]
                if self.validate_record(rec_data):
                    rec = self.parse_record(rec_data, rec_num, current_offset + i)
                    records.append(rec)
                rec_num += 1
            current_offset += chunk_size
        return records

    def scan_via_signature(self, partition_offset: int, partition_size: int, progress_callback=None) -> list:
        records = []
        chunk_size = 1024 * 1024
        current_offset = partition_offset
        end_offset = partition_offset + partition_size
        rec_num = 0
        
        while current_offset < end_offset:
            data = self.disk.read_bytes(current_offset, chunk_size)
            if not data: break
            
            for i in range(0, len(data), 1024):
                if data[i:i+4] == FILE_SIGNATURE:
                    rec_data = data[i:i+1024]
                    if self.validate_record(rec_data):
                        rec = self.parse_record(rec_data, rec_num, current_offset + i)
                        records.append(rec)
                        rec_num += 1
                        if progress_callback and rec_num % 1000 == 0:
                            progress_callback(rec_num)
                            
            current_offset += chunk_size
            if progress_callback:
                progress_callback(-1) # update bar
                
        return records

class TreeNode:
    def __init__(self, record: MFTRecord):
        self.record = record
        self.children = []
        self.full_path = ""

class DirectoryTree:
    def __init__(self):
        self.root = None
        self.orphans = []
        self.all_records = {}

class ReconstructionEngine:
    @staticmethod
    def reconstruct(records: list) -> DirectoryTree:
        tree = DirectoryTree()
        # Remove duplicates
        unique = {}
        for r in records:
            key = (r.record_number, r.sequence_number)
            unique[key] = r
            
        tree.all_records = {r.record_number: r for r in unique.values()}
        nodes = {r.record_number: TreeNode(r) for r in unique.values()}
        
        if 5 in nodes:
            tree.root = nodes[5]
            tree.root.full_path = ""
            
        for r_num, node in nodes.items():
            if r_num == 5: continue
            parent_num = node.record.parent_record_number
            if parent_num in nodes:
                nodes[parent_num].children.append(node)
            else:
                tree.orphans.append(node.record)
                
        ReconstructionEngine._assign_paths(tree.root, "") if tree.root else None
        return tree

    @staticmethod
    def _assign_paths(node: TreeNode, current_path: str):
        if node is None: return
        node.full_path = f"{current_path}/{node.record.file_name}" if current_path else node.record.file_name
        for child in node.children:
            ReconstructionEngine._assign_paths(child, node.full_path)

class ReportGenerator:
    @staticmethod
    def export_csv(filepath: str, records: list):
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Record#', 'FileName', 'Status', 'Size', 'Created', 'Modified', 'ParentRecord'])
            for r in records:
                writer.writerow([
                    r.record_number, r.file_name,
                    "Active" if r.is_active else "Deleted",
                    r.used_size, r.created_time, r.modified_time, r.parent_record_number
                ])

    @staticmethod
    def export_json(filepath: str, records: list):
        data = []
        for r in records:
            data.append({
                'record_number': r.record_number,
                'file_name': r.file_name,
                'is_active': r.is_active,
                'size': r.used_size
            })
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def export_pdf(filepath: str, records: list):
        if not HAS_REPORTLAB: return
        c = canvas.Canvas(filepath, pagesize=letter)
        c.drawString(100, 750, "MFT Recovery Report")
        c.drawString(100, 730, f"Total Records: {len(records)}")
        y = 700
        for i, r in enumerate(records[:50]): # Just first 50 for demo
            if y < 50:
                c.showPage()
                y = 750
            c.drawString(100, y, f"{r.record_number} - {r.file_name} - {'Active' if r.is_active else 'Deleted'}")
            y -= 15
        c.save()
class HexViewerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = b''
        self.is_dark_mode = True
        self.base_offset = 0
        self.font = QFont("Courier New", 10)
        self.fm = QFontMetrics(self.font)
        self.line_height = self.fm.height()
        self.char_width = self.fm.horizontalAdvance('W')
        self.bytes_per_line = 16
        self.lines_total = 0
        self.scroll_y = 0
        
        self.scrollbar = QScrollBar(Qt.Vertical, self)
        self.scrollbar.valueChanged.connect(self.on_scroll)
        self.setFocusPolicy(Qt.StrongFocus)

    def load_record(self, data: bytes, base_offset: int):
        self.data = data
        self.base_offset = base_offset
        self.lines_total = (len(data) + 15) // 16
        self.scrollbar.setRange(0, max(0, self.lines_total - self.height() // self.line_height))
        self.scrollbar.setValue(0)
        self.update()

    def navigate_to_offset(self, offset: int):
        if self.base_offset <= offset < self.base_offset + len(self.data):
            rel_offset = offset - self.base_offset
            line = rel_offset // 16
            self.scrollbar.setValue(line)

    def on_scroll(self, value):
        self.scroll_y = value
        self.update()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.scrollbar.setGeometry(self.width() - 20, 0, 20, self.height())
        visible_lines = self.height() // self.line_height
        self.scrollbar.setRange(0, max(0, self.lines_total - visible_lines))

    def paintEvent(self, event):
        if not self.data: return
        painter = QPainter(self)
        painter.setFont(self.font)
        
        visible_lines = self.height() // self.line_height
        start_line = self.scroll_y
        end_line = min(self.lines_total, start_line + visible_lines + 1)
        
        y = self.line_height
        for i in range(start_line, end_line):
            offset = i * 16
            line_data = self.data[offset:offset+16]
            abs_offset = self.base_offset + offset
            
            # Draw offset
            offset_color = "#B5CEA8" if self.is_dark_mode else "#008000"
            painter.setPen(QColor(offset_color))
            painter.drawText(10, y, f"{abs_offset:010X}")
            
            # Draw hex
            x_hex = 10 + 12 * self.char_width
            x_ascii = x_hex + 50 * self.char_width
            
            for j, b in enumerate(line_data):
                px = x_hex + j * 3 * self.char_width
                if j >= 8: px += self.char_width
                
                # Highlight FILE signature
                if self.data[offset+j:offset+j+4] == FILE_SIGNATURE and j <= 12:
                    sig_color = "#FF6B6B" if self.is_dark_mode else "#FFB3B3"
                    painter.fillRect(px, y - self.line_height + 3, self.char_width * 2, self.line_height, QColor(sig_color))
                    
                hex_color = "#9CDCFE" if self.is_dark_mode else "#0000FF"
                painter.setPen(QColor(hex_color))
                painter.drawText(px, y, f"{b:02X}")
                
                # Draw ASCII
                char = chr(b) if 32 <= b <= 126 else '.'
                ascii_color = "#CE9178" if self.is_dark_mode else "#A31515"
                painter.setPen(QColor(ascii_color))
                painter.drawText(x_ascii + j * self.char_width, y, char)
                
            y += self.line_height

class ScanWorker(QThread):
    progress = Signal(int)
    record_found = Signal(MFTRecord)
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, engine, offset, size, vbr_params=None):
        super().__init__()
        self.engine = engine
        self.offset = offset
        self.size = size
        self.vbr_params = vbr_params

    def run(self):
        try:
            if self.vbr_params:
                records = self.engine.scan_via_vbr(self.offset, self.vbr_params)
            else:
                records = self.engine.scan_via_signature(self.offset, self.size)
            self.finished.emit(records)
        except Exception as e:
            self.error.emit(str(e))

class PartitionDialog(QDialog):
    def __init__(self, partitions, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Partition")
        self.resize(600, 300)
        self.selected_partition = None
        
        layout = QVBoxLayout(self)
        self.table = QTableWidget(len(partitions), 6)
        self.table.setHorizontalHeaderLabels(["Index", "Type", "Type Name", "Start LBA", "Size", "NTFS?"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        for i, p in enumerate(partitions):
            self.table.setItem(i, 0, QTableWidgetItem(str(p['index'])))
            self.table.setItem(i, 1, QTableWidgetItem(str(p['type'])))
            self.table.setItem(i, 2, QTableWidgetItem(p['type_name']))
            self.table.setItem(i, 3, QTableWidgetItem(str(p['lba_start'])))
            self.table.setItem(i, 4, QTableWidgetItem(str(p['size_bytes'])))
            item_ntfs = QTableWidgetItem(str(p['is_ntfs']))
            if p['is_ntfs']:
                item_ntfs.setBackground(QColor(40, 100, 40))
            self.table.setItem(i, 5, item_ntfs)
            
        layout.addWidget(self.table)
        
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)
        self.table.doubleClicked.connect(self.accept)

    def accept(self):
        row = self.table.currentRow()
        if row >= 0:
            self.selected_partition = row
        super().accept()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MFT Recovery Tool v1.0 — NTFS Forensic Analysis")
        self.resize(1400, 900)
        
        self.disk_handler = None
        self.analyzer = None
        self.engine = None
        self.records = []
        self.is_dark_mode = True
        
        self.setup_ui()
        self.apply_theme()

    def apply_theme(self):
        if self.is_dark_mode:
            self.setStyleSheet("""
                QMainWindow, QDialog { background-color: #1E1E1E; color: #D4D4D4; }
                QWidget { background-color: #252526; color: #D4D4D4; }
                QTreeWidget, QTableWidget { background-color: #1E1E1E; border: 1px solid #3E3E3E; gridline-color: #3E3E3E; }
                QHeaderView::section { background-color: #333333; color: #D4D4D4; padding: 4px; border: 1px solid #3E3E3E; }
                QMenuBar { background-color: #2D2D2D; color: #D4D4D4; }
                QMenuBar::item:selected { background-color: #3E3E3E; }
                QMenu { background-color: #252526; color: #D4D4D4; border: 1px solid #3E3E3E; }
                QMenu::item:selected { background-color: #264F78; }
                QToolBar { background-color: #2D2D2D; color: #D4D4D4; border: none; }
                QStatusBar { background-color: #007ACC; color: white; }
                QTreeWidget::item:selected, QTableWidget::item:selected { background-color: #264F78; color: white; }
                QPushButton { background-color: #333333; color: #D4D4D4; border: 1px solid #555555; padding: 5px 15px; border-radius: 4px; font-weight: bold; }
                QPushButton:hover { background-color: #444444; }
            """)
        else:
            self.setStyleSheet("""
                QMainWindow, QDialog { background-color: #F0F0F0; color: #333333; }
                QWidget { background-color: #FFFFFF; color: #333333; }
                QTreeWidget, QTableWidget { background-color: #FFFFFF; border: 1px solid #CCCCCC; gridline-color: #E0E0E0; }
                QHeaderView::section { background-color: #E0E0E0; color: #333333; padding: 4px; border: 1px solid #CCCCCC; }
                QMenuBar { background-color: #E0E0E0; color: #333333; }
                QMenuBar::item:selected { background-color: #CCCCCC; }
                QMenu { background-color: #FFFFFF; color: #333333; border: 1px solid #CCCCCC; }
                QMenu::item:selected { background-color: #007ACC; color: white; }
                QToolBar { background-color: #E0E0E0; color: #333333; border: none; }
                QStatusBar { background-color: #007ACC; color: white; }
                QTreeWidget::item:selected, QTableWidget::item:selected { background-color: #007ACC; color: white; }
                QPushButton { background-color: #E0E0E0; color: #333333; border: 1px solid #CCCCCC; padding: 5px 15px; border-radius: 4px; font-weight: bold; }
                QPushButton:hover { background-color: #D0D0D0; }
            """)
            
        if hasattr(self, 'hex_view'):
            self.hex_view.is_dark_mode = self.is_dark_mode
            self.hex_view.update()

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.apply_theme()
        if self.is_dark_mode:
            self.theme_btn.setText("☀️ Light Mode")
        else:
            self.theme_btn.setText("🌙 Dark Mode")

    def setup_ui(self):
        # Menu Bar
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        file_menu.addAction("Open Forensic Image", self.open_image, "Ctrl+O")
        file_menu.addAction("Open Live Disk", self.open_live_disk, "Ctrl+L")
        file_menu.addAction("Close Source", self.close_source, "Ctrl+W")
        file_menu.addAction("Exit", self.close, "Ctrl+Q")
        
        view_menu = menubar.addMenu("View")
        self.act_left = view_menu.addAction("Toggle Left Panel", self.toggle_left)
        self.act_right = view_menu.addAction("Toggle Right Panel", self.toggle_right)
        
        tools_menu = menubar.addMenu("Tools")
        tools_menu.addAction("Scan for MFT", self.scan_mft, "F5")
        tools_menu.addAction("Scan for FILE Signatures", self.scan_signatures, "F6")
        
        report_menu = menubar.addMenu("Report")
        report_menu.addAction("Export CSV", lambda: self.export_report('csv'))
        report_menu.addAction("Export JSON", lambda: self.export_report('json'))
        report_menu.addAction("Export PDF", lambda: self.export_report('pdf'))
        
        # Toolbar
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)
        toolbar.addAction("Open Image", self.open_image)
        toolbar.addAction("Open Live", self.open_live_disk)
        toolbar.addAction("Scan", self.scan_mft)
        toolbar.addAction("Report", lambda: self.export_report('csv'))
        
        # Main Layout
        self.splitter = QSplitter(Qt.Horizontal)
        self.setCentralWidget(self.splitter)
        
        # Left Panel
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Recovered Files")
        self.tree.itemClicked.connect(self.on_tree_click)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_tree_context_menu)
        self.splitter.addWidget(self.tree)
        
        # Center Panel
        self.hex_view = HexViewerWidget()
        self.splitter.addWidget(self.hex_view)
        
        # Right Panel
        self.right_panel = QWidget()
        right_layout = QVBoxLayout(self.right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        self.meta_table = QTableWidget(0, 2)
        self.meta_table.setHorizontalHeaderLabels(["Field", "Value"])
        self.meta_table.horizontalHeader().setStretchLastSection(True)
        right_layout.addWidget(self.meta_table)
        
        bottom_right_layout = QHBoxLayout()
        bottom_right_layout.addStretch()
        self.theme_btn = QPushButton("☀️ Light Mode")
        self.theme_btn.setCursor(Qt.PointingHandCursor)
        self.theme_btn.clicked.connect(self.toggle_theme)
        bottom_right_layout.setContentsMargins(0, 5, 10, 10)
        bottom_right_layout.addWidget(self.theme_btn)
        
        right_layout.addLayout(bottom_right_layout)
        self.splitter.addWidget(self.right_panel)
        
        self.splitter.setSizes([int(self.width()*0.25), int(self.width()*0.45), int(self.width()*0.30)])
        
        # Status Bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Ready")

    def toggle_left(self):
        self.tree.setVisible(not self.tree.isVisible())

    def show_tree_context_menu(self, position):
        item = self.tree.itemAt(position)
        if not item: return
        record: MFTRecord = item.data(0, Qt.UserRole)
        if not record or record.is_directory: return
        
        menu = QMenu(self.tree)
        extract_action = QAction("Extract/Save File...", self)
        extract_action.triggered.connect(lambda: self.extract_file(record))
        menu.addAction(extract_action)
        menu.exec(self.tree.viewport().mapToGlobal(position))

    def extract_file(self, record: MFTRecord):
        if not self.disk_handler:
            QMessageBox.critical(self, "Error", "No disk image or drive loaded.")
            return
            
        save_path, _ = QFileDialog.getSaveFileName(self, "Extract File", record.file_name)
        if not save_path: return
        
        try:
            if record.is_resident:
                with open(save_path, 'wb') as f:
                    f.write(record.resident_data)
            else:
                bpc = self.vbr_params.get('bytes_per_cluster', 4096) if hasattr(self, 'vbr_params') and self.vbr_params else 4096
                with open(save_path, 'wb') as f:
                    for cluster_offset, cluster_length in record.data_runs:
                        if cluster_offset == 0:
                            f.write(b'\x00' * (cluster_length * bpc))
                        else:
                            abs_offset = cluster_offset * bpc
                            read_len = cluster_length * bpc
                            chunk = self.disk_handler.read_bytes(abs_offset, read_len)
                            f.write(chunk)
                
                if record.used_size > 0:
                    with open(save_path, 'r+b') as f:
                        f.truncate(record.used_size)
                        
            QMessageBox.information(self, "Success", f"File '{record.file_name}' extracted successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Extraction Error", f"Failed to extract file: {str(e)}")

    def toggle_right(self):
        self.right_panel.setVisible(not self.right_panel.isVisible())

    def open_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Image", "", "Forensic Images (*.dd *.img *.raw *.E01 *.001);;All Files (*.*)")
        if path:
            self.disk_handler = ImageFileHandler()
            if self.disk_handler.open_image(path):
                self.analyzer = PartitionAnalyzer(self.disk_handler)
                self.engine = MFTRecoveryEngine(self.disk_handler)
                self.status.showMessage(f"Loaded: {path}")
                initial_data = self.disk_handler.read_bytes(0, 1024)
                self.hex_view.load_record(initial_data, 0)
                self.detect_partitions()

    def open_live_disk(self):
        path, ok = QInputDialog.getText(self, "Open Live Disk", "Drive path (e.g. \\\\.\\PhysicalDrive0):")
        if ok and path:
            self.disk_handler = LiveDiskHandler()
            try:
                if self.disk_handler.open_live_disk(path):
                    self.analyzer = PartitionAnalyzer(self.disk_handler)
                    self.engine = MFTRecoveryEngine(self.disk_handler)
                    self.status.showMessage(f"Loaded: {path}")
                    initial_data = self.disk_handler.read_bytes(0, 1024)
                    self.hex_view.load_record(initial_data, 0)    
                    self.detect_partitions()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def close_source(self):
        if self.disk_handler:
            self.disk_handler.close()
            self.disk_handler = None
        self.tree.clear()
        self.meta_table.setRowCount(0)
        self.hex_view.load_record(b'', 0)
        self.status.showMessage("Closed source")

    def detect_partitions(self):
        parts = self.analyzer.detect_partitions()
        if not parts:
            QMessageBox.warning(self, "Warning", "No partitions detected")
            return
            
        dlg = PartitionDialog(parts, self)
        if dlg.exec() == QDialog.Accepted and dlg.selected_partition is not None:
            p = parts[dlg.selected_partition]
            self.selected_partition = p
            start_off = p['lba_start'] * 512
            vbr_data = self.disk_handler.read_bytes(start_off, 512)
            self.vbr_params = VBRParser.parse(vbr_data)
            self.status.showMessage(f"Selected partition {dlg.selected_partition}. MFT Size: {self.vbr_params.get('mft_record_size', 1024)}")

    def scan_mft(self):
        if not hasattr(self, 'selected_partition'): return
        p = self.selected_partition
        self.worker = ScanWorker(self.engine, p['lba_start']*512, p['size_bytes'], self.vbr_params)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.start()
        self.status.showMessage("Scanning...")

    def scan_signatures(self):
        if not hasattr(self, 'selected_partition'): return
        p = self.selected_partition
        self.worker = ScanWorker(self.engine, p['lba_start']*512, p['size_bytes'])
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.start()
        self.status.showMessage("Carving signatures...")

    def on_scan_finished(self, records):
        self.records = records
        tree_model = ReconstructionEngine.reconstruct(records)
        self.populate_tree(tree_model)
        self.status.showMessage(f"Scan complete. Found {len(records)} records.")

    def populate_tree(self, tree_model: DirectoryTree):
        self.tree.clear()
        
        def add_node(parent_item, tn: TreeNode):
            item = QTreeWidgetItem(parent_item)
            item.setText(0, tn.record.file_name)
            item.setData(0, Qt.UserRole, tn.record)
            
            if tn.record.is_deleted:
                item.setForeground(0, QColor("#F44747"))
            elif tn.record.is_directory:
                item.setForeground(0, QColor("#4EC9B0"))
                
            for child in tn.children:
                add_node(item, child)
                
        if tree_model.root:
            add_node(self.tree, tree_model.root)

    def on_tree_click(self, item, col):
        record: MFTRecord = item.data(0, Qt.UserRole)
        if record:
            self.hex_view.load_record(record.raw_data, record.disk_offset)
            self.populate_metadata(record)

    def populate_metadata(self, record: MFTRecord):
        self.meta_table.setRowCount(0)
        fields = [
            ("Record Number", str(record.record_number)),
            ("Disk Offset", f"0x{record.disk_offset:X}"),
            ("File Name", record.file_name),
            ("Status", "Active" if record.is_active else "Deleted"),
            ("Is Directory", str(record.is_directory)),
            ("Size", str(record.used_size)),
            ("Created", str(record.created_time)),
            ("Modified", str(record.modified_time)),
            ("Data Resident", str(record.is_resident)),
            ("Recovery Confidence", record.recovery_confidence)
        ]
        
        self.meta_table.setRowCount(len(fields))
        for i, (k, v) in enumerate(fields):
            self.meta_table.setItem(i, 0, QTableWidgetItem(k))
            self.meta_table.setItem(i, 1, QTableWidgetItem(v))

    def export_report(self, fmt):
        if not self.records: return
        path, _ = QFileDialog.getSaveFileName(self, "Export", "", f"{fmt.upper()} (*.{fmt})")
        if path:
            if fmt == 'csv':
                ReportGenerator.export_csv(path, self.records)
            elif fmt == 'json':
                ReportGenerator.export_json(path, self.records)
            elif fmt == 'pdf':
                ReportGenerator.export_pdf(path, self.records)
            QMessageBox.information(self, "Success", f"Exported {len(self.records)} records to {path}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("MFT Recovery Tool")
    app.setOrganizationName("ForensicsLab")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
