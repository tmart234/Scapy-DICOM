# SPDX-License-Identifier: GPL-2.0-only
"""
DICOM Pixel Data handling with fragment-level control.

Encapsulated pixel data (JPEG, JPEG2000, RLE) uses a fragment structure:
    PixelData (7FE0,0010) OB
    ├── Item (offset table) - may be empty
    ├── Item (fragment 1)
    ├── Item (fragment 2)
    ├── ...
    └── Sequence Delimitation Item

This module allows manipulation of individual fragments for fuzzing.

Example:
    from dicom_hacker.pixel import EncapsulatedPixelData, PixelData
    
    # Build encapsulated pixel data
    epd = EncapsulatedPixelData()
    epd.add_fragment(jpeg_frame_1)
    epd.add_fragment(jpeg_frame_2)
    
    # Corrupt offset table
    epd.set_offset_table([0x00, 0x1000, 0x2000])  # Wrong offsets
    
    # Corrupt a fragment
    epd.corrupt_fragment(0, lambda data: data + b'\\x00' * 100)
    
    # Create element
    elem = Element(0x7FE0, 0x0010, 'OB', epd)
"""

import struct
from io import BytesIO
from typing import Callable, List, Optional, Union

__all__ = [
    'EncapsulatedPixelData',
    'PixelData',
    'Fragment',
]


# Item tags (little endian)
ITEM_TAG_LE = b'\xFE\xFF\x00\xE0'
ITEM_TAG_BE = b'\xFF\xFE\xE0\x00'
SEQ_DELIM_TAG_LE = b'\xFE\xFF\xDD\xE0'
SEQ_DELIM_TAG_BE = b'\xFF\xFE\xDD\xE0'


class Fragment:
    """
    Single fragment in encapsulated pixel data.
    
    Allows full control over fragment bytes.
    """
    
    def __init__(self, data: bytes = b'', length_override: int = None):
        self.data = data
        self.length_override = length_override
    
    def encode(self, little_endian: bool = True) -> bytes:
        """Encode as Item."""
        bio = BytesIO()
        
        # Item tag
        bio.write(ITEM_TAG_LE if little_endian else ITEM_TAG_BE)
        
        # Length
        length = self.length_override if self.length_override is not None else len(self.data)
        fmt = '<I' if little_endian else '>I'
        bio.write(struct.pack(fmt, length))
        
        # Data
        bio.write(self.data)
        
        # Pad to even if needed
        if len(self.data) % 2:
            bio.write(b'\x00')
        
        return bio.getvalue()


class EncapsulatedPixelData:
    """
    Encapsulated (compressed) pixel data with fragment-level control.
    
    Structure:
        - Offset table (first item, may be empty)
        - Fragments (one or more items)
        - Sequence delimitation item
    
    Usage:
        epd = EncapsulatedPixelData()
        epd.add_fragment(jpeg_data_1)
        epd.add_fragment(jpeg_data_2)
        
        # Corrupt offset table
        epd.set_offset_table_raw(b'\\x00\\x00\\x00\\x00\\xFF\\xFF\\xFF\\xFF')
        
        # Corrupt fragment
        epd.set_fragment(0, corrupt_jpeg(jpeg_data_1))
        
        # Get bytes
        raw = epd.encode()
    """
    
    def __init__(self):
        self.offset_table: Optional[bytes] = None  # Raw offset table bytes
        self.offset_table_offsets: Optional[List[int]] = None  # Computed offsets
        self.fragments: List[Fragment] = []
        self.include_delimiter = True
        
        # Override options
        self._raw_offset_table_length: Optional[int] = None
        
    def add_fragment(self, data: bytes, length_override: int = None) -> 'EncapsulatedPixelData':
        """Add a fragment."""
        self.fragments.append(Fragment(data, length_override))
        return self
    
    def set_fragment(self, index: int, data: bytes, length_override: int = None) -> 'EncapsulatedPixelData':
        """Set fragment data at index."""
        if index < len(self.fragments):
            self.fragments[index] = Fragment(data, length_override)
        return self
    
    def corrupt_fragment(self, index: int, 
                         corruptor: Callable[[bytes], bytes]) -> 'EncapsulatedPixelData':
        """Apply corruption function to fragment."""
        if index < len(self.fragments):
            self.fragments[index].data = corruptor(self.fragments[index].data)
        return self
    
    def set_offset_table(self, offsets: List[int]) -> 'EncapsulatedPixelData':
        """Set offset table from list of offsets."""
        self.offset_table_offsets = offsets
        self.offset_table = None  # Clear raw override
        return self
    
    def set_offset_table_raw(self, data: bytes, 
                             length_override: int = None) -> 'EncapsulatedPixelData':
        """Set raw offset table bytes."""
        self.offset_table = data
        self.offset_table_offsets = None
        self._raw_offset_table_length = length_override
        return self
    
    def clear_offset_table(self) -> 'EncapsulatedPixelData':
        """Set empty offset table."""
        self.offset_table = b''
        self.offset_table_offsets = None
        return self
    
    def compute_offset_table(self) -> 'EncapsulatedPixelData':
        """Compute correct offset table from fragments."""
        offsets = []
        offset = 0
        
        for frag in self.fragments:
            offsets.append(offset)
            # Each fragment: 4 (tag) + 4 (length) + data (padded to even)
            data_len = len(frag.data)
            if data_len % 2:
                data_len += 1
            offset += 8 + data_len
        
        self.offset_table_offsets = offsets
        self.offset_table = None
        return self
    
    def _encode_offset_table(self, little_endian: bool) -> bytes:
        """Encode offset table item."""
        bio = BytesIO()
        
        # Item tag
        bio.write(ITEM_TAG_LE if little_endian else ITEM_TAG_BE)
        
        # Get offset table data
        if self.offset_table is not None:
            # Raw override
            data = self.offset_table
        elif self.offset_table_offsets:
            # Encode offsets
            fmt = '<I' if little_endian else '>I'
            data = b''.join(struct.pack(fmt, o) for o in self.offset_table_offsets)
        else:
            # Empty offset table
            data = b''
        
        # Length
        length = self._raw_offset_table_length if self._raw_offset_table_length is not None else len(data)
        fmt = '<I' if little_endian else '>I'
        bio.write(struct.pack(fmt, length))
        
        # Data
        bio.write(data)
        
        return bio.getvalue()
    
    def encode(self, little_endian: bool = True) -> bytes:
        """Encode complete pixel data value."""
        bio = BytesIO()
        
        # Offset table (first item)
        bio.write(self._encode_offset_table(little_endian))
        
        # Fragments
        for frag in self.fragments:
            bio.write(frag.encode(little_endian))
        
        # Sequence delimitation
        if self.include_delimiter:
            bio.write(SEQ_DELIM_TAG_LE if little_endian else SEQ_DELIM_TAG_BE)
            bio.write(b'\x00\x00\x00\x00')
        
        return bio.getvalue()
    
    @classmethod
    def parse(cls, data: bytes, little_endian: bool = True) -> 'EncapsulatedPixelData':
        """Parse encapsulated pixel data."""
        epd = cls()
        pos = 0
        first_item = True
        
        while pos < len(data) - 8:
            # Read tag
            tag = data[pos:pos+4]
            pos += 4
            
            # Check for sequence delimitation
            if tag == SEQ_DELIM_TAG_LE or tag == SEQ_DELIM_TAG_BE:
                break
            
            # Check for item tag
            if tag != ITEM_TAG_LE and tag != ITEM_TAG_BE:
                break
            
            # Read length
            fmt = '<I' if little_endian else '>I'
            length = struct.unpack(fmt, data[pos:pos+4])[0]
            pos += 4
            
            # Read data
            item_data = data[pos:pos+length]
            pos += length
            
            if first_item:
                # Offset table
                epd.offset_table = item_data
                first_item = False
            else:
                # Fragment
                epd.add_fragment(item_data)
            
            # Skip padding
            if length % 2:
                pos += 1
        
        return epd
    
    @classmethod
    def from_pydicom(cls, elem) -> 'EncapsulatedPixelData':
        """Create from pydicom pixel data element."""
        epd = cls()
        
        if hasattr(elem, 'value') and hasattr(elem.value, '__iter__'):
            for i, fragment in enumerate(elem.value):
                if hasattr(fragment, 'tobytes'):
                    epd.add_fragment(fragment.tobytes())
                elif isinstance(fragment, bytes):
                    epd.add_fragment(fragment)
        
        return epd


class PixelData:
    """
    Native (uncompressed) pixel data with dimension control.
    
    Allows creating pixel data with mismatched dimensions for fuzzing.
    
    Usage:
        pd = PixelData(rows=512, cols=512, bits=16)
        pd.set_data(b'\\x00' * 100)  # Much smaller than expected
        
        # Or with dimension mismatch
        pd = PixelData.dimension_mismatch(
            declared_rows=512,
            declared_cols=512,
            actual_data=b'\\x00' * 100
        )
    """
    
    def __init__(self, rows: int = 256, cols: int = 256, 
                 bits_allocated: int = 16, samples_per_pixel: int = 1,
                 data: bytes = None):
        self.rows = rows
        self.cols = cols
        self.bits_allocated = bits_allocated
        self.samples_per_pixel = samples_per_pixel
        self.data = data
        
    def expected_size(self) -> int:
        """Calculate expected pixel data size."""
        bytes_per_sample = self.bits_allocated // 8
        return self.rows * self.cols * self.samples_per_pixel * bytes_per_sample
    
    def set_data(self, data: bytes) -> 'PixelData':
        """Set raw pixel data."""
        self.data = data
        return self
    
    def generate_data(self, pattern: bytes = b'\x00') -> 'PixelData':
        """Generate pixel data of expected size."""
        size = self.expected_size()
        self.data = (pattern * (size // len(pattern) + 1))[:size]
        return self
    
    def encode(self, little_endian: bool = True) -> bytes:
        """Return pixel data bytes."""
        if self.data:
            return self.data
        return self.generate_data().data
    
    @classmethod
    def dimension_mismatch(cls, declared_rows: int, declared_cols: int,
                           actual_data: bytes, bits: int = 16) -> 'PixelData':
        """Create pixel data with dimension mismatch."""
        pd = cls(rows=declared_rows, cols=declared_cols, bits_allocated=bits)
        pd.data = actual_data
        return pd
    
    @classmethod
    def overflow_dimensions(cls, bits: int = 16) -> 'PixelData':
        """Create pixel data with overflow dimensions."""
        pd = cls(rows=0xFFFF, cols=0xFFFF, bits_allocated=bits)
        pd.data = b'\x00' * 100
        return pd
    
    @classmethod  
    def zero_dimensions(cls, bits: int = 16) -> 'PixelData':
        """Create pixel data with zero dimensions."""
        pd = cls(rows=0, cols=0, bits_allocated=bits)
        pd.data = b'\x00' * 100
        return pd


# =============================================================================
# Corruption Helpers
# =============================================================================

def corrupt_jpeg_header(data: bytes) -> bytes:
    """Corrupt JPEG header (SOI marker)."""
    if len(data) >= 2 and data[:2] == b'\xFF\xD8':
        return b'\xFF\x00' + data[2:]
    return data


def corrupt_jpeg_eoi(data: bytes) -> bytes:
    """Remove JPEG EOI marker."""
    if len(data) >= 2 and data[-2:] == b'\xFF\xD9':
        return data[:-2]
    return data


def truncate_fragment(data: bytes, keep: int) -> bytes:
    """Truncate fragment to specific size."""
    return data[:keep]


def duplicate_bytes(data: bytes, offset: int, count: int) -> bytes:
    """Duplicate bytes at offset."""
    return data[:offset] + data[offset:offset+count] * 2 + data[offset+count:]
