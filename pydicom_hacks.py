# SPDX-License-Identifier: GPL-2.0-only
"""
pydicom Hacks - Extract maximum value from pydicom while bypassing validation.

This module "hacks" pydicom in the best sense - using its sophisticated
internals (VR tables, transfer syntax machinery, element parsing) while
bypassing its validation to produce malformed output.

Key Strategies:
    1. Use pydicom's READING (it handles all transfer syntaxes, sequences, etc.)
    2. Bypass pydicom's WRITING (use our own encoders that don't validate)
    3. Steal pydicom's KNOWLEDGE (VR tables, tag dictionaries, UID registries)

Example:
    from dicom_hacker.pydicom_hacks import (
        PydicomExtractor,    # Extract raw bytes from pydicom datasets
        VRTable,             # Access pydicom's VR definitions
        TagDict,             # Access pydicom's tag dictionary
        UIDRegistry,         # Access pydicom's UID registry
        steal_encoders,      # Get pydicom's internal encoders
    )
    
    # Extract element bytes while corrupting
    extractor = PydicomExtractor(pydicom_dataset)
    for tag, raw_bytes, info in extractor.extract_all():
        # raw_bytes contains pydicom's properly encoded element
        # Now we can corrupt it surgically
        corrupted = corrupt_byte(raw_bytes, offset=4, value=0xFF)

    # Get all VR definitions
    for vr, info in VRTable.items():
        print(f"{vr}: length_field={info['length_size']}, padding={info['padding']}")
"""

from typing import (
    Any, Callable, Dict, Generator, List, Optional, Tuple, Union,
    TYPE_CHECKING
)
from dataclasses import dataclass, field
from io import BytesIO
import struct
import re

# Optional pydicom import
try:
    import pydicom
    from pydicom.dataelem import DataElement, RawDataElement
    from pydicom.dataset import Dataset as PydicomDataset
    from pydicom.sequence import Sequence as PydicomSequence
    from pydicom.tag import Tag as PydicomTag, BaseTag
    from pydicom.uid import UID
    from pydicom.valuerep import VR as PydicomVR
    from pydicom import datadict
    from pydicom import uid as uid_module
    from pydicom.charset import default_encoding
    from pydicom.filewriter import write_data_element
    HAS_PYDICOM = True
except ImportError:
    HAS_PYDICOM = False

__all__ = [
    # Core utilities
    'PydicomExtractor',
    'VRTable',
    'TagDict',
    'UIDRegistry',
    
    # Encoder stealing
    'steal_element_encoder',
    'steal_sequence_encoder',
    'encode_element_raw',
    
    # VR manipulation
    'get_vr_for_tag',
    'get_default_vr',
    'get_vr_length_field_size',
    'is_vr_valid',
    'get_all_vrs',
    
    # Tag manipulation
    'get_tag_info',
    'get_private_creator_tag',
    'get_all_tags_for_keyword',
    
    # UID utilities
    'get_uid_info',
    'get_all_sop_classes',
    'get_all_transfer_syntaxes',
    'generate_uid',
    
    # Encoding bypass
    'encode_with_wrong_vr',
    'encode_with_wrong_endian',
    'encode_implicit_as_explicit',
    'encode_explicit_as_implicit',
    
    # Element extraction
    'extract_element_bytes',
    'extract_sequence_bytes',
    'extract_pixel_data_bytes',
]


# =============================================================================
# VR Table - Steal pydicom's VR knowledge
# =============================================================================

class _VRTable:
    """
    Access to pydicom's VR definitions.
    
    pydicom knows exactly how each VR should be encoded - length field sizes,
    padding characters, value representations. We steal this knowledge.
    """
    
    # VR categories per DICOM PS3.5
    _SHORT_LENGTH_VRS = {'AE', 'AS', 'AT', 'CS', 'DA', 'DS', 'DT', 'FL', 'FD',
                         'IS', 'LO', 'LT', 'PN', 'SH', 'SL', 'SS', 'ST', 'TM',
                         'UI', 'UL', 'US'}
    
    _LONG_LENGTH_VRS = {'OB', 'OD', 'OF', 'OL', 'OW', 'SQ', 'UC', 'UN', 'UR', 'UT'}
    
    _STRING_VRS = {'AE', 'AS', 'CS', 'DA', 'DS', 'DT', 'IS', 'LO', 'LT',
                   'PN', 'SH', 'ST', 'TM', 'UI', 'UC', 'UR', 'UT'}
    
    _BINARY_VRS = {'AT', 'FL', 'FD', 'OB', 'OD', 'OF', 'OL', 'OW', 'SL', 'SS',
                   'UL', 'US', 'UN'}
    
    _PADDING = {
        'UI': b'\x00',  # UID padded with null
        'OB': b'\x00',
        'UN': b'\x00',
        # Everything else padded with space
    }
    
    def __init__(self):
        self._cache = {}
        self._build_cache()
    
    def _build_cache(self):
        """Build VR information cache."""
        all_vrs = (self._SHORT_LENGTH_VRS | self._LONG_LENGTH_VRS)
        
        for vr in all_vrs:
            is_short = vr in self._SHORT_LENGTH_VRS
            self._cache[vr] = {
                'vr': vr,
                'length_size': 2 if is_short else 4,  # In explicit VR
                'has_reserved': not is_short,  # 2-byte reserved before length
                'is_string': vr in self._STRING_VRS,
                'is_binary': vr in self._BINARY_VRS,
                'padding': self._PADDING.get(vr, b' '),
                'max_length': 0xFFFF if is_short else 0xFFFFFFFF,
            }
        
        # Add pydicom-specific info if available
        if HAS_PYDICOM:
            try:
                for vr_name in dir(PydicomVR):
                    if len(vr_name) == 2 and vr_name.isupper():
                        vr_obj = getattr(PydicomVR, vr_name, None)
                        if vr_obj and vr_name in self._cache:
                            # Add any extra pydicom info
                            pass
            except Exception:
                pass
    
    def __getitem__(self, vr: str) -> Dict[str, Any]:
        """Get VR info."""
        if vr in self._cache:
            return self._cache[vr]
        # Unknown VR - treat as long binary
        return {
            'vr': vr,
            'length_size': 4,
            'has_reserved': True,
            'is_string': False,
            'is_binary': True,
            'padding': b'\x00',
            'max_length': 0xFFFFFFFF,
        }
    
    def __contains__(self, vr: str) -> bool:
        return vr in self._cache
    
    def items(self):
        return self._cache.items()
    
    def keys(self):
        return self._cache.keys()
    
    def values(self):
        return self._cache.values()
    
    def is_valid(self, vr: str) -> bool:
        """Check if VR is valid per DICOM standard."""
        return vr in self._cache
    
    def get_all_invalid_vrs(self) -> List[str]:
        """Generate list of invalid VR codes for fuzzing."""
        invalid = []
        for c1 in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789':
            for c2 in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789':
                vr = c1 + c2
                if vr not in self._cache:
                    invalid.append(vr)
        return invalid


VRTable = _VRTable()


# =============================================================================
# Tag Dictionary - Steal pydicom's tag knowledge
# =============================================================================

class _TagDict:
    """
    Access to pydicom's tag dictionary.
    
    pydicom has a comprehensive mapping of tags to names, VRs, and VMs.
    We steal this for intelligent fuzzing.
    """
    
    def __init__(self):
        self._cache = {}
    
    def get(self, tag: Union[int, Tuple[int, int]], default=None) -> Optional[Dict]:
        """Get tag information."""
        if isinstance(tag, tuple):
            tag = (tag[0] << 16) | tag[1]
        
        if tag in self._cache:
            return self._cache[tag]
        
        if not HAS_PYDICOM:
            return default
        
        try:
            # Use pydicom's datadict
            entry = datadict.get_entry(tag)
            if entry:
                info = {
                    'tag': tag,
                    'vr': entry[0],
                    'vm': entry[1],
                    'name': entry[2],
                    'keyword': entry[3] if len(entry) > 3 else entry[2].replace(' ', ''),
                    'retired': entry[4] if len(entry) > 4 else False,
                }
                self._cache[tag] = info
                return info
        except Exception:
            pass
        
        return default
    
    def get_vr(self, tag: Union[int, Tuple[int, int]]) -> Optional[str]:
        """Get the VR for a tag."""
        info = self.get(tag)
        return info['vr'] if info else None
    
    def get_keyword(self, tag: Union[int, Tuple[int, int]]) -> Optional[str]:
        """Get the keyword for a tag."""
        info = self.get(tag)
        return info['keyword'] if info else None
    
    def find_by_keyword(self, keyword: str) -> Optional[int]:
        """Find tag by keyword."""
        if not HAS_PYDICOM:
            return None
        try:
            return datadict.tag_for_keyword(keyword)
        except Exception:
            return None
    
    def get_all_tags_with_vr(self, vr: str) -> List[int]:
        """Get all tags that use a specific VR."""
        tags = []
        if not HAS_PYDICOM:
            return tags
        
        try:
            # Iterate through pydicom's datadict
            for tag in datadict.DicomDictionary:
                entry = datadict.DicomDictionary.get(tag)
                if entry and entry[0] == vr:
                    tags.append(tag)
        except Exception:
            pass
        
        return tags


TagDict = _TagDict()


# =============================================================================
# UID Registry - Steal pydicom's UID knowledge
# =============================================================================

class _UIDRegistry:
    """
    Access to pydicom's UID registry.
    
    pydicom knows all standard UIDs - SOP classes, transfer syntaxes, etc.
    We steal this for intelligent test generation.
    """
    
    def __init__(self):
        self._sop_classes = {}
        self._transfer_syntaxes = {}
        self._build_cache()
    
    def _build_cache(self):
        """Build UID caches from pydicom."""
        if not HAS_PYDICOM:
            return
        
        try:
            # Get all UIDs from pydicom's uid module
            for name in dir(uid_module):
                obj = getattr(uid_module, name)
                if isinstance(obj, UID):
                    uid_str = str(obj)
                    info = {
                        'uid': uid_str,
                        'name': name,
                        'keyword': getattr(obj, 'keyword', name),
                    }
                    
                    # Categorize
                    if 'Transfer' in name or 'transfer' in name.lower():
                        self._transfer_syntaxes[uid_str] = info
                    elif 'Storage' in name or 'SOP' in name:
                        self._sop_classes[uid_str] = info
        except Exception:
            pass
    
    def get_sop_classes(self) -> Dict[str, Dict]:
        """Get all SOP class UIDs."""
        return self._sop_classes
    
    def get_transfer_syntaxes(self) -> Dict[str, Dict]:
        """Get all transfer syntax UIDs."""
        return self._transfer_syntaxes
    
    def is_valid_uid(self, uid: str) -> bool:
        """Check if UID is syntactically valid."""
        # UID must be <= 64 chars, only digits and dots, no leading/trailing dots
        if len(uid) > 64:
            return False
        if not re.match(r'^[0-9]+(\.[0-9]+)*$', uid):
            return False
        return True
    
    def generate_uid(self, prefix: str = '1.2.826.0.1.3680043.8.1234.') -> str:
        """Generate a random UID with given prefix."""
        import random
        suffix = '.'.join(str(random.randint(1, 99999)) for _ in range(3))
        return prefix + suffix


UIDRegistry = _UIDRegistry()


# =============================================================================
# Pydicom Extractor - Extract bytes from pydicom datasets
# =============================================================================

@dataclass
class ExtractedElement:
    """Information about an extracted element."""
    tag: int
    vr: str
    value: Any
    raw_bytes: bytes
    offset: int = 0  # Offset in original file/stream
    is_sequence: bool = False
    sequence_items: List['ExtractedElement'] = field(default_factory=list)


class PydicomExtractor:
    """
    Extract raw bytes from pydicom datasets.
    
    This class takes a pydicom Dataset and extracts the raw bytes for each
    element, BEFORE any manipulation. This lets us:
    
    1. See exactly how pydicom encoded something
    2. Modify specific bytes while keeping the rest intact
    3. Extract elements in transfer-syntax-aware format
    
    Example:
        ds = pydicom.dcmread("ct.dcm")
        extractor = PydicomExtractor(ds)
        
        for elem in extractor.extract_all():
            print(f"Tag {elem.tag:08X}: {len(elem.raw_bytes)} bytes")
            # Corrupt specific byte
            corrupted = bytearray(elem.raw_bytes)
            corrupted[4] = 0xFF  # Corrupt length byte
            send_to_target(bytes(corrupted))
    """
    
    def __init__(self, dataset, transfer_syntax: str = '1.2.840.10008.1.2.1'):
        """
        Initialize extractor.
        
        Args:
            dataset: pydicom Dataset to extract from
            transfer_syntax: Transfer syntax UID (determines encoding)
        """
        if not HAS_PYDICOM:
            raise ImportError("pydicom required for PydicomExtractor")
        
        self.dataset = dataset
        self.transfer_syntax = transfer_syntax
        
        # Determine encoding parameters
        self.implicit_vr = transfer_syntax == '1.2.840.10008.1.2'
        self.little_endian = transfer_syntax != '1.2.840.10008.1.2.2'
    
    def extract_element(self, tag: Union[int, Tuple[int, int]]) -> Optional[ExtractedElement]:
        """Extract a single element."""
        if isinstance(tag, tuple):
            tag = (tag[0] << 16) | tag[1]
        
        try:
            # Get element from dataset
            elem = self.dataset[tag]
            raw_bytes = self._encode_element(elem)
            
            return ExtractedElement(
                tag=tag,
                vr=elem.VR,
                value=elem.value,
                raw_bytes=raw_bytes,
                is_sequence=(elem.VR == 'SQ'),
            )
        except KeyError:
            return None
    
    def extract_all(self) -> Generator[ExtractedElement, None, None]:
        """Extract all elements as raw bytes."""
        for elem in self.dataset:
            raw_bytes = self._encode_element(elem)
            
            yield ExtractedElement(
                tag=int(elem.tag),
                vr=elem.VR,
                value=elem.value,
                raw_bytes=raw_bytes,
                is_sequence=(elem.VR == 'SQ'),
            )
    
    def _encode_element(self, elem: DataElement) -> bytes:
        """Encode a single element to bytes using pydicom's encoder."""
        buf = BytesIO()
        
        try:
            # Use pydicom's write_data_element
            write_data_element(
                buf, elem,
                not self.implicit_vr,  # is_explicit_VR
                self.little_endian,
            )
            return buf.getvalue()
        except Exception:
            # Fallback: manual encoding
            return self._manual_encode_element(elem)
    
    def _manual_encode_element(self, elem: DataElement) -> bytes:
        """Manual element encoding when pydicom fails."""
        buf = BytesIO()
        tag = int(elem.tag)
        group = (tag >> 16) & 0xFFFF
        element_num = tag & 0xFFFF
        
        endian = '<' if self.little_endian else '>'
        
        # Write tag
        buf.write(struct.pack(f'{endian}HH', group, element_num))
        
        # Get value bytes
        value_bytes = self._get_value_bytes(elem)
        
        if self.implicit_vr:
            # Implicit VR: tag (4) + length (4) + value
            buf.write(struct.pack(f'{endian}I', len(value_bytes)))
        else:
            # Explicit VR: tag (4) + VR (2) + length (2 or 4) + value
            vr = elem.VR if elem.VR else 'UN'
            buf.write(vr.encode('ascii')[:2].ljust(2))
            
            vr_info = VRTable[vr]
            if vr_info['has_reserved']:
                # 2 bytes reserved + 4 bytes length
                buf.write(b'\x00\x00')
                buf.write(struct.pack(f'{endian}I', len(value_bytes)))
            else:
                # 2 bytes length
                buf.write(struct.pack(f'{endian}H', len(value_bytes)))
        
        buf.write(value_bytes)
        return buf.getvalue()
    
    def _get_value_bytes(self, elem: DataElement) -> bytes:
        """Get value as bytes."""
        if elem.value is None:
            return b''
        
        if isinstance(elem.value, bytes):
            return elem.value
        
        if isinstance(elem.value, str):
            return elem.value.encode('utf-8')
        
        if isinstance(elem.value, (int, float)):
            vr = elem.VR
            endian = '<' if self.little_endian else '>'
            
            if vr in ('US', 'SS'):
                fmt = f'{endian}h' if vr == 'SS' else f'{endian}H'
                return struct.pack(fmt, int(elem.value))
            elif vr in ('UL', 'SL'):
                fmt = f'{endian}i' if vr == 'SL' else f'{endian}I'
                return struct.pack(fmt, int(elem.value))
            elif vr == 'FL':
                return struct.pack(f'{endian}f', float(elem.value))
            elif vr == 'FD':
                return struct.pack(f'{endian}d', float(elem.value))
        
        # Default: convert to string
        return str(elem.value).encode('utf-8')


# =============================================================================
# Encoding Bypass - Encode with intentionally wrong parameters
# =============================================================================

def encode_with_wrong_vr(
    dataset,
    tag: Union[int, Tuple[int, int]],
    wrong_vr: str,
    transfer_syntax: str = '1.2.840.10008.1.2.1'
) -> bytes:
    """
    Encode a dataset element with intentionally wrong VR.
    
    This extracts an element and re-encodes it with a different VR code,
    keeping the value bytes the same. Useful for testing VR validation.
    
    Args:
        dataset: pydicom Dataset
        tag: Tag to extract
        wrong_vr: VR to use instead of correct one
        transfer_syntax: Transfer syntax for encoding
    
    Returns:
        Encoded element bytes with wrong VR
    """
    if not HAS_PYDICOM:
        raise ImportError("pydicom required")
    
    extractor = PydicomExtractor(dataset, transfer_syntax)
    elem = extractor.extract_element(tag)
    
    if elem is None:
        raise KeyError(f"Tag {tag} not found in dataset")
    
    # Re-encode with wrong VR
    from .element import Element
    
    return Element.raw(
        tag=elem.tag,
        vr=wrong_vr,
        value=elem.raw_bytes[8:] if len(elem.raw_bytes) > 8 else b'',
    ).encode(implicit_vr=(transfer_syntax == '1.2.840.10008.1.2'))


def encode_with_wrong_endian(
    dataset,
    tag: Union[int, Tuple[int, int]],
    transfer_syntax: str = '1.2.840.10008.1.2.1'
) -> bytes:
    """
    Encode dataset element with swapped endianness.
    
    Takes an element encoded in one endianness and swaps the byte order
    of multi-byte numeric fields.
    """
    if not HAS_PYDICOM:
        raise ImportError("pydicom required")
    
    extractor = PydicomExtractor(dataset, transfer_syntax)
    elem = extractor.extract_element(tag)
    
    if elem is None:
        raise KeyError(f"Tag {tag} not found in dataset")
    
    # Swap endianness of numeric value
    raw = bytearray(elem.raw_bytes)
    
    # Swap tag bytes (group and element)
    raw[0:2] = raw[0:2][::-1]
    raw[2:4] = raw[2:4][::-1]
    
    # If numeric value, swap those bytes too
    if elem.vr in ('US', 'SS'):
        raw[8:10] = raw[8:10][::-1]
    elif elem.vr in ('UL', 'SL', 'FL'):
        raw[8:12] = raw[8:12][::-1]
    elif elem.vr == 'FD':
        raw[8:16] = raw[8:16][::-1]
    
    return bytes(raw)


def encode_implicit_as_explicit(
    dataset,
    tag: Union[int, Tuple[int, int]],
) -> bytes:
    """
    Take implicitly-encoded element and add explicit VR header.
    
    This creates a malformed element where the value bytes are from
    implicit VR encoding but the header says explicit VR.
    """
    if not HAS_PYDICOM:
        raise ImportError("pydicom required")
    
    # Extract with implicit VR
    extractor = PydicomExtractor(dataset, '1.2.840.10008.1.2')
    elem = extractor.extract_element(tag)
    
    if elem is None:
        raise KeyError(f"Tag {tag} not found in dataset")
    
    # Get value portion (skip 8 byte implicit header: tag 4 + length 4)
    value_bytes = elem.raw_bytes[8:] if len(elem.raw_bytes) > 8 else b''
    
    # Encode with explicit VR using our encoder
    from .element import Element
    return Element.raw(
        tag=elem.tag,
        vr=elem.vr,
        value=value_bytes,
    ).encode(implicit_vr=False)


def encode_explicit_as_implicit(
    dataset,
    tag: Union[int, Tuple[int, int]],
) -> bytes:
    """
    Take explicitly-encoded element and encode as implicit VR.
    
    Strips the VR from the encoding, potentially confusing parsers.
    """
    if not HAS_PYDICOM:
        raise ImportError("pydicom required")
    
    # Extract with explicit VR
    extractor = PydicomExtractor(dataset, '1.2.840.10008.1.2.1')
    elem = extractor.extract_element(tag)
    
    if elem is None:
        raise KeyError(f"Tag {tag} not found in dataset")
    
    # Calculate value offset based on VR
    vr_info = VRTable[elem.vr]
    if vr_info['has_reserved']:
        value_offset = 12  # tag 4 + vr 2 + reserved 2 + length 4
    else:
        value_offset = 8   # tag 4 + vr 2 + length 2
    
    value_bytes = elem.raw_bytes[value_offset:] if len(elem.raw_bytes) > value_offset else b''
    
    # Encode as implicit VR
    from .element import Element
    return Element.raw(
        tag=elem.tag,
        vr=elem.vr,
        value=value_bytes,
    ).encode(implicit_vr=True)


# =============================================================================
# Convenience Functions
# =============================================================================

def get_vr_for_tag(tag: Union[int, Tuple[int, int]]) -> Optional[str]:
    """Get the correct VR for a tag."""
    return TagDict.get_vr(tag)


def get_default_vr(tag: Union[int, Tuple[int, int]] = None) -> str:
    """Get a sensible default VR."""
    if tag:
        vr = get_vr_for_tag(tag)
        if vr:
            return vr
    return 'LO'  # Long string is a safe default


def get_vr_length_field_size(vr: str, explicit: bool = True) -> int:
    """Get the size of the length field for a VR."""
    if not explicit:
        return 4  # Always 4 bytes in implicit VR
    
    info = VRTable[vr]
    return info['length_size']


def is_vr_valid(vr: str) -> bool:
    """Check if a VR is valid."""
    return VRTable.is_valid(vr)


def get_all_vrs() -> List[str]:
    """Get all valid VRs."""
    return list(VRTable.keys())


def get_tag_info(tag: Union[int, Tuple[int, int]]) -> Optional[Dict]:
    """Get full info about a tag."""
    return TagDict.get(tag)


def get_private_creator_tag(group: int, element: int) -> int:
    """
    Calculate the private creator tag for a private element.
    
    Private elements (odd group, element >= 0x1000) need a private
    creator element in the same group with element = block number.
    """
    if group % 2 == 0:
        raise ValueError("Private tags must have odd group number")
    if element < 0x1000:
        raise ValueError("Private element number must be >= 0x1000")
    
    block = (element >> 8) & 0xFF
    return (group << 16) | block


def get_all_tags_for_keyword(keyword: str) -> Optional[int]:
    """Get tag for a keyword."""
    return TagDict.find_by_keyword(keyword)


def get_uid_info(uid: str) -> Optional[Dict]:
    """Get info about a UID."""
    if uid in UIDRegistry._sop_classes:
        return UIDRegistry._sop_classes[uid]
    if uid in UIDRegistry._transfer_syntaxes:
        return UIDRegistry._transfer_syntaxes[uid]
    return None


def get_all_sop_classes() -> Dict[str, Dict]:
    """Get all SOP class UIDs."""
    return UIDRegistry.get_sop_classes()


def get_all_transfer_syntaxes() -> Dict[str, Dict]:
    """Get all transfer syntax UIDs."""
    return UIDRegistry.get_transfer_syntaxes()


def generate_uid(prefix: str = None) -> str:
    """Generate a random valid UID."""
    if prefix is None:
        prefix = '1.2.826.0.1.3680043.8.1234.'
    return UIDRegistry.generate_uid(prefix)
