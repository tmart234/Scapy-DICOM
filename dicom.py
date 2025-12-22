# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Tyler M

# scapy.contrib.description = DICOM (Digital Imaging and Communications in Medicine)
# scapy.contrib.status = loads

"""
DICOM (Digital Imaging and Communications in Medicine) Protocol

This module provides Scapy layers for the DICOM Upper Layer Protocol,
enabling packet crafting, parsing, and network analysis of DICOM
communications commonly used in medical imaging systems.

Reference: DICOM PS3.8 - Network Communication Support for Message Exchange
https://dicom.nema.org/medical/dicom/current/output/html/part08.html

Architecture Notes (v2.0 Refactor):
- Random fields use native Scapy RandChoice/RandString instead of custom classes
- DIMSE fields inherit from LEShortField/LEIntField with a TLV mixin
- Single smart packet classes handle both valid and fuzzing modes
- Session management uses scapy.automaton for robust state handling
- Length fields are explicit in fields_desc for fuzz targeting
"""

import logging
import random
import struct

from scapy.automaton import ATMT, Automaton
from scapy.config import conf
from scapy.data import DADict
from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    IntField,
    LEIntField,
    LEShortField,
    LenField,
    PacketField,
    PacketListField,
    ShortField,
    StrFixedLenField,
    StrLenField,
    XIntField,
    XShortField,
)
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket
from scapy.volatile import (
    RandBin,
    RandChoice,
    RandInt,
    RandNum,
    RandShort,
    RandString,
)

__all__ = [
    # Constants
    "DICOM_PORT",
    "APP_CONTEXT_UID",
    "DEFAULT_TRANSFER_SYNTAX_UID",
    "VERIFICATION_SOP_CLASS_UID",
    "CT_IMAGE_STORAGE_SOP_CLASS_UID",
    "PDU_TYPES",
    "ITEM_TYPES",
    "DIMSE_COMMAND_FIELDS",
    "DIMSE_STATUS_CODES",
    # Custom Fields
    "AETitleField",
    "DICOMUIDField",
    # DIMSE Element Fields (TLV structure)
    "DIMSEElementField",
    "DIMSEUIDField",
    "DIMSEUSField",
    "DIMSEULField",
    # PDU Packet classes
    "DICOM",
    "A_ASSOCIATE_RQ",
    "A_ASSOCIATE_AC",
    "A_ASSOCIATE_RJ",
    "P_DATA_TF",
    "PresentationDataValueItem",
    "A_RELEASE_RQ",
    "A_RELEASE_RP",
    "A_ABORT",
    # Variable Item classes
    "DICOMVariableItem",
    "DICOMApplicationContext",
    "DICOMPresentationContextRQ",
    "DICOMPresentationContextAC",
    "DICOMAbstractSyntax",
    "DICOMTransferSyntax",
    "DICOMUserInformation",
    "DICOMMaximumLength",
    "DICOMImplementationClassUID",
    "DICOMAsyncOperationsWindow",
    "DICOMSCPSCURoleSelection",
    "DICOMImplementationVersionName",
    "DICOMUserIdentity",
    "DICOMUserIdentityResponse",
    # DIMSE Command Packets (Single Smart Classes)
    "C_ECHO_RQ",
    "C_ECHO_RSP",
    "C_STORE_RQ",
    "C_STORE_RSP",
    "C_FIND_RQ",
    # Automaton-based Session
    "DICOM_SCU",
    # DIMSE utilities
    "parse_dimse_status",
    # Utility functions
    "_pad_ae_title",
    "_uid_to_bytes",
    # Builder helpers
    "build_presentation_context_rq",
    "build_user_information",
]

log = logging.getLogger("scapy.contrib.dicom")

# --- Constants ---
DICOM_PORT = 104
APP_CONTEXT_UID = "1.2.840.10008.3.1.1.1"
DEFAULT_TRANSFER_SYNTAX_UID = "1.2.840.10008.1.2"  # Implicit VR Little Endian
VERIFICATION_SOP_CLASS_UID = "1.2.840.10008.1.1"
CT_IMAGE_STORAGE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.2"

# --- Configuration ---
if "dicom" not in conf.contribs:
    conf.contribs["dicom"] = {
        "max_pdu_length": 16384,
        "read_timeout": 30,
        "implementation_class_uid": "1.2.3.999.1",
        "implementation_version": "SCAPY_DICOM_2.0",
        "default_ae_title": "SCAPY_SCU",
        "raw_mode": False,  # Global toggle for fuzzing mode
    }

# PDU Type definitions
PDU_TYPES = DADict(_name="PDU_TYPES")
PDU_TYPES[0x01] = "A_ASSOCIATE_RQ"
PDU_TYPES[0x02] = "A_ASSOCIATE_AC"
PDU_TYPES[0x03] = "A_ASSOCIATE_RJ"
PDU_TYPES[0x04] = "P_DATA_TF"
PDU_TYPES[0x05] = "A_RELEASE_RQ"
PDU_TYPES[0x06] = "A_RELEASE_RP"
PDU_TYPES[0x07] = "A_ABORT"

# Variable Item Type definitions
ITEM_TYPES = DADict(_name="ITEM_TYPES")
ITEM_TYPES[0x10] = "Application_Context"
ITEM_TYPES[0x20] = "Presentation_Context_RQ"
ITEM_TYPES[0x21] = "Presentation_Context_AC"
ITEM_TYPES[0x30] = "Abstract_Syntax"
ITEM_TYPES[0x40] = "Transfer_Syntax"
ITEM_TYPES[0x50] = "User_Information"
ITEM_TYPES[0x51] = "Maximum_Length"
ITEM_TYPES[0x52] = "Implementation_Class_UID"
ITEM_TYPES[0x53] = "Async_Operations_Window"
ITEM_TYPES[0x54] = "SCP_SCU_Role_Selection"
ITEM_TYPES[0x55] = "Implementation_Version_Name"
ITEM_TYPES[0x58] = "User_Identity"
ITEM_TYPES[0x59] = "User_Identity_Response"

# DIMSE Status Codes
DIMSE_STATUS_CODES = DADict(_name="DIMSE_STATUS_CODES")
DIMSE_STATUS_CODES[0x0000] = "Success"
DIMSE_STATUS_CODES[0x0001] = "Warning_Requested_Optional_Attrs_Not_Supported"
DIMSE_STATUS_CODES[0x0107] = "Warning_SOP_Class_Not_Supported"
DIMSE_STATUS_CODES[0x0110] = "Processing_Failure"
DIMSE_STATUS_CODES[0x0111] = "No_Such_SOP_Class"
DIMSE_STATUS_CODES[0x0112] = "Duplicate_SOP_Instance"
DIMSE_STATUS_CODES[0x0117] = "Invalid_Object_Instance"
DIMSE_STATUS_CODES[0x0122] = "Refused_SOP_Class_Not_Supported"
DIMSE_STATUS_CODES[0x0124] = "Not_Authorized"
DIMSE_STATUS_CODES[0x0210] = "Duplicate_Invocation"
DIMSE_STATUS_CODES[0x0211] = "Unrecognized_Operation"
DIMSE_STATUS_CODES[0x0212] = "Mistyped_Argument"
DIMSE_STATUS_CODES[0x0213] = "Resource_Limitation"
DIMSE_STATUS_CODES[0xA700] = "Out_Of_Resources"
DIMSE_STATUS_CODES[0xA900] = "Dataset_Does_Not_Match_SOP_Class"
DIMSE_STATUS_CODES[0xB000] = "Warning_Coercion_Of_Data"
DIMSE_STATUS_CODES[0xB006] = "Warning_Elements_Discarded"
DIMSE_STATUS_CODES[0xC000] = "Error_Cannot_Understand"
DIMSE_STATUS_CODES[0xFE00] = "Cancel"
DIMSE_STATUS_CODES[0xFF00] = "Pending"
DIMSE_STATUS_CODES[0xFF01] = "Pending_Warning"

# DIMSE Command Field values
DIMSE_COMMAND_FIELDS = {
    0x0001: "C-STORE-RQ",
    0x8001: "C-STORE-RSP",
    0x0020: "C-FIND-RQ",
    0x8020: "C-FIND-RSP",
    0x0010: "C-GET-RQ",
    0x8010: "C-GET-RSP",
    0x0021: "C-MOVE-RQ",
    0x8021: "C-MOVE-RSP",
    0x0030: "C-ECHO-RQ",
    0x8030: "C-ECHO-RSP",
    0x0FFF: "C-CANCEL-RQ",
}


# =============================================================================
# Native Scapy Random Value Generators (Replaces Custom RandField Classes)
# =============================================================================
# Instead of custom RandDICOMStatus, RandDICOMUID, etc., use native generators:
#
#   RandDICOMStatus -> RandChoice(list(DIMSE_STATUS_CODES.keys()))
#   RandDICOMUID    -> RandDICOMUIDGen() helper function
#   RandAETitle     -> RandString(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")
#
# These are used in field randval() methods below.
# =============================================================================

# Pre-computed lists for RandChoice
_VALID_DIMSE_STATUSES = list(DIMSE_STATUS_CODES.keys())
_VALID_AE_CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _"


def _rand_dicom_uid(root="1.2.3.999", ensure_even=True):
    """
    Generate a random DICOM UID string.
    
    Args:
        root: UID root prefix
        ensure_even: If True, pad to even length (DICOM compliant)
                    If False, may produce odd-length UIDs (for fuzzing)
    
    Returns:
        bytes: Random UID
    """
    num_components = random.randint(2, 4)
    components = [str(random.randint(1, 99999)) for _ in range(num_components)]
    uid = f"{root}.{'.'.join(components)}"
    
    if ensure_even and len(uid) % 2 != 0:
        uid += "\x00"
    
    return uid.encode("ascii")


def _rand_ae_title():
    """Generate a random valid AE title (16 bytes, space-padded)."""
    length = random.randint(4, 16)
    ae = bytes(random.choice(_VALID_AE_CHARS) for _ in range(length))
    return ae.ljust(16, b" ")


# =============================================================================
# Helper Functions
# =============================================================================

def _pad_ae_title(title):
    """Pad an Application Entity title to 16 bytes with spaces."""
    if isinstance(title, bytes):
        return title.ljust(16, b" ")
    return title.ljust(16).encode("ascii")


def _uid_to_bytes(uid, pad_even=True):
    """
    Convert a UID string to bytes.
    
    Args:
        uid: UID as string or bytes
        pad_even: If True, pad to even length per DICOM spec.
                 If False, preserve original length (for fuzzing).
    
    Returns:
        bytes: UID as bytes
    """
    if isinstance(uid, bytes):
        b_uid = uid
    elif isinstance(uid, str):
        b_uid = uid.encode("ascii")
    else:
        return b""
    
    if pad_even and len(b_uid) % 2 != 0:
        b_uid += b"\x00"
    
    return b_uid


# =============================================================================
# Custom Field Classes
# =============================================================================

class AETitleField(StrFixedLenField):
    """
    DICOM Application Entity Title field (16 bytes, space-padded).
    
    Automatically handles padding, encoding, and random value generation.
    """
    
    def __init__(self, name, default):
        if isinstance(default, str):
            default = default.ljust(16).encode("ascii")
        elif isinstance(default, bytes):
            default = default.ljust(16, b" ")
        else:
            default = b" " * 16
        super().__init__(name, default, length=16)
    
    def any2i(self, pkt, val):
        if val is None:
            return self.default
        if isinstance(val, str):
            return val.ljust(16).encode("ascii")[:16]
        if isinstance(val, bytes):
            return val.ljust(16, b" ")[:16]
        return self.default
    
    def i2repr(self, pkt, val):
        if isinstance(val, bytes):
            return val.rstrip(b" ").decode("ascii", errors="replace")
        return repr(val)
    
    def randval(self):
        """Native Scapy random: RandString for AE titles."""
        return RandString(16, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")


class DICOMUIDField(StrLenField):
    """
    DICOM UID field with automatic even-length padding.
    
    For fuzzing odd-length UIDs, set pkt.raw_mode = True or use
    conf.contribs["dicom"]["raw_mode"] = True.
    """
    
    def any2i(self, pkt, val):
        if val is None:
            return b""
        if isinstance(val, bytes):
            b_uid = val
        elif isinstance(val, str):
            b_uid = val.encode("ascii")
        else:
            return b""
        
        # Check raw_mode from packet or global config
        raw_mode = getattr(pkt, "raw_mode", False) if pkt else False
        raw_mode = raw_mode or conf.contribs.get("dicom", {}).get("raw_mode", False)
        
        if not raw_mode and len(b_uid) % 2 != 0:
            b_uid += b"\x00"
        
        return b_uid
    
    def i2repr(self, pkt, val):
        if isinstance(val, bytes):
            return val.decode("ascii").rstrip("\x00")
        return str(val)
    
    def randval(self):
        """Generate random UID (respects global raw_mode for odd-length)."""
        raw_mode = conf.contribs.get("dicom", {}).get("raw_mode", False)
        return RandBin(random.randint(10, 64) if raw_mode else random.randint(10, 32) * 2)


# =============================================================================
# DIMSE Element Fields (TLV Mixin + Native Field Inheritance)
# =============================================================================
# Key improvement: Inherit from LEShortField/LEIntField for the value,
# and use a mixin to prepend the Tag-Length header.
#
# This leverages Scapy's built-in:
# - Type conversion (any2i, i2m, m2i)
# - Display formatting (i2repr)  
# - Error handling
# - Random value generation (randval)
# =============================================================================

class DIMSETLVMixin:
    """
    Mixin that adds DICOM Tag-Length header to fields.
    
    DICOM data elements use a TLV structure:
        - Tag Group: 2 bytes (little-endian)
        - Tag Element: 2 bytes (little-endian)
        - Value Length: 4 bytes (little-endian)
        - Value: variable
    
    Subclasses set tag_group and tag_elem as class attributes.
    """
    tag_group = 0x0000
    tag_elem = 0x0000
    
    def _build_tlv_header(self, value_length):
        """Build the 8-byte TLV header."""
        return struct.pack("<HHI", self.tag_group, self.tag_elem, value_length)
    
    def _parse_tlv_header(self, s):
        """Parse TLV header, return (tag_group, tag_elem, length, remaining)."""
        if len(s) < 8:
            return None, None, 0, s
        tag_g, tag_e, length = struct.unpack("<HHI", s[:8])
        return tag_g, tag_e, length, s[8:]


class DIMSEUSField(DIMSETLVMixin, LEShortField):
    """
    DIMSE Unsigned Short field with TLV header.
    
    Inherits from LEShortField for value handling + TLV mixin for header.
    
    Usage:
        DIMSEUSField("command_field", 0x0030, tag=(0x0000, 0x0100))
    """
    
    def __init__(self, name, default, tag):
        """
        Args:
            name: Field name
            default: Default value (16-bit unsigned)
            tag: Tuple of (tag_group, tag_element)
        """
        self.tag_group, self.tag_elem = tag
        LEShortField.__init__(self, name, default)
    
    def addfield(self, pkt, s, val):
        """Serialize: TLV header + little-endian short."""
        val_bytes = struct.pack("<H", self.i2m(pkt, val))
        return s + self._build_tlv_header(len(val_bytes)) + val_bytes
    
    def getfield(self, pkt, s):
        """Parse: Skip TLV header, extract little-endian short."""
        tag_g, tag_e, length, remaining = self._parse_tlv_header(s)
        if length >= 2 and len(remaining) >= 2:
            val = struct.unpack("<H", remaining[:2])[0]
            return remaining[length:], self.m2i(pkt, val)
        return remaining, self.default
    
    def i2repr(self, pkt, val):
        """Display as hex for command fields, decimal otherwise."""
        if "command" in self.name.lower() or "status" in self.name.lower():
            return f"0x{val:04X}"
        return str(val)
    
    def randval(self):
        """Native Scapy random short."""
        return RandShort()


class DIMSEULField(DIMSETLVMixin, LEIntField):
    """
    DIMSE Unsigned Long field with TLV header.
    
    Inherits from LEIntField for value handling + TLV mixin for header.
    
    Usage:
        DIMSEULField("command_group_length", None, tag=(0x0000, 0x0000))
    """
    
    def __init__(self, name, default, tag):
        """
        Args:
            name: Field name
            default: Default value (32-bit unsigned), None for auto-calculate
            tag: Tuple of (tag_group, tag_element)
        """
        self.tag_group, self.tag_elem = tag
        LEIntField.__init__(self, name, default)
    
    def addfield(self, pkt, s, val):
        """Serialize: TLV header + little-endian long."""
        if val is None:
            val = 0  # Will be fixed in post_build
        val_bytes = struct.pack("<I", self.i2m(pkt, val))
        return s + self._build_tlv_header(len(val_bytes)) + val_bytes
    
    def getfield(self, pkt, s):
        """Parse: Skip TLV header, extract little-endian long."""
        tag_g, tag_e, length, remaining = self._parse_tlv_header(s)
        if length >= 4 and len(remaining) >= 4:
            val = struct.unpack("<I", remaining[:4])[0]
            return remaining[length:], self.m2i(pkt, val)
        return remaining, self.default
    
    def randval(self):
        """Native Scapy random int."""
        return RandInt()


class DIMSEUIDField(DIMSETLVMixin, Field):
    """
    DIMSE UID field with TLV header.
    
    Smart field that:
    - Auto-pads to even length in normal mode
    - Preserves odd lengths in raw_mode (for fuzzing)
    - Uses native RandString for random values
    
    Usage:
        DIMSEUIDField("affected_sop_class_uid", VERIFICATION_SOP_CLASS_UID, tag=(0x0000, 0x0002))
    """
    
    def __init__(self, name, default, tag):
        """
        Args:
            name: Field name
            default: Default UID string
            tag: Tuple of (tag_group, tag_element)
        """
        self.tag_group, self.tag_elem = tag
        Field.__init__(self, name, default)
    
    def _get_raw_mode(self, pkt):
        """Check if raw mode is enabled (packet-level or global)."""
        if pkt and hasattr(pkt, "raw_mode") and pkt.raw_mode:
            return True
        return conf.contribs.get("dicom", {}).get("raw_mode", False)
    
    def any2i(self, pkt, val):
        """Convert any input to internal representation."""
        if val is None:
            return b""
        if isinstance(val, bytes):
            b_uid = val
        elif isinstance(val, str):
            b_uid = val.encode("ascii")
        else:
            return b""
        
        # Auto-pad unless in raw mode
        if not self._get_raw_mode(pkt) and len(b_uid) % 2 != 0:
            b_uid += b"\x00"
        
        return b_uid
    
    def i2m(self, pkt, val):
        """Internal to machine (wire) format."""
        return self.any2i(pkt, val)
    
    def m2i(self, pkt, val):
        """Machine to internal format."""
        return val
    
    def addfield(self, pkt, s, val):
        """Serialize: TLV header + UID bytes."""
        val = self.any2i(pkt, val)
        return s + self._build_tlv_header(len(val)) + val
    
    def getfield(self, pkt, s):
        """Parse: Skip TLV header, extract UID."""
        tag_g, tag_e, length, remaining = self._parse_tlv_header(s)
        if len(remaining) >= length:
            val = remaining[:length]
            return remaining[length:], val
        return remaining, b""
    
    def i2repr(self, pkt, val):
        """Display UID as string."""
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace").rstrip("\x00")
        return str(val)
    
    def randval(self):
        """Generate random UID using native Scapy."""
        # Generate random numeric components for valid UID structure
        raw_mode = conf.contribs.get("dicom", {}).get("raw_mode", False)
        uid = _rand_dicom_uid(ensure_even=not raw_mode)
        return uid


class DIMSEStatusField(DIMSEUSField):
    """
    DIMSE Status field - specialized unsigned short with status code display.
    
    Uses RandChoice with known status codes for meaningful fuzzing.
    """
    
    def i2repr(self, pkt, val):
        """Display status code name if known."""
        name = DIMSE_STATUS_CODES.get(val, "Unknown")
        return f"0x{val:04X} ({name})"
    
    def randval(self):
        """Native Scapy RandChoice from valid status codes."""
        return RandChoice(*_VALID_DIMSE_STATUSES)


# =============================================================================
# DIMSE Command Packets (Single Smart Classes)
# =============================================================================
# Key improvement: Single class handles both valid traffic and fuzzing.
# 
# - command_group_length is an EXPLICIT field (can be fuzzed!)
# - post_build only calculates length when field is None
# - raw_mode attribute controls UID padding behavior
#
# This eliminates duplicate *_Raw classes entirely.
# =============================================================================

class DIMSECommand(Packet):
    """
    Base class for DIMSE command packets.
    
    Features:
    - Explicit command_group_length field (fuzzable!)
    - Conditional post_build: only calculates when length is None
    - raw_mode attribute for fuzzing (disables auto-corrections)
    
    Subclasses define fields_desc starting with command_group_length.
    """
    
    # Class attribute for raw mode (can be set per-packet)
    raw_mode = False
    
    def post_build(self, pkt, pay):
        """
        Calculate command_group_length if set to None.
        
        Only modifies packet if the length field is None (auto-calculate).
        If length is explicitly set (even to wrong value), preserves it for fuzzing.
        """
        # Check if command_group_length was explicitly set
        if self.command_group_length is not None:
            # User set an explicit value - don't modify (allows fuzzing)
            return pkt + pay
        
        # Auto-calculate: length = total bytes after the length element
        # The length element itself is 12 bytes (tag 4 + len 4 + value 4)
        # So command_group_length = len(pkt) - 12
        group_len = len(pkt) - 12
        
        # Patch the length value at offset 8-12 (after tag+length fields)
        pkt = pkt[:8] + struct.pack("<I", group_len) + pkt[12:]
        
        return pkt + pay
    
    def hashret(self):
        """Hash for sr()/sr1() matching based on message_id."""
        if hasattr(self, "message_id"):
            return struct.pack("<H", self.message_id)
        elif hasattr(self, "message_id_responded"):
            return struct.pack("<H", self.message_id_responded)
        return b""


class C_ECHO_RQ(DIMSECommand):
    """
    C-ECHO-RQ DIMSE Command (DICOM Ping).
    
    Single smart class for both valid traffic and fuzzing.
    
    Usage:
        # Normal use
        pkt = C_ECHO_RQ(message_id=42)
        
        # Explicit length for buffer over-read fuzzing
        pkt = C_ECHO_RQ(command_group_length=9999, message_id=42)
        
        # Odd-length UID fuzzing
        pkt = C_ECHO_RQ()
        pkt.raw_mode = True
        pkt.affected_sop_class_uid = b"1.2.3"  # Odd length preserved
        
        # Global raw mode
        conf.contribs["dicom"]["raw_mode"] = True
        pkt = fuzz(C_ECHO_RQ())  # Generates malformed UIDs
    """
    name = "C-ECHO-RQ"
    fields_desc = [
        # EXPLICIT length field - set to None for auto-calculate, or int for fuzzing
        DIMSEULField("command_group_length", None, tag=(0x0000, 0x0000)),
        DIMSEUIDField("affected_sop_class_uid", VERIFICATION_SOP_CLASS_UID, tag=(0x0000, 0x0002)),
        DIMSEUSField("command_field", 0x0030, tag=(0x0000, 0x0100)),
        DIMSEUSField("message_id", 1, tag=(0x0000, 0x0110)),
        DIMSEUSField("data_set_type", 0x0101, tag=(0x0000, 0x0800)),
    ]
    
    def answers(self, other):
        if isinstance(other, C_ECHO_RSP):
            return other.message_id_responded == self.message_id
        return False


class C_ECHO_RSP(DIMSECommand):
    """
    C-ECHO-RSP DIMSE Response.
    
    Usage:
        pkt = C_ECHO_RSP(message_id_responded=42, status=0x0000)
    """
    name = "C-ECHO-RSP"
    fields_desc = [
        DIMSEULField("command_group_length", None, tag=(0x0000, 0x0000)),
        DIMSEUIDField("affected_sop_class_uid", VERIFICATION_SOP_CLASS_UID, tag=(0x0000, 0x0002)),
        DIMSEUSField("command_field", 0x8030, tag=(0x0000, 0x0100)),
        DIMSEUSField("message_id_responded", 1, tag=(0x0000, 0x0120)),
        DIMSEUSField("data_set_type", 0x0101, tag=(0x0000, 0x0800)),
        DIMSEStatusField("status", 0x0000, tag=(0x0000, 0x0900)),
    ]
    
    def answers(self, other):
        if isinstance(other, C_ECHO_RQ):
            return self.message_id_responded == other.message_id
        return False


class C_STORE_RQ(DIMSECommand):
    """
    C-STORE-RQ DIMSE Command for storing DICOM objects.
    
    Single smart class handles both valid and fuzzing scenarios.
    
    Usage:
        # Normal use
        pkt = C_STORE_RQ(
            affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            affected_sop_instance_uid="1.2.3.4.5.6.7.8",
            message_id=1,
        )
        
        # Fuzz the length field (buffer over-read)
        pkt = C_STORE_RQ(command_group_length=0xFFFFFFFF)
        
        # Fuzz with odd-length UIDs
        conf.contribs["dicom"]["raw_mode"] = True
        pkt = fuzz(C_STORE_RQ())
    """
    name = "C-STORE-RQ"
    fields_desc = [
        DIMSEULField("command_group_length", None, tag=(0x0000, 0x0000)),
        DIMSEUIDField("affected_sop_class_uid", CT_IMAGE_STORAGE_SOP_CLASS_UID, tag=(0x0000, 0x0002)),
        DIMSEUSField("command_field", 0x0001, tag=(0x0000, 0x0100)),
        DIMSEUSField("message_id", 1, tag=(0x0000, 0x0110)),
        DIMSEUSField("priority", 0x0002, tag=(0x0000, 0x0700)),
        DIMSEUSField("data_set_type", 0x0000, tag=(0x0000, 0x0800)),
        DIMSEUIDField("affected_sop_instance_uid", "1.2.3.4.5.6.7.8.9", tag=(0x0000, 0x1000)),
    ]
    
    def answers(self, other):
        if isinstance(other, C_STORE_RSP):
            return other.message_id_responded == self.message_id
        return False


class C_STORE_RSP(DIMSECommand):
    """
    C-STORE-RSP DIMSE Response.
    """
    name = "C-STORE-RSP"
    fields_desc = [
        DIMSEULField("command_group_length", None, tag=(0x0000, 0x0000)),
        DIMSEUIDField("affected_sop_class_uid", CT_IMAGE_STORAGE_SOP_CLASS_UID, tag=(0x0000, 0x0002)),
        DIMSEUSField("command_field", 0x8001, tag=(0x0000, 0x0100)),
        DIMSEUSField("message_id_responded", 1, tag=(0x0000, 0x0120)),
        DIMSEUSField("data_set_type", 0x0101, tag=(0x0000, 0x0800)),
        DIMSEStatusField("status", 0x0000, tag=(0x0000, 0x0900)),
        DIMSEUIDField("affected_sop_instance_uid", "1.2.3.4.5.6.7.8.9", tag=(0x0000, 0x1000)),
    ]
    
    def answers(self, other):
        if isinstance(other, C_STORE_RQ):
            return self.message_id_responded == other.message_id
        return False


class C_FIND_RQ(DIMSECommand):
    """
    C-FIND-RQ DIMSE Command for querying DICOM objects.
    """
    name = "C-FIND-RQ"
    fields_desc = [
        DIMSEULField("command_group_length", None, tag=(0x0000, 0x0000)),
        DIMSEUIDField("affected_sop_class_uid", "1.2.840.10008.5.1.4.1.2.1.1", tag=(0x0000, 0x0002)),
        DIMSEUSField("command_field", 0x0020, tag=(0x0000, 0x0100)),
        DIMSEUSField("message_id", 1, tag=(0x0000, 0x0110)),
        DIMSEUSField("priority", 0x0002, tag=(0x0000, 0x0700)),
        DIMSEUSField("data_set_type", 0x0000, tag=(0x0000, 0x0800)),
    ]


def parse_dimse_status(dimse_bytes):
    """
    Parse the Status field from a DIMSE response message.
    
    Args:
        dimse_bytes: Raw bytes of a DIMSE response
        
    Returns:
        Status code (int) if found, None otherwise.
    """
    if dimse_bytes is None or len(dimse_bytes) < 12:
        return None
    
    try:
        # Parse CommandGroupLength
        cmd_group_len = struct.unpack("<I", dimse_bytes[8:12])[0]
        
        # Parse elements looking for status
        offset = 12
        group_end = offset + cmd_group_len
        
        while offset < group_end and offset + 8 <= len(dimse_bytes):
            tag_group, tag_elem = struct.unpack("<HH", dimse_bytes[offset:offset + 4])
            value_len = struct.unpack("<I", dimse_bytes[offset + 4:offset + 8])[0]
            
            if offset + 8 + value_len > len(dimse_bytes):
                break
            
            # (0000,0900) Status
            if tag_group == 0x0000 and tag_elem == 0x0900 and value_len >= 2:
                return struct.unpack("<H", dimse_bytes[offset + 8:offset + 10])[0]
            
            offset += 8 + value_len
        
        return None
        
    except Exception as e:
        log.debug("Error parsing DIMSE status: %s", e)
        return None


# =============================================================================
# DICOM Variable Item Classes
# =============================================================================

class DICOMVariableItem(Packet):
    """DICOM Variable Item Header - Dispatcher packet."""
    name = "DICOM Variable Item"
    fields_desc = [
        ByteEnumField("item_type", 0x10, ITEM_TYPES),
        ByteField("reserved", 0),
        LenField("length", None, fmt="!H"),
    ]

    def extract_padding(self, s):
        if self.length is not None:
            if len(s) < self.length:
                raise Exception("PDU payload incomplete")
            return s[:self.length], s[self.length:]
        return s, b""
    
    def guess_payload_class(self, payload):
        type_to_class = {
            0x10: DICOMApplicationContext,
            0x20: DICOMPresentationContextRQ,
            0x21: DICOMPresentationContextAC,
            0x30: DICOMAbstractSyntax,
            0x40: DICOMTransferSyntax,
            0x50: DICOMUserInformation,
            0x51: DICOMMaximumLength,
            0x52: DICOMImplementationClassUID,
            0x53: DICOMAsyncOperationsWindow,
            0x54: DICOMSCPSCURoleSelection,
            0x55: DICOMImplementationVersionName,
            0x58: DICOMUserIdentity,
            0x59: DICOMUserIdentityResponse,
        }
        return type_to_class.get(self.item_type, DICOMGenericItem)


class DICOMApplicationContext(Packet):
    """Application Context Item payload (Type 0x10)."""
    name = "DICOM Application Context"
    fields_desc = [
        StrLenField("uid", _uid_to_bytes(APP_CONTEXT_UID),
                    length_from=lambda pkt: (pkt.underlayer.length
                                             if pkt.underlayer and pkt.underlayer.length
                                             else len(pkt.uid))),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMAbstractSyntax(Packet):
    """Abstract Syntax Sub-Item payload (Type 0x30)."""
    name = "DICOM Abstract Syntax"
    fields_desc = [
        StrLenField("uid", b"",
                    length_from=lambda pkt: (pkt.underlayer.length
                                             if pkt.underlayer and pkt.underlayer.length
                                             else len(pkt.uid))),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMTransferSyntax(Packet):
    """Transfer Syntax Sub-Item payload (Type 0x40)."""
    name = "DICOM Transfer Syntax"
    fields_desc = [
        StrLenField("uid", _uid_to_bytes(DEFAULT_TRANSFER_SYNTAX_UID),
                    length_from=lambda pkt: (pkt.underlayer.length
                                             if pkt.underlayer and pkt.underlayer.length
                                             else len(pkt.uid))),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMPresentationContextRQ(Packet):
    """Presentation Context Item payload for A-ASSOCIATE-RQ (Type 0x20)."""
    name = "DICOM Presentation Context RQ"
    fields_desc = [
        ByteField("context_id", 1),
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteField("reserved3", 0),
        PacketListField("sub_items", [],
                        DICOMVariableItem,
                        max_count=64,
                        length_from=lambda pkt: (pkt.underlayer.length - 4
                                                  if pkt.underlayer and pkt.underlayer.length
                                                  else 0)),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMPresentationContextAC(Packet):
    """Presentation Context Item payload for A-ASSOCIATE-AC (Type 0x21)."""
    name = "DICOM Presentation Context AC"
    
    RESULT_CODES = {
        0: "acceptance",
        1: "user-rejection",
        2: "no-reason",
        3: "abstract-syntax-not-supported",
        4: "transfer-syntaxes-not-supported",
    }
    
    fields_desc = [
        ByteField("context_id", 1),
        ByteField("reserved1", 0),
        ByteEnumField("result", 0, RESULT_CODES),
        ByteField("reserved2", 0),
        PacketListField("sub_items", [],
                        DICOMVariableItem,
                        max_count=8,
                        length_from=lambda pkt: (pkt.underlayer.length - 4
                                                  if pkt.underlayer and pkt.underlayer.length
                                                  else 0)),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMMaximumLength(Packet):
    """Maximum Length Sub-Item payload (Type 0x51)."""
    name = "DICOM Maximum Length"
    fields_desc = [
        IntField("max_pdu_length", 16384),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMImplementationClassUID(Packet):
    """Implementation Class UID Sub-Item payload (Type 0x52)."""
    name = "DICOM Implementation Class UID"
    fields_desc = [
        StrLenField("uid", b"",
                    length_from=lambda pkt: (pkt.underlayer.length
                                             if pkt.underlayer and pkt.underlayer.length
                                             else len(pkt.uid))),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMImplementationVersionName(Packet):
    """Implementation Version Name Sub-Item payload (Type 0x55)."""
    name = "DICOM Implementation Version Name"
    fields_desc = [
        StrLenField("name", b"",
                    length_from=lambda pkt: (pkt.underlayer.length
                                             if pkt.underlayer and pkt.underlayer.length
                                             else len(pkt.name))),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMAsyncOperationsWindow(Packet):
    """Asynchronous Operations Window Sub-Item payload (Type 0x53)."""
    name = "DICOM Async Operations Window"
    fields_desc = [
        ShortField("max_ops_invoked", 1),
        ShortField("max_ops_performed", 1),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMSCPSCURoleSelection(Packet):
    """SCP/SCU Role Selection Sub-Item payload (Type 0x54)."""
    name = "DICOM SCP/SCU Role Selection"
    fields_desc = [
        FieldLenField("uid_length", None, length_of="sop_class_uid", fmt="!H"),
        StrLenField("sop_class_uid", b"",
                    length_from=lambda pkt: pkt.uid_length),
        ByteField("scu_role", 0),
        ByteField("scp_role", 0),
    ]

    def extract_padding(self, s):
        return b"", s


USER_IDENTITY_TYPES = {
    1: "Username",
    2: "Username and Passcode",
    3: "Kerberos Service Ticket",
    4: "SAML Assertion",
    5: "JSON Web Token (JWT)",
}


class DICOMUserIdentity(Packet):
    """User Identity Negotiation Sub-Item payload (Type 0x58)."""
    name = "DICOM User Identity"
    fields_desc = [
        ByteEnumField("user_identity_type", 1, USER_IDENTITY_TYPES),
        ByteField("positive_response_requested", 0),
        FieldLenField("primary_field_length", None, length_of="primary_field", fmt="!H"),
        StrLenField("primary_field", b"",
                    length_from=lambda pkt: pkt.primary_field_length),
        ConditionalField(
            FieldLenField("secondary_field_length", None, length_of="secondary_field", fmt="!H"),
            lambda pkt: pkt.user_identity_type == 2
        ),
        ConditionalField(
            StrLenField("secondary_field", b"",
                        length_from=lambda pkt: pkt.secondary_field_length),
            lambda pkt: pkt.user_identity_type == 2
        ),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMUserIdentityResponse(Packet):
    """User Identity Server Response Sub-Item payload (Type 0x59)."""
    name = "DICOM User Identity Response"
    fields_desc = [
        FieldLenField("response_length", None, length_of="server_response", fmt="!H"),
        StrLenField("server_response", b"",
                    length_from=lambda pkt: pkt.response_length),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMUserInformation(Packet):
    """User Information Item payload (Type 0x50)."""
    name = "DICOM User Information"
    fields_desc = [
        PacketListField("sub_items", [],
                        DICOMVariableItem,
                        max_count=32,
                        length_from=lambda pkt: (pkt.underlayer.length
                                                  if pkt.underlayer and pkt.underlayer.length
                                                  else 0)),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMGenericItem(Packet):
    """Generic/Unknown Item payload for unrecognized item types."""
    name = "DICOM Generic Item"
    fields_desc = [
        StrLenField("data", b"",
                    length_from=lambda pkt: (pkt.underlayer.length
                                             if pkt.underlayer and pkt.underlayer.length
                                             else len(pkt.data))),
    ]

    def extract_padding(self, s):
        return b"", s


# Variable Item Layer Bindings
bind_layers(DICOMVariableItem, DICOMApplicationContext, item_type=0x10)
bind_layers(DICOMVariableItem, DICOMPresentationContextRQ, item_type=0x20)
bind_layers(DICOMVariableItem, DICOMPresentationContextAC, item_type=0x21)
bind_layers(DICOMVariableItem, DICOMAbstractSyntax, item_type=0x30)
bind_layers(DICOMVariableItem, DICOMTransferSyntax, item_type=0x40)
bind_layers(DICOMVariableItem, DICOMUserInformation, item_type=0x50)
bind_layers(DICOMVariableItem, DICOMMaximumLength, item_type=0x51)
bind_layers(DICOMVariableItem, DICOMImplementationClassUID, item_type=0x52)
bind_layers(DICOMVariableItem, DICOMAsyncOperationsWindow, item_type=0x53)
bind_layers(DICOMVariableItem, DICOMSCPSCURoleSelection, item_type=0x54)
bind_layers(DICOMVariableItem, DICOMImplementationVersionName, item_type=0x55)
bind_layers(DICOMVariableItem, DICOMUserIdentity, item_type=0x58)
bind_layers(DICOMVariableItem, DICOMUserIdentityResponse, item_type=0x59)
bind_layers(DICOMVariableItem, DICOMGenericItem)


# =============================================================================
# DICOM PDU Classes
# =============================================================================

class DICOM(Packet):
    """DICOM Upper Layer PDU header."""
    name = "DICOM UL"
    fields_desc = [
        ByteEnumField("pdu_type", 0x01, PDU_TYPES),
        ByteField("reserved1", 0),
        LenField("length", None, fmt="!I"),
    ]

    def extract_padding(self, s):
        if self.length is not None:
            return s[:self.length], s[self.length:]
        return s, b""
    
    def hashret(self):
        return struct.pack("B", self.pdu_type)
    
    def answers(self, other):
        if not isinstance(other, DICOM):
            return False
        response_map = {
            0x01: [0x02, 0x03],
            0x04: [0x04],
            0x05: [0x06],
        }
        expected = response_map.get(other.pdu_type, [])
        return self.pdu_type in expected
    
    @classmethod
    def tcp_reassemble(cls, data, metadata):
        if len(data) < 6:
            return None
        pdu_length = struct.unpack("!I", data[2:6])[0]
        total_size = 6 + pdu_length
        if len(data) < total_size:
            return None
        return cls(data[:total_size])


class PresentationDataValueItem(Packet):
    """Presentation Data Value Item within a P-DATA-TF PDU."""
    name = "PresentationDataValueItem"
    fields_desc = [
        FieldLenField("length", None, length_of="data", fmt="!I",
                      adjust=lambda pkt, x: x + 2),
        ByteField("context_id", 1),
        BitField("reserved_bits", 0, 6),
        BitField("is_last", 0, 1),
        BitField("is_command", 0, 1),
        StrLenField("data", b"",
                    length_from=lambda pkt: max(0, (pkt.length or 2) - 2)),
    ]

    def extract_padding(self, s):
        return b"", s


class A_ASSOCIATE_RQ(Packet):
    """A-ASSOCIATE-RQ PDU for requesting an association."""
    name = "A-ASSOCIATE-RQ"
    fields_desc = [
        ShortField("protocol_version", 1),
        ShortField("reserved1", 0),
        AETitleField("called_ae_title", ""),
        AETitleField("calling_ae_title", ""),
        StrFixedLenField("reserved2", b"\x00" * 32, 32),
        PacketListField("variable_items", [],
                        DICOMVariableItem,
                        max_count=256,
                        length_from=lambda pkt: (pkt.underlayer.length - 68
                                                  if pkt.underlayer and pkt.underlayer.length
                                                  else 0)),
    ]


class A_ASSOCIATE_AC(Packet):
    """A-ASSOCIATE-AC PDU for accepting an association."""
    name = "A-ASSOCIATE-AC"
    fields_desc = [
        ShortField("protocol_version", 1),
        ShortField("reserved1", 0),
        AETitleField("called_ae_title", ""),
        AETitleField("calling_ae_title", ""),
        StrFixedLenField("reserved2", b"\x00" * 32, 32),
        PacketListField("variable_items", [],
                        DICOMVariableItem,
                        max_count=256,
                        length_from=lambda pkt: (pkt.underlayer.length - 68
                                                  if pkt.underlayer and pkt.underlayer.length
                                                  else 0)),
    ]

    def answers(self, other):
        return isinstance(other, A_ASSOCIATE_RQ)


class A_ASSOCIATE_RJ(Packet):
    """A-ASSOCIATE-RJ PDU for rejecting an association."""
    name = "A-ASSOCIATE-RJ"
    fields_desc = [
        ByteField("reserved1", 0),
        ByteField("result", 1),
        ByteField("source", 1),
        ByteField("reason_diag", 1),
    ]
    
    def answers(self, other):
        return isinstance(other, A_ASSOCIATE_RQ)


class P_DATA_TF(Packet):
    """P-DATA-TF PDU for transferring presentation data."""
    name = "P-DATA-TF"
    fields_desc = [
        PacketListField("pdv_items", [],
                        PresentationDataValueItem,
                        max_count=256,
                        length_from=lambda pkt: (pkt.underlayer.length
                                                  if pkt.underlayer and pkt.underlayer.length
                                                  else 0)),
    ]


class A_RELEASE_RQ(Packet):
    """A-RELEASE-RQ PDU for requesting association release."""
    name = "A-RELEASE-RQ"
    fields_desc = [IntField("reserved1", 0)]


class A_RELEASE_RP(Packet):
    """A-RELEASE-RP PDU for confirming association release."""
    name = "A-RELEASE-RP"
    fields_desc = [IntField("reserved1", 0)]

    def answers(self, other):
        return isinstance(other, A_RELEASE_RQ)


class A_ABORT(Packet):
    """A-ABORT PDU for aborting an association."""
    name = "A-ABORT"
    fields_desc = [
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteField("source", 0),
        ByteField("reason_diag", 0),
    ]


# PDU Layer Bindings
bind_layers(TCP, DICOM, dport=DICOM_PORT)
bind_layers(TCP, DICOM, sport=DICOM_PORT)
bind_layers(DICOM, A_ASSOCIATE_RQ, pdu_type=0x01)
bind_layers(DICOM, A_ASSOCIATE_AC, pdu_type=0x02)
bind_layers(DICOM, A_ASSOCIATE_RJ, pdu_type=0x03)
bind_layers(DICOM, P_DATA_TF, pdu_type=0x04)
bind_layers(DICOM, A_RELEASE_RQ, pdu_type=0x05)
bind_layers(DICOM, A_RELEASE_RP, pdu_type=0x06)
bind_layers(DICOM, A_ABORT, pdu_type=0x07)


# =============================================================================
# Helper Functions for Building Packets
# =============================================================================

def build_presentation_context_rq(context_id, abstract_syntax_uid, transfer_syntax_uids):
    """Build a Presentation Context RQ item using proper Scapy packets."""
    abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid=_uid_to_bytes(abstract_syntax_uid))
    
    sub_items = [abs_syn]
    for ts_uid in transfer_syntax_uids:
        ts = DICOMVariableItem() / DICOMTransferSyntax(uid=_uid_to_bytes(ts_uid))
        sub_items.append(ts)
    
    return DICOMVariableItem() / DICOMPresentationContextRQ(
        context_id=context_id,
        sub_items=sub_items,
    )


def build_user_information(max_pdu_length=16384, implementation_class_uid=None, implementation_version=None):
    """Build a User Information item using proper Scapy packets."""
    sub_items = [
        DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=max_pdu_length)
    ]
    
    if implementation_class_uid:
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationClassUID(uid=_uid_to_bytes(implementation_class_uid))
        )
    
    if implementation_version:
        ver_bytes = implementation_version if isinstance(implementation_version, bytes) else implementation_version.encode("ascii")
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationVersionName(name=ver_bytes)
        )
    
    return DICOMVariableItem() / DICOMUserInformation(sub_items=sub_items)


# =============================================================================
# DICOM SCU Automaton (Replaces Manual DICOMSession Class)
# =============================================================================
# Key improvement: Using scapy.automaton for robust state machine handling.
#
# Benefits:
# - Native async event handling (unexpected disconnects, weird packets)
# - Proper state transitions with ATMT decorators
# - Built-in timeout handling
# - Critical for maintaining fuzzing loops without manual try/except
# =============================================================================

class DICOM_SCU(Automaton):
    """
    DICOM Service Class User (SCU) Automaton.
    
    Implements the DICOM association state machine using Scapy's automaton
    framework. Handles:
    - Association establishment/rejection
    - C-ECHO, C-STORE operations
    - Graceful release
    - Unexpected disconnects and aborts
    
    Usage:
        # Basic C-ECHO
        scu = DICOM_SCU(
            dst_ip="192.168.1.100",
            dst_port=104,
            dst_ae="TARGET_AE",
        )
        result = scu.c_echo()
        print(f"C-ECHO status: {result}")
        scu.release()
        
        # Fuzzing mode
        scu = DICOM_SCU(dst_ip="192.168.1.100", dst_port=104, dst_ae="TARGET")
        scu.raw_mode = True  # Enable odd-length UIDs etc.
        result = scu.c_echo()
    """
    
    # Automaton state names
    STATE_IDLE = "IDLE"
    STATE_AWAITING_ASSOC = "AWAITING_ASSOC"
    STATE_ASSOCIATED = "ASSOCIATED"
    STATE_AWAITING_RELEASE = "AWAITING_RELEASE"
    STATE_AWAITING_RESPONSE = "AWAITING_RESPONSE"
    
    def parse_args(self, dst_ip, dst_port, dst_ae, src_ae="SCAPY_SCU",
                   timeout=10, raw_mode=False, requested_contexts=None, **kwargs):
        """
        Initialize the SCU automaton.
        
        Args:
            dst_ip: Destination IP address
            dst_port: Destination port (typically 104 or 11112)
            dst_ae: Destination Application Entity title
            src_ae: Source Application Entity title
            timeout: Socket timeout in seconds
            raw_mode: If True, disable auto-corrections for fuzzing
            requested_contexts: Dict mapping SOP Class UIDs to Transfer Syntax lists
        """
        Automaton.parse_args(self, **kwargs)
        
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dst_ae = _pad_ae_title(dst_ae)
        self.src_ae = _pad_ae_title(src_ae)
        self.timeout = timeout
        self.raw_mode = raw_mode
        
        # Default to Verification SOP Class
        self.requested_contexts = requested_contexts or {
            VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
        }
        
        # Internal state
        self.sock = None
        self.stream = None
        self.accepted_contexts = {}
        self.max_pdu_length = 16384
        self._proposed_max_pdu = 16384
        self._proposed_context_map = {}
        self._message_id_counter = random.randint(1, 50000)
        
        # Result storage (for operations)
        self._last_result = None
        self._pending_operation = None
    
    def master_filter(self, pkt):
        """Filter to only process DICOM packets."""
        return pkt.haslayer(DICOM)
    
    # =========================================================================
    # States
    # =========================================================================
    
    @ATMT.state(initial=1)
    def IDLE(self):
        """Initial state - not connected."""
        pass
    
    @ATMT.state()
    def AWAITING_ASSOC(self):
        """Waiting for association response."""
        pass
    
    @ATMT.state()
    def ASSOCIATED(self):
        """Association established, ready for operations."""
        pass
    
    @ATMT.state()
    def AWAITING_RELEASE(self):
        """Waiting for release response."""
        pass
    
    @ATMT.state()
    def AWAITING_RESPONSE(self):
        """Waiting for DIMSE response (C-ECHO-RSP, C-STORE-RSP, etc.)."""
        pass
    
    @ATMT.state(final=1)
    def END(self):
        """Final state - connection closed."""
        self._cleanup()
    
    # =========================================================================
    # Conditions & Actions
    # =========================================================================
    
    @ATMT.condition(IDLE)
    def connect_and_associate(self):
        """From IDLE, connect and send A-ASSOCIATE-RQ."""
        import socket
        try:
            self.sock = socket.create_connection(
                (self.dst_ip, self.dst_port),
                timeout=self.timeout,
            )
            self.stream = StreamSocket(self.sock, basecls=DICOM)
            
            # Build and send A-ASSOCIATE-RQ
            assoc_rq = self._build_associate_rq()
            self.send(assoc_rq)
            
            raise self.AWAITING_ASSOC()
            
        except Exception as e:
            log.error("Connection failed: %s", e)
            self._last_result = None
            raise self.END()
    
    @ATMT.receive_condition(AWAITING_ASSOC)
    def receive_assoc_response(self, pkt):
        """Process association response."""
        if pkt.haslayer(A_ASSOCIATE_AC):
            self._parse_accepted_contexts(pkt)
            self._parse_max_pdu_length(pkt)
            log.info("Association accepted")
            raise self.ASSOCIATED()
        
        elif pkt.haslayer(A_ASSOCIATE_RJ):
            rj = pkt[A_ASSOCIATE_RJ]
            log.error("Association rejected: result=%d, source=%d, reason=%d",
                     rj.result, rj.source, rj.reason_diag)
            self._last_result = None
            raise self.END()
    
    @ATMT.timeout(AWAITING_ASSOC, 10)
    def assoc_timeout(self):
        """Handle association timeout."""
        log.error("Association timeout")
        self._last_result = None
        raise self.END()
    
    @ATMT.receive_condition(ASSOCIATED)
    def receive_abort_associated(self, pkt):
        """Handle unexpected abort while associated."""
        if pkt.haslayer(A_ABORT):
            log.warning("Received A-ABORT while associated")
            raise self.END()
    
    @ATMT.receive_condition(AWAITING_RESPONSE)
    def receive_dimse_response(self, pkt):
        """Process DIMSE response."""
        if pkt.haslayer(P_DATA_TF):
            pdv_items = pkt[P_DATA_TF].pdv_items
            if pdv_items:
                data = pdv_items[0].data
                if isinstance(data, str):
                    data = data.encode("latin-1")
                self._last_result = parse_dimse_status(data)
            raise self.ASSOCIATED()
        
        elif pkt.haslayer(A_ABORT):
            log.warning("Received A-ABORT during operation")
            self._last_result = None
            raise self.END()
    
    @ATMT.timeout(AWAITING_RESPONSE, 10)
    def response_timeout(self):
        """Handle DIMSE response timeout."""
        log.error("DIMSE response timeout")
        self._last_result = None
        raise self.ASSOCIATED()
    
    @ATMT.receive_condition(AWAITING_RELEASE)
    def receive_release_response(self, pkt):
        """Process release response."""
        if pkt.haslayer(A_RELEASE_RP):
            log.info("Association released")
            raise self.END()
        
        elif pkt.haslayer(A_ABORT):
            log.warning("Received A-ABORT instead of A-RELEASE-RP")
            raise self.END()
    
    @ATMT.timeout(AWAITING_RELEASE, 10)
    def release_timeout(self):
        """Handle release timeout."""
        log.error("Release timeout")
        raise self.END()
    
    # =========================================================================
    # Actions (triggered by user or internal logic)
    # =========================================================================
    
    @ATMT.action(receive_assoc_response)
    def action_assoc_accepted(self):
        """Action when association is accepted."""
        pass
    
    # =========================================================================
    # Public API Methods
    # =========================================================================
    
    def associate(self, requested_contexts=None):
        """
        Establish DICOM association.
        
        Args:
            requested_contexts: Optional dict of SOP Class -> Transfer Syntax list
            
        Returns:
            True if association established, False otherwise
        """
        if requested_contexts:
            self.requested_contexts = requested_contexts
        
        # Run automaton until ASSOCIATED or END
        try:
            self.run(wait=False)
            # Wait for state transition
            import time
            for _ in range(int(self.timeout * 10)):
                if self.state.state == "ASSOCIATED":
                    return True
                if self.state.state == "END":
                    return False
                time.sleep(0.1)
            return False
        except Exception as e:
            log.error("Association error: %s", e)
            return False
    
    def c_echo(self):
        """
        Send C-ECHO request (DICOM ping).
        
        Returns:
            Status code (0 = success) or None if failed
        """
        if self.state.state != "ASSOCIATED":
            log.error("Not associated")
            return None
        
        # Find accepted context for Verification
        echo_ctx_id = self._find_accepted_context_id(VERIFICATION_SOP_CLASS_UID)
        if echo_ctx_id is None:
            log.error("No accepted context for Verification SOP Class")
            return None
        
        msg_id = self._get_next_message_id()
        
        # Build C-ECHO-RQ
        dimse_rq = bytes(C_ECHO_RQ(message_id=msg_id))
        
        pdv = PresentationDataValueItem(
            context_id=echo_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        pdata = DICOM() / P_DATA_TF(pdv_items=[pdv])
        
        # Send and wait for response
        self._last_result = None
        self.send(pdata)
        
        # Transition to waiting state
        try:
            self.state = self.AWAITING_RESPONSE
            
            # Wait for response
            import time
            for _ in range(int(self.timeout * 10)):
                if self._last_result is not None:
                    return self._last_result
                if self.state.state == "ASSOCIATED":
                    return self._last_result
                if self.state.state == "END":
                    return None
                time.sleep(0.1)
            
            return self._last_result
            
        except Exception as e:
            log.error("C-ECHO error: %s", e)
            return None
    
    def c_store(self, dataset_bytes, sop_class_uid, sop_instance_uid,
                transfer_syntax_uid=DEFAULT_TRANSFER_SYNTAX_UID):
        """
        Send C-STORE request to store a DICOM dataset.
        
        Args:
            dataset_bytes: Raw bytes of the DICOM dataset
            sop_class_uid: SOP Class UID
            sop_instance_uid: SOP Instance UID
            transfer_syntax_uid: Transfer Syntax UID
            
        Returns:
            Status code (0 = success) or None if failed
        """
        if self.state.state != "ASSOCIATED":
            log.error("Not associated")
            return None
        
        store_ctx_id = self._find_accepted_context_id(sop_class_uid, transfer_syntax_uid)
        if store_ctx_id is None:
            log.error("No accepted context for %s", sop_class_uid)
            return None
        
        msg_id = self._get_next_message_id()
        
        # Build C-STORE-RQ
        store_rq = C_STORE_RQ(
            affected_sop_class_uid=sop_class_uid,
            affected_sop_instance_uid=sop_instance_uid,
            message_id=msg_id,
        )
        if self.raw_mode:
            store_rq.raw_mode = True
        
        dimse_rq = bytes(store_rq)
        
        # Send command
        cmd_pdv = PresentationDataValueItem(
            context_id=store_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        pdata_cmd = DICOM() / P_DATA_TF(pdv_items=[cmd_pdv])
        self.send(pdata_cmd)
        
        # Send data (with fragmentation if needed)
        max_pdv_data = self.max_pdu_length - 12
        
        if len(dataset_bytes) <= max_pdv_data:
            data_pdv = PresentationDataValueItem(
                context_id=store_ctx_id,
                data=dataset_bytes,
                is_command=0,
                is_last=1,
            )
            pdata_data = DICOM() / P_DATA_TF(pdv_items=[data_pdv])
            self.send(pdata_data)
        else:
            # Fragment
            offset = 0
            while offset < len(dataset_bytes):
                chunk = dataset_bytes[offset:offset + max_pdv_data]
                is_last = 1 if (offset + len(chunk) >= len(dataset_bytes)) else 0
                data_pdv = PresentationDataValueItem(
                    context_id=store_ctx_id,
                    data=chunk,
                    is_command=0,
                    is_last=is_last,
                )
                pdata_data = DICOM() / P_DATA_TF(pdv_items=[data_pdv])
                self.send(pdata_data)
                offset += len(chunk)
        
        # Wait for response
        self._last_result = None
        
        import time
        for _ in range(int(self.timeout * 10)):
            if self._last_result is not None:
                return self._last_result
            time.sleep(0.1)
        
        return self._last_result
    
    def release(self):
        """Request graceful release of the association."""
        if self.state.state != "ASSOCIATED":
            return True
        
        release_rq = DICOM() / A_RELEASE_RQ()
        self.send(release_rq)
        
        # Transition to waiting
        self.state = self.AWAITING_RELEASE
        
        import time
        for _ in range(int(self.timeout * 10)):
            if self.state.state == "END":
                return True
            time.sleep(0.1)
        
        self._cleanup()
        return False
    
    def abort(self):
        """Abort the association immediately."""
        abort_pdu = DICOM() / A_ABORT(source=0, reason_diag=0)
        try:
            self.send(abort_pdu)
        except Exception:
            pass
        self._cleanup()
    
    # =========================================================================
    # Internal Helpers
    # =========================================================================
    
    def _build_associate_rq(self):
        """Build A-ASSOCIATE-RQ packet."""
        self._proposed_context_map = {}
        
        variable_items = [
            DICOMVariableItem() / DICOMApplicationContext()
        ]
        
        ctx_id = 1
        for abs_syntax, trn_syntaxes in self.requested_contexts.items():
            self._proposed_context_map[ctx_id] = abs_syntax
            pctx = build_presentation_context_rq(ctx_id, abs_syntax, trn_syntaxes)
            variable_items.append(pctx)
            ctx_id += 2
        
        user_info = build_user_information(max_pdu_length=self._proposed_max_pdu)
        variable_items.append(user_info)
        
        return DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.dst_ae,
            calling_ae_title=self.src_ae,
            variable_items=variable_items,
        )
    
    def _parse_accepted_contexts(self, response):
        """Parse accepted presentation contexts from A-ASSOCIATE-AC."""
        for item in response[A_ASSOCIATE_AC].variable_items:
            if item.item_type == 0x21 and item.haslayer(DICOMPresentationContextAC):
                pctx = item[DICOMPresentationContextAC]
                ctx_id = pctx.context_id
                result = pctx.result
                
                if result != 0:
                    continue
                
                abs_syntax = self._proposed_context_map.get(ctx_id)
                if abs_syntax is None:
                    continue
                
                for sub_item in pctx.sub_items:
                    if sub_item.item_type == 0x40 and sub_item.haslayer(DICOMTransferSyntax):
                        ts_uid = sub_item[DICOMTransferSyntax].uid
                        if isinstance(ts_uid, bytes):
                            ts_uid = ts_uid.rstrip(b"\x00").decode("ascii")
                        self.accepted_contexts[ctx_id] = (abs_syntax, ts_uid)
                        break
    
    def _parse_max_pdu_length(self, response):
        """Parse max PDU length from A-ASSOCIATE-AC."""
        try:
            for item in response[A_ASSOCIATE_AC].variable_items:
                if item.item_type == 0x50 and item.haslayer(DICOMUserInformation):
                    user_info = item[DICOMUserInformation]
                    for sub_item in user_info.sub_items:
                        if sub_item.item_type == 0x51 and sub_item.haslayer(DICOMMaximumLength):
                            server_max = sub_item[DICOMMaximumLength].max_pdu_length
                            self.max_pdu_length = min(self._proposed_max_pdu, server_max)
                            return
        except Exception:
            pass
        self.max_pdu_length = self._proposed_max_pdu
    
    def _find_accepted_context_id(self, sop_class_uid, transfer_syntax_uid=None):
        """Find an accepted presentation context ID."""
        for ctx_id, (abs_syntax, ts_syntax) in self.accepted_contexts.items():
            if abs_syntax == sop_class_uid:
                if transfer_syntax_uid is None or transfer_syntax_uid == ts_syntax:
                    return ctx_id
        return None
    
    def _get_next_message_id(self):
        """Get the next message ID."""
        self._message_id_counter += 1
        return self._message_id_counter & 0xFFFF
    
    def _cleanup(self):
        """Clean up socket resources."""
        if self.stream:
            try:
                self.stream.close()
            except Exception:
                pass
        self.stream = None
        self.sock = None


# =============================================================================
# Backward Compatibility: DICOMSession wrapper
# =============================================================================

class DICOMSession:
    """
    Backward-compatible wrapper around DICOM_SCU automaton.
    
    Provides the same API as the old manual session class.
    """
    
    def __init__(self, dst_ip, dst_port, dst_ae, src_ae="SCAPY_SCU",
                 read_timeout=10, raw_mode=False):
        self._scu = DICOM_SCU(
            dst_ip=dst_ip,
            dst_port=dst_port,
            dst_ae=dst_ae,
            src_ae=src_ae,
            timeout=read_timeout,
            raw_mode=raw_mode,
        )
        self.raw_mode = raw_mode
    
    def connect(self):
        return True  # Connection happens in associate()
    
    def associate(self, requested_contexts=None):
        return self._scu.associate(requested_contexts)
    
    def c_echo(self):
        return self._scu.c_echo()
    
    def c_store(self, dataset_bytes, sop_class_uid, sop_instance_uid,
                transfer_syntax_uid):
        return self._scu.c_store(dataset_bytes, sop_class_uid, sop_instance_uid,
                                 transfer_syntax_uid)
    
    def release(self):
        return self._scu.release()
    
    def close(self):
        self._scu.abort()
    
    @property
    def assoc_established(self):
        return self._scu.state.state == "ASSOCIATED"
    
    @property
    def accepted_contexts(self):
        return self._scu.accepted_contexts
    
    @property
    def max_pdu_length(self):
        return self._scu.max_pdu_length