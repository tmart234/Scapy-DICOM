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
"""

import logging
import socket
import struct
import time

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitField,
    ByteEnumField,
    ByteField,
    Field,
    FieldLenField,
    IntField,
    LenField,
    PacketListField,
    ShortField,
    StrFixedLenField,
    StrLenField,
)
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket

__all__ = [
    # Constants
    "DICOM_PORT",
    "APP_CONTEXT_UID",
    "DEFAULT_TRANSFER_SYNTAX_UID",
    "VERIFICATION_SOP_CLASS_UID",
    "CT_IMAGE_STORAGE_SOP_CLASS_UID",
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
    "DICOMImplementationVersionName",
    # DIMSE Custom Fields
    "DICOMElementField",
    "DICOMUIDField",
    "DICOMUIDFieldRaw",
    "DICOMUSField",
    "DICOMULField",
    # DIMSE Command Packets
    "DIMSEPacket",
    "C_ECHO_RQ",
    "C_ECHO_RSP",
    "C_STORE_RQ",
    "C_STORE_RSP",
    "C_FIND_RQ",
    # Session helper
    "DICOMSession",
    # DIMSE utilities
    "parse_dimse_status",
    # Utility functions
    "_pad_ae_title",
    "_uid_to_bytes",
    # Raw/Fuzzing utilities (no auto-correction, bypass UID padding)
    "_uid_to_bytes_raw",
    "build_c_echo_rq_dimse_raw",
    "build_c_store_rq_dimse_raw",
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

# PDU Type definitions
PDU_TYPES = {
    0x01: "A-ASSOCIATE-RQ",
    0x02: "A-ASSOCIATE-AC",
    0x03: "A-ASSOCIATE-RJ",
    0x04: "P-DATA-TF",
    0x05: "A-RELEASE-RQ",
    0x06: "A-RELEASE-RP",
    0x07: "A-ABORT",
}

# Variable Item Type definitions
ITEM_TYPES = {
    0x10: "Application Context",
    0x20: "Presentation Context RQ",
    0x21: "Presentation Context AC",
    0x30: "Abstract Syntax",
    0x40: "Transfer Syntax",
    0x50: "User Information",
    0x51: "Maximum Length",
    0x52: "Implementation Class UID",
    0x55: "Implementation Version Name",
    0x56: "User Identity",
}


# --- Helper Functions ---

def _pad_ae_title(title):
    """Pad an Application Entity title to 16 bytes with spaces."""
    if isinstance(title, bytes):
        return title.ljust(16, b" ")
    return title.ljust(16).encode("ascii")


def _uid_to_bytes(uid):
    """
    Convert a UID string to bytes, padding to even length if needed.
    
    Note: This function auto-corrects odd-length UIDs per DICOM spec.
    For fuzzing with intentionally malformed UIDs, use _uid_to_bytes_raw().
    """
    if isinstance(uid, bytes):
        b_uid = uid
    elif isinstance(uid, str):
        b_uid = uid.encode("ascii")
    else:
        return b""
    # UIDs must have even length per DICOM spec
    if len(b_uid) % 2 != 0:
        b_uid += b"\x00"
    return b_uid


def _uid_to_bytes_raw(uid):
    """
    Convert a UID string to bytes WITHOUT padding correction.
    
    Use this for fuzzing to send intentionally malformed odd-length UIDs.
    """
    if isinstance(uid, bytes):
        return uid
    elif isinstance(uid, str):
        return uid.encode("ascii")
    else:
        return b""


# =============================================================================
# DIMSE Custom Fields
# =============================================================================
# These fields handle DICOM's TLV (Tag-Length-Value) structure with
# Implicit VR Little Endian encoding used in command sets.
# =============================================================================


class DICOMElementField(Field):
    """
    Base field for DICOM data elements (Tag-Length-Value structure).
    
    Each element is encoded as:
        - Tag Group: 2 bytes (little-endian)
        - Tag Element: 2 bytes (little-endian)
        - Value Length: 4 bytes (little-endian)
        - Value: variable bytes
    
    The tag is fixed at field definition time.
    """
    __slots__ = ["tag_group", "tag_elem"]
    
    def __init__(self, name, default, tag_group, tag_elem):
        self.tag_group = tag_group
        self.tag_elem = tag_elem
        Field.__init__(self, name, default)
    
    def addfield(self, pkt, s, val):
        """Serialize the field to bytes."""
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("ascii")
        return s + struct.pack("<HHI", self.tag_group, self.tag_elem, len(val)) + val
    
    def getfield(self, pkt, s):
        """Parse the field from bytes."""
        if len(s) < 8:
            return s, b""
        tag_g, tag_e, length = struct.unpack("<HHI", s[:8])
        # Verify tag matches (optional - for strict parsing)
        value = s[8:8 + length]
        return s[8 + length:], value
    
    def i2repr(self, pkt, val):
        """Human-readable representation."""
        if isinstance(val, bytes):
            try:
                return val.decode("ascii").rstrip("\x00")
            except UnicodeDecodeError:
                return val.hex()
        return repr(val)


class DICOMUIDField(DICOMElementField):
    """
    DICOM UID element field - auto-pads to even length per DICOM spec.
    
    Usage:
        DICOMUIDField("affected_sop_class_uid", VERIFICATION_SOP_CLASS_UID, 0x0000, 0x0002)
    """
    
    def addfield(self, pkt, s, val):
        """Serialize UID with even-length padding."""
        val = _uid_to_bytes(val)
        return super().addfield(pkt, s, val)
    
    def i2repr(self, pkt, val):
        """Display UID as string."""
        if isinstance(val, bytes):
            return val.decode("ascii").rstrip("\x00")
        return str(val)


class DICOMUIDFieldRaw(DICOMElementField):
    """
    DICOM UID element field WITHOUT auto-padding (for fuzzing).
    
    Use this to send intentionally malformed odd-length UIDs.
    """
    
    def addfield(self, pkt, s, val):
        """Serialize UID without padding correction."""
        val = _uid_to_bytes_raw(val)
        return super().addfield(pkt, s, val)


class DICOMUSField(DICOMElementField):
    """
    DICOM US (Unsigned Short) element field.
    
    Value is a 16-bit unsigned integer.
    
    Usage:
        DICOMUSField("command_field", 0x0030, 0x0000, 0x0100)
    """
    
    def addfield(self, pkt, s, val):
        """Serialize unsigned short."""
        val_bytes = struct.pack("<H", val)
        return super().addfield(pkt, s, val_bytes)
    
    def getfield(self, pkt, s):
        """Parse unsigned short."""
        remain, val_bytes = super().getfield(pkt, s)
        if len(val_bytes) >= 2:
            return remain, struct.unpack("<H", val_bytes[:2])[0]
        return remain, 0
    
    def i2repr(self, pkt, val):
        """Display as hex."""
        return f"0x{val:04X}"


class DICOMULField(DICOMElementField):
    """
    DICOM UL (Unsigned Long) element field.
    
    Value is a 32-bit unsigned integer.
    
    Usage:
        DICOMULField("command_group_length", None, 0x0000, 0x0000)
    """
    
    def addfield(self, pkt, s, val):
        """Serialize unsigned long."""
        val_bytes = struct.pack("<I", val)
        return super().addfield(pkt, s, val_bytes)
    
    def getfield(self, pkt, s):
        """Parse unsigned long."""
        remain, val_bytes = super().getfield(pkt, s)
        if len(val_bytes) >= 4:
            return remain, struct.unpack("<I", val_bytes[:4])[0]
        return remain, 0


# =============================================================================
# DIMSE Packet Base Class
# =============================================================================
# This base class handles the unique DIMSE requirement where the first element
# (CommandGroupLength at tag 0000,0000) contains the length of all subsequent
# elements in the same packet. Standard LenField calculates payload length,
# but DIMSE needs intra-packet length calculation.
# =============================================================================

class DIMSEPacket(Packet):
    """
    Base class for DIMSE command packets.
    
    DIMSE packets have a unique structure: the first element (0000,0000) 
    CommandGroupLength contains the byte count of all elements that follow.
    This is an intra-packet dependency that standard fields can't model,
    so we handle it in post_build.
    
    Subclasses should define fields_desc WITHOUT the CommandGroupLength -
    this base class prepends it automatically.
    """
    
    # GROUP_LENGTH_ELEMENT_SIZE = 12 bytes:
    # Tag Group (2) + Tag Element (2) + Value Length (4) + Value (4)
    GROUP_LENGTH_ELEMENT_SIZE = 12
    
    def post_build(self, pkt, pay):
        """
        Prepend CommandGroupLength (0000,0000) element.
        
        The CommandGroupLength value = length of all elements after it.
        This is the one valid use of post_build for DIMSE because standard
        fields cannot calculate "length of myself minus header".
        """
        # Calculate group_len = size of all fields in pkt (excluding the
        # CommandGroupLength element we're about to prepend)
        group_len = len(pkt)
        
        # Build the CommandGroupLength element:
        # Tag (0000,0000), Length (4 bytes), Value (group_len as uint32)
        header = struct.pack("<HHI", 0x0000, 0x0000, 4) + struct.pack("<I", group_len)
        
        return header + pkt + pay


# =============================================================================
# DIMSE Command Packet Classes
# =============================================================================
# These replace the build_*_dimse functions with proper Scapy packets.
# Now you can easily fuzz specific fields like message_id!
# =============================================================================

# Command Field values (0000,0100)
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
    0x0100: "N-EVENT-REPORT-RQ",
    0x8100: "N-EVENT-REPORT-RSP",
    0x0110: "N-GET-RQ",
    0x8110: "N-GET-RSP",
    0x0120: "N-SET-RQ",
    0x8120: "N-SET-RSP",
    0x0130: "N-ACTION-RQ",
    0x8130: "N-ACTION-RSP",
    0x0140: "N-CREATE-RQ",
    0x8140: "N-CREATE-RSP",
    0x0150: "N-DELETE-RQ",
    0x8150: "N-DELETE-RSP",
}

# Data Set Type values (0000,0800)
DATA_SET_TYPES = {
    0x0000: "Data Set Present",
    0x0001: "Data Set Present",  # Also valid
    0x0101: "No Data Set",
}

# Priority values (0000,0700)
PRIORITY_VALUES = {
    0x0000: "MEDIUM",
    0x0001: "HIGH",
    0x0002: "LOW",
}


class C_ECHO_RQ(DIMSEPacket):
    """
    C-ECHO-RQ DIMSE Command (DICOM Ping).
    
    This replaces build_c_echo_rq_dimse() with a proper Scapy packet.
    Inherits from DIMSEPacket which handles CommandGroupLength automatically.
    
    Usage:
        # Simple creation
        pkt = C_ECHO_RQ(message_id=42)
        
        # Fuzzing - easy to modify specific fields
        pkt = C_ECHO_RQ(message_id=0xFFFF)  # Test max message ID
        pkt = C_ECHO_RQ(affected_sop_class_uid="1.2.3.INVALID")  # Bad UID
        
        # Get raw bytes for P-DATA-TF
        pdv = PresentationDataValueItem(context_id=1, data=bytes(pkt), is_command=1, is_last=1)
    """
    name = "C-ECHO-RQ"
    fields_desc = [
        # (0000,0002) Affected SOP Class UID - Verification SOP Class
        DICOMUIDField("affected_sop_class_uid", VERIFICATION_SOP_CLASS_UID, 0x0000, 0x0002),
        # (0000,0100) Command Field - C-ECHO-RQ = 0x0030
        DICOMUSField("command_field", 0x0030, 0x0000, 0x0100),
        # (0000,0110) Message ID
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        # (0000,0800) Command Data Set Type - No Data Set = 0x0101
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
    ]


class C_ECHO_RSP(DIMSEPacket):
    """
    C-ECHO-RSP DIMSE Response.
    
    Inherits from DIMSEPacket which handles CommandGroupLength automatically.
    
    Usage:
        pkt = C_ECHO_RSP(message_id_responded=42, status=0x0000)
    """
    name = "C-ECHO-RSP"
    fields_desc = [
        # (0000,0002) Affected SOP Class UID
        DICOMUIDField("affected_sop_class_uid", VERIFICATION_SOP_CLASS_UID, 0x0000, 0x0002),
        # (0000,0100) Command Field - C-ECHO-RSP = 0x8030
        DICOMUSField("command_field", 0x8030, 0x0000, 0x0100),
        # (0000,0120) Message ID Being Responded To
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        # (0000,0800) Command Data Set Type
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        # (0000,0900) Status
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
    ]


class C_STORE_RQ(DIMSEPacket):
    """
    C-STORE-RQ DIMSE Command for storing DICOM objects.
    
    This replaces build_c_store_rq_dimse() with a proper Scapy packet.
    Inherits from DIMSEPacket which handles CommandGroupLength automatically.
    
    Usage:
        pkt = C_STORE_RQ(
            affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            affected_sop_instance_uid="1.2.3.4.5.6.7.8",
            message_id=1,
            priority=0x0002,  # LOW
        )
        
        # Fuzzing examples
        pkt = C_STORE_RQ(priority=0xFFFF)  # Invalid priority
        pkt = C_STORE_RQ(message_id=0)     # Zero message ID
    """
    name = "C-STORE-RQ"
    fields_desc = [
        # (0000,0002) Affected SOP Class UID
        DICOMUIDField("affected_sop_class_uid", CT_IMAGE_STORAGE_SOP_CLASS_UID, 0x0000, 0x0002),
        # (0000,0100) Command Field - C-STORE-RQ = 0x0001
        DICOMUSField("command_field", 0x0001, 0x0000, 0x0100),
        # (0000,0110) Message ID
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        # (0000,0700) Priority
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        # (0000,0800) Command Data Set Type - Data Set Present = 0x0000
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
        # (0000,1000) Affected SOP Instance UID
        DICOMUIDField("affected_sop_instance_uid", "1.2.3.4.5.6.7.8.9", 0x0000, 0x1000),
    ]


class C_STORE_RSP(DIMSEPacket):
    """
    C-STORE-RSP DIMSE Response.
    
    Inherits from DIMSEPacket which handles CommandGroupLength automatically.
    
    Usage:
        pkt = C_STORE_RSP(message_id_responded=1, status=0x0000)
    """
    name = "C-STORE-RSP"
    fields_desc = [
        # (0000,0002) Affected SOP Class UID
        DICOMUIDField("affected_sop_class_uid", CT_IMAGE_STORAGE_SOP_CLASS_UID, 0x0000, 0x0002),
        # (0000,0100) Command Field - C-STORE-RSP = 0x8001
        DICOMUSField("command_field", 0x8001, 0x0000, 0x0100),
        # (0000,0120) Message ID Being Responded To
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        # (0000,0800) Command Data Set Type
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        # (0000,0900) Status
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        # (0000,1000) Affected SOP Instance UID
        DICOMUIDField("affected_sop_instance_uid", "1.2.3.4.5.6.7.8.9", 0x0000, 0x1000),
    ]


class C_FIND_RQ(DIMSEPacket):
    """
    C-FIND-RQ DIMSE Command for querying DICOM objects.
    
    Inherits from DIMSEPacket which handles CommandGroupLength automatically.
    
    Usage:
        pkt = C_FIND_RQ(
            affected_sop_class_uid="1.2.840.10008.5.1.4.1.2.1.1",  # Patient Root Query
            message_id=1,
        )
    """
    name = "C-FIND-RQ"
    fields_desc = [
        # (0000,0002) Affected SOP Class UID
        DICOMUIDField("affected_sop_class_uid", "1.2.840.10008.5.1.4.1.2.1.1", 0x0000, 0x0002),
        # (0000,0100) Command Field - C-FIND-RQ = 0x0020
        DICOMUSField("command_field", 0x0020, 0x0000, 0x0100),
        # (0000,0110) Message ID
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        # (0000,0700) Priority
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        # (0000,0800) Command Data Set Type - Data Set Present = 0x0000
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]


# =============================================================================
# Raw DIMSE Builders (for fuzzing - bypass auto-padding)
# =============================================================================
# These functions bypass the auto-padding that packet classes do,
# allowing you to send intentionally malformed odd-length UIDs.
# =============================================================================

def build_c_echo_rq_dimse_raw(message_id=1, sop_class_uid=None):
    """Build a C-ECHO-RQ DIMSE command WITHOUT auto-padding (for fuzzing)."""
    if sop_class_uid is None:
        sop_uid_bytes = _uid_to_bytes_raw(VERIFICATION_SOP_CLASS_UID)
    elif isinstance(sop_class_uid, bytes):
        sop_uid_bytes = sop_class_uid
    else:
        sop_uid_bytes = _uid_to_bytes_raw(sop_class_uid)
    
    elements = [
        (0x0000, 0x0002, sop_uid_bytes),
        (0x0000, 0x0100, struct.pack("<H", 0x0030)),
        (0x0000, 0x0110, struct.pack("<H", message_id)),
        (0x0000, 0x0800, struct.pack("<H", 0x0101)),
    ]
    payload = b"".join(
        struct.pack("<HH", g, e) + struct.pack("<I", len(v)) + v
        for g, e, v in elements
    )
    group_len = len(payload)
    return (
        struct.pack("<HHI", 0x0000, 0x0000, 4)
        + struct.pack("<I", group_len)
        + payload
    )


def build_c_store_rq_dimse_raw(sop_class_uid, sop_instance_uid, message_id=1):
    """Build a C-STORE-RQ DIMSE command WITHOUT auto-padding (for fuzzing)."""
    sop_class_bytes = sop_class_uid if isinstance(sop_class_uid, bytes) else _uid_to_bytes_raw(sop_class_uid)
    sop_inst_bytes = sop_instance_uid if isinstance(sop_instance_uid, bytes) else _uid_to_bytes_raw(sop_instance_uid)
    
    elements = [
        (0x0000, 0x0002, sop_class_bytes),
        (0x0000, 0x0100, struct.pack("<H", 0x0001)),
        (0x0000, 0x0110, struct.pack("<H", message_id)),
        (0x0000, 0x0700, struct.pack("<H", 0x0002)),
        (0x0000, 0x0800, struct.pack("<H", 0x0000)),
        (0x0000, 0x1000, sop_inst_bytes),
    ]
    payload = b"".join(
        struct.pack("<HH", g, e) + struct.pack("<I", len(v)) + v
        for g, e, v in elements
    )
    group_len = len(payload)
    return (
        struct.pack("<HHI", 0x0000, 0x0000, 4)
        + struct.pack("<I", group_len)
        + payload
    )


def parse_dimse_status(dimse_bytes):
    """Parse the Status field from a DIMSE response message."""
    try:
        if len(dimse_bytes) < 12:
            return None
        cmd_group_len = struct.unpack("<I", dimse_bytes[8:12])[0]
        offset = 12
        group_end_offset = offset + cmd_group_len
        while offset < group_end_offset and offset + 8 <= len(dimse_bytes):
            tag_group, tag_elem = struct.unpack("<HH", dimse_bytes[offset:offset + 4])
            value_len = struct.unpack("<I", dimse_bytes[offset + 4:offset + 8])[0]
            if tag_group == 0x0000 and tag_elem == 0x0900 and value_len == 2:
                return struct.unpack("<H", dimse_bytes[offset + 8:offset + 10])[0]
            offset += 8 + value_len
    except Exception:
        return None
    return None


# =============================================================================
# DICOM Variable Item Classes (The "Kosher" Approach)
# =============================================================================
# These replace the generic "blob" container with proper typed packets.
# bind_layers dispatches based on item_type, so:
#   DICOMVariableItem() / DICOMApplicationContext(uid="1.2.3...")
# automatically sets item_type=0x10 and calculates length.
#
# KEY FIX: Using LenField instead of ShortField + manual post_build.
# LenField automatically calculates the payload length.
# =============================================================================

class DICOMVariableItem(Packet):
    """
    DICOM Variable Item Header - Dispatcher packet.
    
    This is the base header for all variable items in A-ASSOCIATE PDUs.
    Use bind_layers to automatically dispatch to the correct sub-type
    based on item_type.
    
    Item Types:
        0x10: Application Context
        0x20: Presentation Context (in RQ)
        0x21: Presentation Context (in AC)
        0x30: Abstract Syntax (nested in Pres. Context)
        0x40: Transfer Syntax (nested in Pres. Context)
        0x50: User Information
        0x51: Maximum Length Sub-Item
        0x52: Implementation Class UID
        0x55: Implementation Version Name
    
    KEY FIX: Using LenField for automatic payload length calculation.
    """
    name = "DICOM Variable Item"
    fields_desc = [
        ByteEnumField("item_type", 0x10, ITEM_TYPES),
        ByteField("reserved", 0),
        # LenField automatically calculates payload length when set to None
        LenField("length", None, fmt="!H"),
    ]

    def extract_padding(self, s):
        """Extract padding for PacketListField parsing.
        
        Returns (payload_for_this_item, remaining_for_next_item).
        Uses the length field to determine how much data belongs to this item's payload.
        """
        if self.length is not None:
            if len(s) < self.length:
                raise Exception("PDU payload incomplete - waiting for more data")
            return s[:self.length], s[self.length:]
        return s, b""
    
    def guess_payload_class(self, payload):
        """Dispatch to the correct sub-packet based on item_type."""
        type_to_class = {
            0x10: DICOMApplicationContext,
            0x20: DICOMPresentationContextRQ,
            0x21: DICOMPresentationContextAC,
            0x30: DICOMAbstractSyntax,
            0x40: DICOMTransferSyntax,
            0x50: DICOMUserInformation,
            0x51: DICOMMaximumLength,
            0x52: DICOMImplementationClassUID,
            0x55: DICOMImplementationVersionName,
        }
        return type_to_class.get(self.item_type, DICOMGenericItem)


class DICOMApplicationContext(Packet):
    """
    Application Context Item payload (Type 0x10).
    
    Contains the Application Context UID, typically "1.2.840.10008.3.1.1.1".
    
    Usage:
        pkt = DICOMVariableItem() / DICOMApplicationContext()
        # item_type automatically set to 0x10, length auto-calculated
    """
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
    """
    Abstract Syntax Sub-Item payload (Type 0x30).
    
    Nested inside Presentation Context items. Contains the SOP Class UID
    (e.g., Verification, CT Image Storage).
    
    Usage:
        pkt = DICOMVariableItem() / DICOMAbstractSyntax(uid="1.2.840.10008.1.1")
    """
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
    """
    Transfer Syntax Sub-Item payload (Type 0x40).
    
    Nested inside Presentation Context items. Specifies encoding
    (e.g., Implicit VR Little Endian).
    
    Usage:
        pkt = DICOMVariableItem() / DICOMTransferSyntax(uid="1.2.840.10008.1.2")
    """
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
    """
    Presentation Context Item payload for A-ASSOCIATE-RQ (Type 0x20).
    
    Contains:
        - context_id: Odd number 1-255 identifying this context
        - Nested items: One Abstract Syntax + one or more Transfer Syntaxes
    
    Usage:
        abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid="1.2.840.10008.1.1")
        ts = DICOMVariableItem() / DICOMTransferSyntax()
        pctx = DICOMVariableItem() / DICOMPresentationContextRQ(
            context_id=1,
            sub_items=[abs_syn, ts]
        )
    """
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
    """
    Presentation Context Item payload for A-ASSOCIATE-AC (Type 0x21).
    
    Contains:
        - context_id: Matches the RQ context_id
        - result: 0=accepted, 1=user-rejection, 2=no-reason, 3=abstract-syntax-not-supported, 4=transfer-syntaxes-not-supported
        - Nested: One Transfer Syntax (the accepted one)
    
    Usage:
        ts = DICOMVariableItem() / DICOMTransferSyntax()
        pctx_ac = DICOMVariableItem() / DICOMPresentationContextAC(
            context_id=1,
            result=0,
            sub_items=[ts]
        )
    """
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
    """
    Maximum Length Sub-Item payload (Type 0x51).
    
    Nested inside User Information. Specifies the maximum PDU size
    that can be received.
    
    Usage:
        max_len = DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=16384)
    """
    name = "DICOM Maximum Length"
    fields_desc = [
        IntField("max_pdu_length", 16384),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMImplementationClassUID(Packet):
    """
    Implementation Class UID Sub-Item payload (Type 0x52).
    
    Nested inside User Information. Identifies the implementation.
    
    Usage:
        impl = DICOMVariableItem() / DICOMImplementationClassUID(uid="1.2.3.4")
    """
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
    """
    Implementation Version Name Sub-Item payload (Type 0x55).
    
    Nested inside User Information. Version string for the implementation.
    
    Usage:
        ver = DICOMVariableItem() / DICOMImplementationVersionName(name=b"SCAPY_DICOM")
    """
    name = "DICOM Implementation Version Name"
    fields_desc = [
        StrLenField("name", b"",
                    length_from=lambda pkt: (pkt.underlayer.length
                                             if pkt.underlayer and pkt.underlayer.length
                                             else len(pkt.name))),
    ]

    def extract_padding(self, s):
        return b"", s


class DICOMUserInformation(Packet):
    """
    User Information Item payload (Type 0x50).
    
    Contains nested sub-items like Maximum Length, Implementation Class UID, etc.
    
    Usage:
        max_len = DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=16384)
        user_info = DICOMVariableItem() / DICOMUserInformation(sub_items=[max_len])
    """
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
    """
    Generic/Unknown Item payload for unrecognized item types.
    
    Used as fallback when item_type doesn't match a known type.
    Allows parsing unknown item types without failing.
    """
    name = "DICOM Generic Item"
    fields_desc = [
        StrLenField("data", b"",
                    length_from=lambda pkt: (pkt.underlayer.length
                                             if pkt.underlayer and pkt.underlayer.length
                                             else len(pkt.data))),
    ]

    def extract_padding(self, s):
        return b"", s


# --- Variable Item Layer Bindings ---
# These bind the item_type field to the appropriate payload class
bind_layers(DICOMVariableItem, DICOMApplicationContext, item_type=0x10)
bind_layers(DICOMVariableItem, DICOMPresentationContextRQ, item_type=0x20)
bind_layers(DICOMVariableItem, DICOMPresentationContextAC, item_type=0x21)
bind_layers(DICOMVariableItem, DICOMAbstractSyntax, item_type=0x30)
bind_layers(DICOMVariableItem, DICOMTransferSyntax, item_type=0x40)
bind_layers(DICOMVariableItem, DICOMUserInformation, item_type=0x50)
bind_layers(DICOMVariableItem, DICOMMaximumLength, item_type=0x51)
bind_layers(DICOMVariableItem, DICOMImplementationClassUID, item_type=0x52)
bind_layers(DICOMVariableItem, DICOMImplementationVersionName, item_type=0x55)
# Fallback for unknown types
bind_layers(DICOMVariableItem, DICOMGenericItem)


# =============================================================================
# DICOM PDU Classes
# =============================================================================
# KEY FIX: Using LenField instead of IntField + manual post_build.
# LenField automatically calculates the payload length when set to None.
# =============================================================================

class DICOM(Packet):
    """
    DICOM Upper Layer PDU header.

    This is the main PDU wrapper containing type, reserved byte, and length.
    
    The extract_padding() method enables proper framing with StreamSocket,
    so Scapy can automatically handle PDU boundaries in TCP streams.
    
    KEY FIX: Using LenField for automatic payload length calculation.
    No more manual post_build with struct.pack!
    """
    name = "DICOM UL"
    fields_desc = [
        ByteEnumField("pdu_type", 0x01, PDU_TYPES),
        ByteField("reserved1", 0),
        # LenField automatically calculates payload length when set to None
        LenField("length", None, fmt="!I"),
    ]

    def extract_padding(self, s):
        """
        Extract padding for proper StreamSocket framing.
        
        Returns (payload_for_this_pdu, remaining_data_for_next_pdu).
        Uses the length field to determine PDU boundaries.
        """
        if self.length is not None:
            return s[:self.length], s[self.length:]
        return s, b""


class PresentationDataValueItem(Packet):
    """
    Presentation Data Value Item within a P-DATA-TF PDU.

    Contains context ID, message control header, and the actual DIMSE data.
    
    Message Control Header bits:
        Bit 0 (is_command): 1 = Command message, 0 = Data message
        Bit 1 (is_last): 1 = Last fragment, 0 = More fragments follow
    
    KEY FIX: Using FieldLenField to link length and data fields.
    When you update `data`, Scapy automatically updates `length`.
    """
    name = "PresentationDataValueItem"
    fields_desc = [
        # FieldLenField links to the 'data' field and adds 2 for context_id + control byte
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
    """
    A-ASSOCIATE-RQ PDU for requesting an association.

    Contains called/calling AE titles and variable items for negotiation.
    """
    name = "A-ASSOCIATE-RQ"
    fields_desc = [
        ShortField("protocol_version", 1),
        ShortField("reserved1", 0),
        StrFixedLenField("called_ae_title", b"", 16),
        StrFixedLenField("calling_ae_title", b"", 16),
        StrFixedLenField("reserved2", b"\x00" * 32, 32),
        PacketListField("variable_items", [],
                        DICOMVariableItem,
                        max_count=256,
                        length_from=lambda pkt: (pkt.underlayer.length - 68
                                                  if pkt.underlayer and pkt.underlayer.length
                                                  else 0)),
    ]


class A_ASSOCIATE_AC(Packet):
    """
    A-ASSOCIATE-AC PDU for accepting an association.

    Has the same structure as A-ASSOCIATE-RQ.
    """
    name = "A-ASSOCIATE-AC"
    fields_desc = [
        ShortField("protocol_version", 1),
        ShortField("reserved1", 0),
        StrFixedLenField("called_ae_title", b"", 16),
        StrFixedLenField("calling_ae_title", b"", 16),
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
    """
    P-DATA-TF PDU for transferring presentation data.

    Contains one or more Presentation Data Value Items.
    """
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


# --- PDU Layer Bindings ---
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
    """
    Build a Presentation Context RQ item using proper Scapy packets.
    
    :param context_id: Odd number 1-255
    :param abstract_syntax_uid: SOP Class UID (string or bytes)
    :param transfer_syntax_uids: List of Transfer Syntax UIDs
    :return: DICOMVariableItem / DICOMPresentationContextRQ packet
    """
    # Build Abstract Syntax sub-item
    abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid=_uid_to_bytes(abstract_syntax_uid))
    
    # Build Transfer Syntax sub-items
    sub_items = [abs_syn]
    for ts_uid in transfer_syntax_uids:
        ts = DICOMVariableItem() / DICOMTransferSyntax(uid=_uid_to_bytes(ts_uid))
        sub_items.append(ts)
    
    # Build Presentation Context
    return DICOMVariableItem() / DICOMPresentationContextRQ(
        context_id=context_id,
        sub_items=sub_items,
    )


def build_user_information(max_pdu_length=16384, implementation_class_uid=None, implementation_version=None):
    """
    Build a User Information item using proper Scapy packets.
    
    :param max_pdu_length: Maximum PDU size to negotiate
    :param implementation_class_uid: Optional implementation class UID
    :param implementation_version: Optional implementation version name
    :return: DICOMVariableItem / DICOMUserInformation packet
    """
    sub_items = [
        DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=max_pdu_length)
    ]
    
    if implementation_class_uid:
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationClassUID(uid=_uid_to_bytes(implementation_class_uid))
        )
    
    if implementation_version:
        ver_bytes = implementation_version if isinstance(implementation_version, bytes) else implementation_version.encode('ascii')
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationVersionName(name=ver_bytes)
        )
    
    return DICOMVariableItem() / DICOMUserInformation(sub_items=sub_items)


# =============================================================================
# DICOM Session Helper Class
# =============================================================================
# KEY FIX: Removed all manual struct.pack calls for PDU serialization.
# The session now relies entirely on Packet objects to serialize themselves
# using the proper LenField and FieldLenField mechanisms.
# =============================================================================

class DICOMSession:
    """
    High-level helper class for DICOM network operations.

    Provides methods for association establishment, C-ECHO, C-STORE,
    and graceful release.
    
    Uses Scapy's StreamSocket for automatic PDU framing - no manual
    socket recv loops needed!

    Example usage::

        session = DICOMSession("192.168.1.100", 104, "TARGET_AE")
        if session.associate():
            status = session.c_echo()
            print(f"C-ECHO status: {status}")
            session.release()
    """

    def __init__(self, dst_ip, dst_port, dst_ae, src_ae="SCAPY_SCU", 
                 read_timeout=10, raw_mode=False):
        """
        Initialize a DICOM session.

        :param dst_ip: Destination IP address
        :param dst_port: Destination port (typically 104 or 11112)
        :param dst_ae: Destination Application Entity title
        :param src_ae: Source Application Entity title (default: "SCAPY_SCU")
        :param read_timeout: Socket read timeout in seconds (default: 10)
        :param raw_mode: If True, disable auto-corrections for fuzzing (default: False)
        """
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dst_ae = _pad_ae_title(dst_ae)
        self.src_ae = _pad_ae_title(src_ae)
        self.sock = None
        self.stream = None
        self.assoc_established = False
        self.accepted_contexts = {}
        self.read_timeout = read_timeout
        self._current_message_id_counter = int(time.time()) % 50000
        self._proposed_max_pdu = 16384
        self.max_pdu_length = 16384
        self.raw_mode = raw_mode
        self._proposed_context_map = {}

    def connect(self):
        """Establish TCP connection to the DICOM server."""
        try:
            self.sock = socket.create_connection(
                (self.dst_ip, self.dst_port),
                timeout=self.read_timeout,
            )
            # StreamSocket handles framing automatically using DICOM.extract_padding()
            self.stream = StreamSocket(self.sock, basecls=DICOM)
            return True
        except Exception as e:
            log.error("Connection failed: %s", e)
            return False

    def send(self, pkt):
        """
        Send a DICOM PDU using StreamSocket.
        
        :param pkt: DICOM packet to send
        """
        self.stream.send(pkt)
    
    def recv(self):
        """
        Receive a DICOM PDU using StreamSocket.
        
        StreamSocket handles PDU framing automatically by reading the
        6-byte header, extracting the length, and reading the full payload.
        
        :return: Parsed DICOM packet or None on timeout/error
        """
        try:
            # StreamSocket.recv() returns a parsed packet
            return self.stream.recv()
        except socket.timeout:
            return None
        except Exception as e:
            log.error("Error receiving PDU: %s", e)
            return None
    
    def sr1(self, pkt):
        """
        Send a PDU and receive the response (Send-Receive 1).
        
        This is the kosher Scapy pattern for request-response protocols.
        
        :param pkt: DICOM packet to send
        :return: Parsed response DICOM packet or None
        """
        try:
            # sr1 sends packet and waits for exactly one response
            return self.stream.sr1(pkt, timeout=self.read_timeout)
        except socket.timeout:
            return None
        except Exception as e:
            log.error("Error in sr1: %s", e)
            return None
    
    def send_raw_bytes(self, raw_bytes):
        """Send raw bytes directly to the socket (for fuzzing)."""
        self.sock.sendall(raw_bytes)

    def associate(self, requested_contexts=None):
        """
        Request DICOM association with the server.

        :param requested_contexts: Dict mapping SOP Class UIDs to lists of
            Transfer Syntax UIDs. If None, requests Verification SOP Class
            with Implicit VR Little Endian.
        :return: True if association accepted, False otherwise
        """
        if not self.stream and not self.connect():
            return False

        if requested_contexts is None:
            requested_contexts = {
                VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
            }

        self._proposed_context_map = {}

        # Build variable items using proper Scapy packets (no more struct.pack!)
        variable_items = [
            # Application Context - just stack the layers
            DICOMVariableItem() / DICOMApplicationContext()
        ]

        # Build presentation contexts
        ctx_id = 1
        for abs_syntax, trn_syntaxes in requested_contexts.items():
            self._proposed_context_map[ctx_id] = abs_syntax
            
            # Use helper function to build presentation context
            pctx = build_presentation_context_rq(ctx_id, abs_syntax, trn_syntaxes)
            variable_items.append(pctx)
            ctx_id += 2

        # User Information with Max PDU Length
        user_info = build_user_information(max_pdu_length=self._proposed_max_pdu)
        variable_items.append(user_info)

        # Build A-ASSOCIATE-RQ - LenField handles length automatically!
        assoc_rq = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.dst_ae,
            calling_ae_title=self.src_ae,
            variable_items=variable_items,
        )

        # Use sr1() - the kosher Scapy pattern for send-and-receive
        response = self.sr1(assoc_rq)

        if response:
            if response.haslayer(A_ASSOCIATE_AC):
                self.assoc_established = True
                self._parse_accepted_contexts(response)
                self._parse_max_pdu_length(response)
                return True
            elif response.haslayer(A_ASSOCIATE_RJ):
                log.error(
                    "Association rejected: result=%d, source=%d, reason=%d",
                    response[A_ASSOCIATE_RJ].result,
                    response[A_ASSOCIATE_RJ].source,
                    response[A_ASSOCIATE_RJ].reason_diag,
                )
                return False

        log.error("Association failed: no valid response received")
        return False

    def _parse_max_pdu_length(self, response):
        """Parse max PDU length from A-ASSOCIATE-AC User Information."""
        try:
            for item in response[A_ASSOCIATE_AC].variable_items:
                # Check if this is a User Information item
                if item.item_type == 0x50 and item.haslayer(DICOMUserInformation):
                    user_info = item[DICOMUserInformation]
                    for sub_item in user_info.sub_items:
                        if sub_item.item_type == 0x51 and sub_item.haslayer(DICOMMaximumLength):
                            server_max = sub_item[DICOMMaximumLength].max_pdu_length
                            self.max_pdu_length = min(self._proposed_max_pdu, server_max)
                            log.debug("Negotiated max PDU length: %d", self.max_pdu_length)
                            return
        except Exception as e:
            log.debug("Could not parse max PDU length: %s", e)
        self.max_pdu_length = self._proposed_max_pdu

    def _parse_accepted_contexts(self, response):
        """Parse accepted presentation contexts from A-ASSOCIATE-AC."""
        for item in response[A_ASSOCIATE_AC].variable_items:
            # Check if this is a Presentation Context AC item
            if item.item_type == 0x21 and item.haslayer(DICOMPresentationContextAC):
                pctx = item[DICOMPresentationContextAC]
                ctx_id = pctx.context_id
                result = pctx.result
                
                if result != 0:  # Not accepted
                    log.debug("Presentation context %d rejected (result=%d)", ctx_id, result)
                    continue
                
                abs_syntax = self._proposed_context_map.get(ctx_id)
                if abs_syntax is None:
                    log.warning(
                        "Server accepted context ID %d which we didn't propose!",
                        ctx_id
                    )
                    continue
                
                # Get the accepted transfer syntax from sub-items
                for sub_item in pctx.sub_items:
                    if sub_item.item_type == 0x40 and sub_item.haslayer(DICOMTransferSyntax):
                        ts_uid = sub_item[DICOMTransferSyntax].uid
                        if isinstance(ts_uid, bytes):
                            ts_uid = ts_uid.rstrip(b"\x00").decode("ascii")
                        self.accepted_contexts[ctx_id] = (abs_syntax, ts_uid)
                        log.debug(
                            "Accepted context %d: %s with transfer syntax %s",
                            ctx_id, abs_syntax, ts_uid
                        )
                        break

    def _get_next_message_id(self):
        """Get the next message ID for DIMSE commands."""
        self._current_message_id_counter += 1
        return self._current_message_id_counter & 0xFFFF

    def _find_accepted_context_id(self, sop_class_uid, transfer_syntax_uid=None):
        """Find an accepted presentation context ID for the given SOP Class."""
        for ctx_id, (abs_syntax, ts_syntax) in self.accepted_contexts.items():
            if abs_syntax == sop_class_uid:
                if transfer_syntax_uid is None or transfer_syntax_uid == ts_syntax:
                    return ctx_id
        return None

    def c_echo(self):
        """
        Send a C-ECHO request (DICOM ping).

        :return: Status code (0 = success) or None if failed
        """
        if not self.assoc_established:
            log.error("Association not established")
            return None

        echo_ctx_id = self._find_accepted_context_id(VERIFICATION_SOP_CLASS_UID)
        if echo_ctx_id is None:
            log.error("No accepted context for Verification SOP Class")
            return None

        msg_id = self._get_next_message_id()
        
        # Use the DIMSE packet class - DIMSEPacket.post_build handles CommandGroupLength
        dimse_rq = bytes(C_ECHO_RQ(message_id=msg_id))
        
        # Build PDV and P-DATA-TF - FieldLenField handles PDV length automatically
        pdv_rq = PresentationDataValueItem(
            context_id=echo_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        # LenField in DICOM handles PDU length automatically
        pdata_rq = DICOM() / P_DATA_TF(pdv_items=[pdv_rq])

        # Use sr1() - send and receive in one call
        response = self.sr1(pdata_rq)

        if response and response.haslayer(P_DATA_TF):
            pdv_items = response[P_DATA_TF].pdv_items
            if pdv_items:
                pdv_rsp = pdv_items[0]
                data = pdv_rsp.data
                if isinstance(data, str):
                    data = data.encode("latin-1")
                return parse_dimse_status(data)
        return None

    def c_store(self, dataset_bytes, sop_class_uid, sop_instance_uid,
                transfer_syntax_uid):
        """
        Send a C-STORE request to store a DICOM dataset.

        :param dataset_bytes: Raw bytes of the DICOM dataset
        :param sop_class_uid: SOP Class UID of the dataset
        :param sop_instance_uid: SOP Instance UID of the dataset
        :param transfer_syntax_uid: Transfer Syntax UID used to encode the dataset
        :return: Status code (0 = success) or None if failed
        """
        if not self.assoc_established:
            log.error("Association not established")
            return None

        store_ctx_id = self._find_accepted_context_id(
            sop_class_uid,
            transfer_syntax_uid,
        )
        if store_ctx_id is None:
            log.error(
                "No accepted context for SOP Class %s with Transfer Syntax %s",
                sop_class_uid,
                transfer_syntax_uid,
            )
            return None

        msg_id = self._get_next_message_id()
        
        # Use DIMSE packet class - DIMSEPacket.post_build handles CommandGroupLength
        if self.raw_mode:
            dimse_rq = build_c_store_rq_dimse_raw(sop_class_uid, sop_instance_uid, msg_id)
        else:
            dimse_rq = bytes(C_STORE_RQ(
                affected_sop_class_uid=sop_class_uid,
                affected_sop_instance_uid=sop_instance_uid,
                message_id=msg_id,
            ))

        # Build command PDV - FieldLenField handles length automatically
        cmd_pdv = PresentationDataValueItem(
            context_id=store_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        # LenField in DICOM handles PDU length automatically
        pdata_cmd = DICOM() / P_DATA_TF(pdv_items=[cmd_pdv])
        self.send(pdata_cmd)

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
            log.debug(
                "Fragmented %d bytes into %d PDUs",
                len(dataset_bytes),
                (len(dataset_bytes) + max_pdv_data - 1) // max_pdv_data,
            )

        # Receive the response
        response = self.recv()

        if response and response.haslayer(P_DATA_TF):
            pdv_items = response[P_DATA_TF].pdv_items
            if pdv_items:
                pdv_rsp = pdv_items[0]
                data = pdv_rsp.data
                if isinstance(data, str):
                    data = data.encode("latin-1")
                return parse_dimse_status(data)
        return None
    
    def c_store_raw(self, dataset_bytes, sop_class_uid, sop_instance_uid,
                    context_id, skip_padding=True):
        """Send a raw C-STORE request for fuzzing purposes."""
        if not self.assoc_established:
            log.error("Association not established")
            return None

        msg_id = self._get_next_message_id()
        
        if skip_padding:
            dimse_rq = build_c_store_rq_dimse_raw(sop_class_uid, sop_instance_uid, msg_id)
        else:
            dimse_rq = bytes(C_STORE_RQ(
                affected_sop_class_uid=sop_class_uid,
                affected_sop_instance_uid=sop_instance_uid,
                message_id=msg_id,
            ))

        cmd_pdv = PresentationDataValueItem(
            context_id=context_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        pdata_cmd = DICOM() / P_DATA_TF(pdv_items=[cmd_pdv])
        self.send(pdata_cmd)

        data_pdv = PresentationDataValueItem(
            context_id=context_id,
            data=dataset_bytes,
            is_command=0,
            is_last=1,
        )
        pdata_data = DICOM() / P_DATA_TF(pdv_items=[data_pdv])
        self.send(pdata_data)

        response = self.recv()

        if response:
            if response.haslayer(P_DATA_TF):
                pdv_items = response[P_DATA_TF].pdv_items
                if pdv_items:
                    pdv_rsp = pdv_items[0]
                    data = pdv_rsp.data
                    if isinstance(data, str):
                        data = data.encode("latin-1")
                    return parse_dimse_status(data)
            elif response.haslayer(A_ABORT):
                log.info("Server aborted connection (expected for malformed data)")
                return None
        return None

    def release(self):
        """Request graceful release of the association."""
        if not self.assoc_established:
            return True

        release_rq = DICOM() / A_RELEASE_RQ()
        
        # Use sr1() for the release handshake
        response = self.sr1(release_rq)
        self.close()

        if response:
            return response.haslayer(A_RELEASE_RP)
        return False

    def close(self):
        """Close the underlying socket connection."""
        if self.stream:
            try:
                self.stream.close()
            except Exception:
                pass
        self.sock = None
        self.stream = None
        self.assoc_established = False