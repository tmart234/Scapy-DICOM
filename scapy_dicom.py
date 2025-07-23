# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
# pylint: disable=attribute-defined-outside-init

"""
DICOM Upper Layer Protocol for Scapy

This module implements the DICOM Upper Layer Protocol as defined in
DICOM Standard PS3.8 (Network Communication Support for Message Exchange)
and relevant sections of PS3.7 (Message Exchange).

It supports Association establishment (A-ASSOCIATE-RQ/AC/RJ),
Data Transfer (P-DATA-TF), Association Release (A-RELEASE-RQ/RP),
and Association Abort (A-ABORT).
"""

import struct
import time
import socket
import logging
from io import BytesIO

from scapy.all import Packet, bind_layers, PacketListField, conf
from scapy.fields import (
    ByteEnumField, ByteField, ShortField, IntField, FieldLenField,
    StrFixedLenField, StrLenField, ShortEnumField, Field, BitField,
    StrField
)
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket
from scapy.packet import NoPayload, Raw

# Use scapy's logger for consistency if desired, or keep this one
log = logging.getLogger("scapy.contrib.dicom")
# Ensure logs are visible if running standalone
logging.basicConfig(level=logging.DEBUG)


DICOM_PORT = 104
APP_CONTEXT_UID = "1.2.840.10008.3.1.1.1"
DEFAULT_TRANSFER_SYNTAX_UID = "1.2.840.10008.1.2"
VERIFICATION_SOP_CLASS_UID = "1.2.840.10008.1.1"
CT_IMAGE_STORAGE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.2"

def _pad_ae_title(title):
    """Pad AE Title with trailing spaces to 16 bytes."""
    if isinstance(title, bytes):
        return title.ljust(16, b' ')
    return title.ljust(16).encode('ascii')

def _uid_to_bytes(uid):
    """Encode UID string to bytes, handling potential trailing null byte.
       Also handles input that might already be bytes.
    """
    if isinstance(uid, bytes):
        # If input is already bytes, just handle padding
        b_uid = uid
    elif isinstance(uid, str):
        # If input is string, encode it
        b_uid = uid.encode('ascii')
    elif uid is None:
        return b'' # Handle None input gracefully
    else:
        # Raise error for unexpected types
        raise TypeError(f"Unsupported type for UID conversion: {type(uid)}")

    # DICOM UIDs may be padded with a single NULL byte (0x00) if their length is odd
    if len(b_uid) % 2 != 0:
        b_uid += b'\x00'
    return b_uid

# --- Minimal DIMSE C-ECHO-RQ Builder ---
# Creates C-ECHO RQ bytes using Implicit VR Little Endian
def build_c_echo_rq_dimse(message_id=1):
    """
    Builds raw bytes for a C-ECHO-RQ DIMSE command message using Implicit VR LE encoding.

    Args:
        message_id (int): The Message ID to use for the command.

    Returns:
        bytes: The raw DIMSE command bytes.
    """
    log.debug(f"Building C-ECHO-RQ DIMSE (Implicit VR LE) (Message ID: {message_id})")
    # Build elements *before* calculating group length
    elements_payload = b''
    affected_sop_uid_bytes = _uid_to_bytes(VERIFICATION_SOP_CLASS_UID) # Use constant defined in this module

    # (0000,0002) Affected SOP Class UID - Tag(4), Len(4), Value(N)
    elements_payload += struct.pack("<HH", 0x0000, 0x0002) + struct.pack("<I", len(affected_sop_uid_bytes)) + affected_sop_uid_bytes

    # (0000,0100) Command Field (C-ECHO-RQ = 0x0030) - Tag(4), Len(4)=2, Value(2)
    elements_payload += struct.pack("<HH", 0x0000, 0x0100) + struct.pack("<I", 2) + struct.pack("<H", 0x0030)

    # (0000,0110) Message ID - Tag(4), Len(4)=2, Value(2)
    elements_payload += struct.pack("<HH", 0x0000, 0x0110) + struct.pack("<I", 2) + struct.pack("<H", message_id)

    # (0000,0800) Command Data Set Type (0x0101 = No dataset) - Tag(4), Len(4)=2, Value(2)
    elements_payload += struct.pack("<HH", 0x0000, 0x0800) + struct.pack("<I", 2) + struct.pack("<H", 0x0101)

    # Calculate group length (length of all elements built above)
    cmd_group_len = len(elements_payload)

    # (0000,0000) Command Group Length - Tag(4), Len(4)=4, Value(4)
    group_length_element = struct.pack("<HH", 0x0000, 0x0000) + struct.pack("<I", 4) + struct.pack("<I", cmd_group_len)

    # Prepend group length element to the other elements
    dimse_command_set = group_length_element + elements_payload

    log.debug(f"Built DIMSE Command Set (Implicit VR LE) (len={len(dimse_command_set)}): {dimse_command_set.hex()}")
    return dimse_command_set

def build_c_store_rq_dimse(sop_class_uid, sop_instance_uid, message_id=1, priority=0x0002,
                           move_originator_aet=None, move_originator_msg_id=None):
    """
    Builds raw bytes for a C-STORE-RQ DIMSE command message using Implicit VR LE encoding.
    """
    log.debug(f"Building C-STORE-RQ DIMSE (Message ID: {message_id})")
    elements_payload = b''

    # (0000,0002) Affected SOP Class UID
    affected_sop_class_uid_bytes = _uid_to_bytes(sop_class_uid)
    elements_payload += struct.pack("<HH", 0x0000, 0x0002) + struct.pack("<I", len(affected_sop_class_uid_bytes)) + affected_sop_class_uid_bytes
    # (0000,0100) Command Field (C-STORE-RQ = 0x0001)
    elements_payload += struct.pack("<HH", 0x0000, 0x0100) + struct.pack("<I", 2) + struct.pack("<H", 0x0001)
    # (0000,0110) Message ID
    elements_payload += struct.pack("<HH", 0x0000, 0x0110) + struct.pack("<I", 2) + struct.pack("<H", message_id)
    # (0000,0700) Priority (MEDIUM = 0x0002)
    elements_payload += struct.pack("<HH", 0x0000, 0x0700) + struct.pack("<I", 2) + struct.pack("<H", priority)
    # (0000,0800) Command Data Set Type (indicates a Data Set is present)
    elements_payload += struct.pack("<HH", 0x0000, 0x0800) + struct.pack("<I", 2) + struct.pack("<H", 0x0102)
    # (0000,1000) Affected SOP Instance UID
    affected_sop_instance_uid_bytes = _uid_to_bytes(sop_instance_uid)
    elements_payload += struct.pack("<HH", 0x0000, 0x1000) + struct.pack("<I", len(affected_sop_instance_uid_bytes)) + affected_sop_instance_uid_bytes
    # (0000,1002) Move Originator Application Entity Title (Conditional)
    if move_originator_aet:
        move_aet_bytes = _pad_ae_title(move_originator_aet)
        elements_payload += struct.pack("<HH", 0x0000, 0x1002) + struct.pack("<I", len(move_aet_bytes)) + move_aet_bytes
    # (0000,1003) Move Originator Message ID (Conditional)
    if move_originator_msg_id is not None:
        elements_payload += struct.pack("<HH", 0x0000, 0x1003) + struct.pack("<I", 2) + struct.pack("<H", move_originator_msg_id)

    cmd_group_len = len(elements_payload)
    group_length_element = struct.pack("<HH", 0x0000, 0x0000) + struct.pack("<I", 4) + struct.pack("<I", cmd_group_len)
    dimse_command_set = group_length_element + elements_payload
    log.debug(f"Built C-STORE-RQ DIMSE (len={len(dimse_command_set)}): {dimse_command_set.hex()}")
    return dimse_command_set

def parse_dimse_status(dimse_bytes):
    """
    Parses the Status (0000,0900) from DIMSE bytes (Implicit VR Little Endian).

    Args:
        dimse_bytes (bytes): The raw bytes of the DIMSE message (starting with Group 0 Length).

    Returns:
        int or None: The Status value (e.g., 0x0000 for Success) if found,
                     otherwise None (if tag not found, wrong format, or parse error).
    """
    try:
        offset = 0
        # Check minimum length for Group 0 Length element (Tag + Len + Value)
        if len(dimse_bytes) < 12:
            log.debug("parse_dimse_status: DIMSE bytes too short for Group Length.")
            return None

        # Check Group 0 Length Tag and Length Field Length
        tag_group, tag_elem = struct.unpack("<HH", dimse_bytes[offset:offset+4])
        value_len_field_len = struct.unpack("<I", dimse_bytes[offset+4:offset+8])[0]
        if not (tag_group == 0x0000 and tag_elem == 0x0000 and value_len_field_len == 4):
            log.debug(f"parse_dimse_status: Expected Group Length Tag (0000,0000) with UL VR (len=4), got ({tag_group:04X},{tag_elem:04X}) Len={value_len_field_len}.")
            return None # Not starting with a valid Group Length element

        # Read the group length value
        cmd_group_len = struct.unpack("<I", dimse_bytes[offset+8:offset+12])[0]
        offset += 12 # Move past the Group Length element

        # Define the end boundary for searching within this group
        group_end_offset = offset + cmd_group_len

        log.debug(f"parse_dimse_status: Searching for Status (0000,0900) within group length {cmd_group_len} (ends at offset {group_end_offset}).")

        while offset < group_end_offset and offset < len(dimse_bytes):
            # Check minimum length for next element header (Tag + Len)
            if offset + 8 > len(dimse_bytes):
                log.debug(f"parse_dimse_status: Truncated element header at offset {offset}.")
                break

            # Read Tag and Value Length (Implicit VR LE)
            tag_group, tag_elem = struct.unpack("<HH", dimse_bytes[offset:offset+4])
            value_len = struct.unpack("<I", dimse_bytes[offset+4:offset+8])[0]
            data_offset = offset + 8
            next_element_offset = data_offset + value_len

            log.debug(f"  Checking Tag: ({tag_group:04X},{tag_elem:04X}), Len: {value_len}, Data Offset: {data_offset}")

            # Check if element exceeds available data (more important than group boundary here)
            if next_element_offset > len(dimse_bytes):
                 log.warning(f"parse_dimse_status: Element ({tag_group:04X},{tag_elem:04X}) length ({value_len}) exceeds available data ({len(dimse_bytes)} total).")
                 break

            if tag_group == 0x0000 and tag_elem == 0x0900: # Status tag found
                log.debug("  Status tag (0000,0900) found.")
                if value_len == 2: # Status is US (2 bytes)
                    if data_offset + 2 <= len(dimse_bytes):
                        status_bytes = dimse_bytes[data_offset:data_offset+2]
                        status = struct.unpack("<H", status_bytes)[0]
                        log.debug(f"  Parsed Status value: 0x{status:04X}")
                        return status # Return the found status
                    else:
                         log.warning("  Status tag (0000,0900) found, but value is truncated.")
                         return None # Indicate parse error
                else:
                    log.warning(f"  Status tag (0000,0900) found but value length is {value_len}, expected 2.")
                    return None # Indicate parse error (unexpected length)

            # Move to next element
            offset = next_element_offset

        log.debug("parse_dimse_status: Status tag (0000,0900) not found within the command group.")
        return None # Status tag not found in the group

    except struct.error as e:
        log.error(f"Struct unpack error parsing DIMSE status: {e}")
        log.error(f"DIMSE Data near error: {dimse_bytes[max(0,offset-4):offset+12].hex()}")
        return None
    except Exception as e:
        log.exception(f"Unexpected error parsing DIMSE status: {e}") # Log stack trace
        return None


def build_c_store_rq_dimse(sop_class_uid, sop_instance_uid, message_id=1, priority=0x0002,
                           move_originator_aet=None, move_originator_msg_id=None):
    """
    Builds raw bytes for a C-STORE-RQ DIMSE command message using Implicit VR LE encoding.
    """
    log.debug(f"Building C-STORE-RQ DIMSE (Message ID: {message_id})")
    elements_payload = b''

    # (0000,0002) Affected SOP Class UID
    affected_sop_class_uid_bytes = _uid_to_bytes(sop_class_uid)
    elements_payload += struct.pack("<HH", 0x0000, 0x0002) + struct.pack("<I", len(affected_sop_class_uid_bytes)) + affected_sop_class_uid_bytes

    # (0000,0100) Command Field (C-STORE-RQ = 0x0001)
    elements_payload += struct.pack("<HH", 0x0000, 0x0100) + struct.pack("<I", 2) + struct.pack("<H", 0x0001)

    # (0000,0110) Message ID
    elements_payload += struct.pack("<HH", 0x0000, 0x0110) + struct.pack("<I", 2) + struct.pack("<H", message_id)

    # (0000,0700) Priority (MEDIUM = 0x0002)
    elements_payload += struct.pack("<HH", 0x0000, 0x0700) + struct.pack("<I", 2) + struct.pack("<H", priority)

    # (0000,0800) Command Data Set Type (Indicates that a Data Set is present in the Message)
    # For C-STORE-RQ, this refers to the command itself. The dataset follows in P-DATA.
    # Standard says "Set to any value other than 0101H (Null)". Typically 0x0000 or 0x0102.
    # Let's use 0x0102, indicating "Data Set Present (Command)" - but this usually refers to attributes *within* the command.
    # More common practice for C-STORE-RQ is that the command dataset itself is NULL (0x0101),
    # and the image dataset follows in the P-DATA stream.
    elements_payload += struct.pack("<HH", 0x0000, 0x0800) + struct.pack("<I", 2) + struct.pack("<H", 0x0101) # No Command Dataset

    # (0000,1000) Affected SOP Instance UID
    affected_sop_instance_uid_bytes = _uid_to_bytes(sop_instance_uid)
    elements_payload += struct.pack("<HH", 0x0000, 0x1000) + struct.pack("<I", len(affected_sop_instance_uid_bytes)) + affected_sop_instance_uid_bytes

    # (0000,1002) Move Originator Application Entity Title (Conditional)
    if move_originator_aet:
        move_aet_bytes = _pad_ae_title(move_originator_aet) # AE titles are fixed 16 bytes
        elements_payload += struct.pack("<HH", 0x0000, 0x1002) + struct.pack("<I", len(move_aet_bytes)) + move_aet_bytes
    
    # (0000,1003) Move Originator Message ID (Conditional)
    if move_originator_msg_id is not None: # Check for None as 0 is a valid ID
        elements_payload += struct.pack("<HH", 0x0000, 0x1003) + struct.pack("<I", 2) + struct.pack("<H", move_originator_msg_id)

    # Calculate Command Group Length
    cmd_group_len = len(elements_payload)
    group_length_element = struct.pack("<HH", 0x0000, 0x0000) + struct.pack("<I", 4) + struct.pack("<I", cmd_group_len)
    
    dimse_command_set = group_length_element + elements_payload
    log.debug(f"Built C-STORE-RQ DIMSE (len={len(dimse_command_set)}): {dimse_command_set.hex()}")
    return dimse_command_set


# --- DICOM Base PDU ---
class DICOM(Packet):
    """
    DICOM Upper Layer Base PDU
    PS3.8 Section 9.1
    """
    name = "DICOM UL"
    fields_desc = [
        ByteEnumField("pdu_type", 0x01, {
            0x01: "A-ASSOCIATE-RQ",
            0x02: "A-ASSOCIATE-AC",
            0x03: "A-ASSOCIATE-RJ",
            0x04: "P-DATA-TF",
            0x05: "A-RELEASE-RQ",
            0x06: "A-RELEASE-RP",
            0x07: "A-ABORT"
        }),
        ByteField("reserved1", 0),  # Reserved, shall be 0x00
        IntField("length", None),    # PDU Length (exclusive of Type, Reserved, Length fields)
    ]

    def post_build(self, p, pay):
        # Calculate PDU length if not provided
        if self.length is None:
            length = len(pay)
            p = p[:2] + struct.pack("!I", length) + p[6:] # Use Network Byte Order (Big Endian) for UL header
        return p + pay


# --- Sub-item Base Classes (for TLV structures within Variable Items) ---
class DULSubItem(Packet):
    """Base class for sub-items often encoded as Type-Length-Value."""
    # Note: This base class doesn't enforce a specific structure,
    # derived classes define their fields.
    def post_build(self, p, pay):
        # Default length calculation for sub-items with a 'length' field
        # Assumes length field is ShortField at offset 2, Big Endian
        if hasattr(self, 'length') and self.length is None and len(p) >= 4:
            length = len(pay) + len(p) - 4 # Length of data part
            p = p[:2] + struct.pack("!H", length) + p[4:]
        return p + pay

class SecureTransportConnectionSubItem(DULSubItem):
    """
    Secure Transport Connection User Data Sub-item (PS3.15 A.5.1)
    Used to request a TLS upgrade on an insecure connection.
    """
    name = "Secure Transport Connection Sub-item"
    fields_desc = [
        ByteField("item_type", 0x56),
        ByteField("reserved", 0),
        ShortField("length", 0), # Length is always 0 as it has no value field
    ]

class UIDField(StrLenField):
    """Custom field for handling DICOM UIDs (ASCII string, odd length padded with NULL)."""
    def i2m(self, pkt, x):
        if x is None:
            return b''
        # Ensure input is string before encoding
        if isinstance(x, bytes):
            x = x.decode('ascii') # Convert to string if needed

        b_val = x.encode('ascii')
        if len(b_val) % 2 != 0:
            b_val += b'\x00'
        return b_val

    def m2i(self, pkt, x):
        if x is None:
            return ""
        # Remove potential trailing null byte for display/use
        if x.endswith(b'\x00'):
            # Check if it's really padding or part of UID (unlikely)
            # An odd length *before* removing null means the null was padding
            if (len(x)-1) % 2 != 0:
                 return x[:-1].decode('ascii')
        return x.decode('ascii')

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        if l is None:
             # Handle cases where length is implicitly defined (e.g. rest of packet)
             # This might need adjustment based on context
             l = len(s)
        # Check if enough bytes are available
        if l > len(s):
            log.warning(f"UIDField: Not enough bytes in buffer. Need {l}, got {len(s)}.")
            # Return remaining buffer and partially decoded value
            return s[len(s):], self.m2i(pkt, s) # Return empty bytes, decode what we have

        return s[l:], self.m2i(pkt, s[:l])


# --- Variable Item Structures (used in A-ASSOCIATE-RQ/AC) ---
# PS3.8 Section 9.3.1 & Table 9-11
class DICOMVariableItem(DULSubItem):
    name = "DICOM Variable Item"
    fields_desc = [
        ByteEnumField("item_type", 0x10, {
            0x10: "Application Context",
            0x20: "Presentation Context RQ",
            0x21: "Presentation Context AC",
            0x30: "Abstract Syntax", # Sub-item only
            0x40: "Transfer Syntax", # Sub-item only
            0x50: "User Information",
            # Added user info sub-item types for clarity
            0x51: "Maximum Length Received",
            0x52: "Implementation Class UID",
            0x53: "Asynchronous Operations Window",
            0x54: "SCU/SCP Role Selection",
            0x55: "Implementation Version Name",
        }),
        ByteField("reserved", 0),  # Reserved, shall be 0x00
        ShortField("length", None), # Length of following data (!H format)
        # 'data' field will hold specific structures based on item_type
        # For simple items like App Context, it's just the UID bytes
        # For complex items like Pres Context, it contains sub-items
        StrLenField("data", b"", length_from=lambda x: x.length),
    ]

# --- Sub-Items for Presentation Context ---
# PS3.8 Section 9.3.2.2 & 9.3.3.2
class AbstractSyntaxSubItem(DULSubItem):
    name = "Abstract Syntax Sub-item"
    fields_desc = [
        ByteField("item_type", 0x30),
        ByteField("reserved", 0),
        ShortField("length", None),
        UIDField("abstract_syntax_uid", "", length_from=lambda x: x.length)
    ]

class TransferSyntaxSubItem(DULSubItem):
    name = "Transfer Syntax Sub-item"
    fields_desc = [
        ByteField("item_type", 0x40),
        ByteField("reserved", 0),
        ShortField("length", None),
        UIDField("transfer_syntax_uid", "", length_from=lambda x: x.length)
    ]

# --- Presentation Context Items ---
# PS3.8 Section 9.3.2.2 (RQ) & 9.3.3.2 (AC)
# NOTE: The PacketListField approach here is complex due to nested TLVs.
# Manual dissection/building (as done in A_ASSOCIATE_RQ/AC) is often more robust.
# These classes are kept mainly for structural representation.

class PresentationContextRQItem(DICOMVariableItem):
    """
    Presentation Context Item for A-ASSOCIATE-RQ. (Representation Only)
    """
    name = "Presentation Context RQ"
    item_type = 0x20 # Override default
    fields_desc = [
        ByteField("item_type", 0x20), # Fixed type
        ByteField("reserved1", 0),
        ShortField("length", None),
        # --- Start of 'data' field content for RQ ---
        ByteField("context_id", 1), # Must be odd, unique per RQ
        ByteField("reserved2", 0),
        ByteField("reserved3", 0),
        ByteField("reserved4", 0),
        # Abstract Syntax and Transfer Syntax items follow here conceptually
        # PacketListField isn't easily usable for direct dissection here
        Raw("sub_item_data")
    ]

class PresentationContextACItem(DICOMVariableItem):
    """
    Presentation Context Item for A-ASSOCIATE-AC. (Representation Only)
    """
    name = "Presentation Context AC"
    item_type = 0x21 # Override default
    fields_desc = [
        ByteField("item_type", 0x21), # Fixed type
        ByteField("reserved1", 0),
        ShortField("length", None),
        # --- Start of 'data' field content for AC ---
        ByteField("context_id", 1), # Matches corresponding RQ context ID
        ByteField("reserved2", 0),
        ByteEnumField("result_reason", 0, {
            0: "Acceptance",
            1: "User Rejection",
            2: "Provider Rejection (no reason)",
            3: "Abstract Syntax Not Supported",
            4: "Transfer Syntaxes Not Supported"
        }),
        ByteField("reserved3", 0),
        # Accepted Transfer Syntax item follows here conceptually
        Raw("sub_item_data")
    ]

# --- User Information Item and Sub-items ---
# PS3.7 Annex D & PS3.8 Section 9.3.2.3
class UserInformationItem(DICOMVariableItem):
    """
    User Information Item (Type 0x50). Contains User Data sub-items. (Representation Only)
    """
    name = "User Information"
    item_type = 0x50 # Override default
    fields_desc = [
        ByteField("item_type", 0x50), # Fixed type
        ByteField("reserved", 0),
        ShortField("length", None),
        # User Data Sub-Items follow here conceptually
        Raw("user_data_subitems")
    ]


class MaxLengthSubItem(DULSubItem):
    """Maximum Length User Data Sub-item (PS3.7 D.1)"""
    name = "Maximum Length Received Sub-item"
    fields_desc = [
        ByteField("item_type", 0x51),
        ByteField("reserved", 0),
        ShortField("length", 4), # Fixed length 4
        IntField("max_length_received", 16384) # Max PDU size we can receive (!I format)
    ]

class ImplementationClassUIDSubItem(DULSubItem):
    """Implementation Class UID User Data Sub-item (PS3.7 D.3)"""
    name = "Implementation Class UID Sub-item"
    fields_desc = [
        ByteField("item_type", 0x52),
        ByteField("reserved", 0),
        ShortField("length", None), # Variable length
        # Scapy's UID (replace if needed for specific implementation)
        UIDField("implementation_class_uid", "1.2.826.0.1.3680043.9.3811." + conf.version.replace(".", ""),
                 length_from=lambda x: x.length)
    ]

class ImplementationVersionNameSubItem(DULSubItem):
    """Implementation Version Name User Data Sub-item (PS3.7 D.3)"""
    name = "Implementation Version Name Sub-item"
    fields_desc = [
        ByteField("item_type", 0x55),
        ByteField("reserved", 0),
        ShortField("length", None), # Variable length
        StrLenField("implementation_version_name", "SCAPY_" + conf.version,
                    length_from=lambda x: x.length) # Max 16 chars
    ]
    def post_build(self, p, pay):
        # Ensure version name does not exceed 16 characters
        # Need to encode before slicing if it's not already bytes
        if isinstance(self.implementation_version_name, str):
            encoded_name = self.implementation_version_name.encode('ascii')
        else:
            encoded_name = self.implementation_version_name

        encoded_name = encoded_name[:16]
        # Decode back to string for the field if needed by StrLenField logic
        self.implementation_version_name = encoded_name.decode('ascii')

        if self.length is None:
            length = len(encoded_name) # Use length of potentially truncated bytes
            p = p[:2] + struct.pack("!H", length) + p[4:]

        # Use encoded_name for payload construction
        return p + encoded_name + pay


class AsyncOperationsWindowSubItem(DULSubItem):
    """Asynchronous Operations Window User Data Sub-item (PS3.7 D.2)"""
    # Note: Negotiation is deprecated, but field might still be sent.
    name = "Asynchronous Operations Window Sub-item"
    fields_desc = [
        ByteField("item_type", 0x53),
        ByteField("reserved", 0),
        ShortField("length", 4), # Fixed length 4
        ShortField("max_operations_invoked", 1), # !H format
        ShortField("max_operations_performed", 1), # !H format
    ]

class SCUSCPRoleSelectionSubItem(DULSubItem):
    """SCU/SCP Role Selection User Data Sub-item (PS3.7 D.4)"""
    name = "SCU/SCP Role Selection Sub-item"
    fields_desc = [
        ByteField("item_type", 0x54),
        ByteField("reserved", 0),
        ShortField("item_length", None), # Total length of this sub-item's data (!H)
        ShortField("uid_length", None), # Length of the SOP Class UID field (!H)
        UIDField("sop_class_uid", "", length_from=lambda x: x.uid_length),
        ByteField("scu_role", 0), # 0 = non-support, 1 = support
        ByteField("scp_role", 0), # 0 = non-support, 1 = support
    ]

    def post_build(self, p, pay):
        # Calculate lengths if not provided
        sop_class_bytes = _uid_to_bytes(self.sop_class_uid) # Ensure UID is bytes with padding
        uid_len = len(sop_class_bytes)
        # Item length = uid_length field(2) + uid data + scu_role(1) + scp_role(1)
        item_len = 2 + uid_len + 1 + 1

        # Pack lengths into the byte string (Big Endian)
        # Start building payload manually
        header = p[:4] # item_type, reserved, placeholder for item_length
        uid_len_bytes = struct.pack("!H", uid_len)
        role_bytes = bytes([self.scu_role, self.scp_role])

        # Reconstruct packet prefix with correct lengths
        p = struct.pack("!BBH", self.item_type, self.reserved, item_len)

        return p + uid_len_bytes + sop_class_bytes + role_bytes + pay


# --- Association Control Service PDUs ---
# PS3.8 Section 9.3
class A_ASSOCIATE_RQ(Packet):
    """A-ASSOCIATE-RQ PDU (PS3.8 Section 9.3.2)"""
    name = "A-ASSOCIATE-RQ"
    fields_desc = [
        ShortField("protocol_version", 0x0001), # Current version is 1 (!H)
        ShortField("reserved1", 0), # Reserved, shall be 0x0000 (!H)
        StrFixedLenField("called_ae_title", b"DefaultCalled ".ljust(16), 16), # Space padded
        StrFixedLenField("calling_ae_title", b"DefaultCalling".ljust(16), 16), # Space padded
        StrFixedLenField("reserved2", b"\x00"*32, 32), # Reserved, shall be 0x00...
        # Variable Items are dissected manually in dissect_payload
    ]
    # Store dissected variable items here
    variable_items = []

        # *** ADDED Correct dissect_payload for A-ASSOCIATE-RQ/AC ***
    def dissect_payload(self, s):
        """Manually dissect variable items from the payload 's'."""
        self.variable_items = []
        # Calculate expected payload length based on DICOM UL header length
        # The fixed header for A-ASSOCIATE-RQ/AC is 68 bytes.
        total_payload_len = getattr(self.underlayer, 'length', len(s))
        fixed_header_len = 68
        if total_payload_len >= fixed_header_len :
             variable_item_len = total_payload_len - fixed_header_len
             payload_bytes = s[:variable_item_len]
             remaining_bytes_after_vars = s[variable_item_len:]
        else:
            # If length is too small or not set, guess based on available bytes 's'
            log.warning(f"A-ASSOCIATE-RQ/AC UL length ({total_payload_len}) < fixed header ({fixed_header_len}), dissecting all available bytes.")
            payload_bytes = s
            remaining_bytes_after_vars = b''

        items = []
        stream = BytesIO(payload_bytes) # Use BytesIO for easier reading

        while True:
            current_pos = stream.tell()
            header = stream.read(4)
            if len(header) < 4:
                # End of stream or truncated item
                if len(header) > 0:
                    log.warning(f"Trailing {len(header)} bytes found after last complete variable item in A-ASSOCIATE-RQ/AC.")
                    # Add leftover bytes to remaining_bytes to avoid losing them
                    remaining_bytes_after_vars = header + remaining_bytes_after_vars
                break # Exit loop

            try:
                item_type, _, item_length = struct.unpack("!BBH", header)
                log.debug(f"Reading Variable Item: Type=0x{item_type:02X}, Length={item_length}")
                item_data = stream.read(item_length)

                if len(item_data) < item_length:
                    log.warning(f"Variable item 0x{item_type:02X} truncated. Expected {item_length}, got {len(item_data)}.")
                    # Put back partially read header and data to remaining_bytes
                    stream.seek(current_pos) # Rewind to start of this item
                    remaining_bytes_after_vars = stream.read() + remaining_bytes_after_vars
                    break # Stop on truncation

                # Attempt to dissect this item using the base class
                # Reconstruct full item bytes for dissection
                full_item_bytes = header + item_data
                item_pkt = DICOMVariableItem(full_item_bytes) # Dissect using base class
                items.append(item_pkt)
                log.debug(f"Dissected Variable Item: {item_pkt.summary()}")

            except struct.error as e:
                 log.error(f"Struct error dissecting variable item header at pos {current_pos}: {e}")
                 stream.seek(current_pos) # Rewind
                 remaining_bytes_after_vars = stream.read() + remaining_bytes_after_vars
                 break
            except Exception as e:
                log.error(f"Failed to dissect variable item starting at pos {current_pos}: {e}", exc_info=True)
                # Append as Raw data to avoid losing bytes, try to continue
                stream.seek(current_pos) # Rewind to start of item
                # Read the problematic item's expected full length if possible
                try:
                    # Reread header to get length again
                    header = stream.read(4)
                    item_type, _, item_length = struct.unpack("!BBH", header)
                    item_bytes_to_skip = stream.read(item_length)
                    log.warning(f"Appending problematic item 0x{item_type:02X} as Raw.")
                    items.append(Raw(header + item_bytes_to_skip))
                except:
                    log.error("Could not recover from variable item dissection error, stopping parse.")
                    remaining_bytes_after_vars = stream.read() + remaining_bytes_after_vars # Add rest as remaining
                    break # Give up

        self.variable_items = items # Assign the manually dissected list
        # Assign any leftover bytes (including those from parsing errors)
        self.payload = Raw(remaining_bytes_after_vars) if remaining_bytes_after_vars else NoPayload()
    # *** END Correct dissect_payload for A-ASSOCIATE-RQ/AC ***


    def build_payload(self):
        """Builds the variable items part of the payload."""
        payload = b"".join(bytes(item) for item in self.variable_items)
        return payload


class A_ASSOCIATE_AC(A_ASSOCIATE_RQ):
    """A-ASSOCIATE-AC PDU (PS3.8 Section 9.3.3)"""
    # Structure identical to RQ up to reserved2 field
    name = "A-ASSOCIATE-AC"
    # Dissection and building logic is inherited from A_ASSOCIATE_RQ


class A_ASSOCIATE_RJ(Packet):
    """A-ASSOCIATE-RJ PDU (PS3.8 Section 9.3.4 & Table 9-16)"""
    name = "A-ASSOCIATE-RJ"
    fields_desc = [
        ByteField("reserved1", 0), # Reserved, shall be 0x00
        ByteEnumField("result", 1, {1: "Rejected (Permanent)", 2: "Rejected (Transient)"}),
        ByteEnumField("source", 1, {
            1: "DICOM UL service-user",
            2: "DICOM UL service-provider (ACSE related)",
            3: "DICOM UL service-provider (Presentation related)"
        }),
        ByteEnumField("reason_diag", 1, {
            # Source 1 (Service User)
            1: "No reason given", 2: "Application context name not supported",
            3: "Calling AE Title not recognized", 7: "Called AE Title not recognized",
            # Source 2 (ACSE)
            # 1: "No reason given", # Duplicate key, maps to source 1
            2: "Protocol version not supported",
            # Source 3 (Presentation)
            0: "Reserved", # Note: Changed key from 1 to avoid conflict with Source 1's 'No reason given'
            # Use unique keys or a more complex mapping if needed
            101: "Temporary congestion", # Assign arbitrary unique keys >= 100 for src 3
            102: "Local limit exceeded",
            # Add other reasons with unique keys as needed
        })
    ]

class A_RELEASE_RQ(Packet):
    """A-RELEASE-RQ PDU (PS3.8 Section 9.3.6)"""
    name = "A-RELEASE-RQ"
    fields_desc = [
        IntField("reserved1", 0), # 4 bytes reserved, shall be 0x00000000 (!I)
    ]

class A_RELEASE_RP(Packet):
    """A-RELEASE-RP PDU (PS3.8 Section 9.3.7)"""
    name = "A-RELEASE-RP"
    fields_desc = [
        IntField("reserved1", 0), # 4 bytes reserved, shall be 0x00000000 (!I)
    ]

class A_ABORT(Packet):
    """A-ABORT PDU (PS3.8 Section 9.3.8 & Table 9-21)"""
    name = "A-ABORT"
    fields_desc = [
        ByteField("reserved1", 0), # Reserved, shall be 0x00
        ByteField("reserved2", 0), # Reserved, shall be 0x00
        ByteEnumField("source", 0, {
            0: "DICOM UL service-user", # Includes application aborts
            2: "DICOM UL service-provider" # Includes transport, TCP errors etc.
            # 1 is reserved
        }),
        ByteEnumField("reason_diag", 0, {
            # Source 0 (User/Application) - Not specified by standard, often 0
            0: "Not specified",
            # Source 2 (Provider) - Need unique keys if combining
            # 0: "Not specified", # Duplicate Key
            201: "Unrecognized PDU", # Assign arbitrary unique keys >= 200 for src 2
            202: "Unexpected PDU",
            204: "Unrecognized PDU parameter",
            205: "Unexpected PDU parameter",
            206: "Invalid PDU parameter value"
            # 203 is reserved
        }) # Reason/Diag - interpretation depends on source
    ]
class PresentationDataValueItem(Packet):
    name = "PresentationDataValueItem"
    fields_desc = [
        FieldLenField("length", None, length_of="value", fmt="!I"),
        # The 'value' field contains the context_id, header, and data
        StrLenField("value", "", length_from=lambda x: x.length)
    ]
    # We define properties to easily access the sub-fields of 'value'
    def __init__(self, *args, **kwargs):
        super(PresentationDataValueItem, self).__init__(*args, **kwargs)
        if 'context_id' in kwargs: self.context_id = kwargs['context_id']
        if 'is_command' in kwargs: self.is_command = kwargs['is_command']
        if 'is_last' in kwargs: self.is_last = kwargs['is_last']
        if 'data' in kwargs: self.data = kwargs['data']

    def _get_msg_hdr(self):
        return struct.unpack("!B", self.value[1:2])[0] if len(self.value) > 1 else 0

    def _set_msg_hdr(self, is_command, is_last):
        hdr = 0
        if is_last: hdr |= 0x02
        if is_command: hdr |= 0x01
        ctx_id_byte = self.value[0:1] if self.value else b'\x01'
        data_bytes = self.value[2:] if len(self.value) > 2 else b''
        self.value = ctx_id_byte + struct.pack("!B", hdr) + data_bytes

    context_id = property(lambda self: self.value[0] if self.value else 0,
                          lambda self, v: setattr(self, 'value', struct.pack("!B", v) + self.value[1:] if self.value else struct.pack("!B", v)))
    is_command = property(lambda self: (self._get_msg_hdr() & 0x01) == 1,
                          lambda self, v: self._set_msg_hdr(v, self.is_last))
    is_last = property(lambda self: (self._get_msg_hdr() >> 1 & 0x01) == 1,
                       lambda self, v: self._set_msg_hdr(self.is_command, v))
    data = property(lambda self: self.value[2:] if len(self.value) > 2 else b'',
                    lambda self, v: setattr(self, 'value', self.value[:2] + v if len(self.value) >= 2 else b'\x01\x00' + v))

# ---- FIXED P_DATA_TF ----
class P_DATA_TF(Packet):
    """
    P-DATA-TF PDU (PS3.8 Section 9.3.5)
    Contains a list of Presentation Data Value Items.
    """
    name = "P-DATA-TF"
    fields_desc = [
        PacketListField("pdv_items", [], PresentationDataValueItem,
                        length_from=lambda pkt: pkt.underlayer.length)
    ]

    
# --- Bind Layers ---
bind_layers(TCP, DICOM, dport=DICOM_PORT)
bind_layers(TCP, DICOM, sport=DICOM_PORT)
# Bind DICOM PDU types to their respective classes
bind_layers(DICOM, A_ASSOCIATE_RQ, pdu_type=0x01)
bind_layers(DICOM, A_ASSOCIATE_AC, pdu_type=0x02)
bind_layers(DICOM, A_ASSOCIATE_RJ, pdu_type=0x03)
bind_layers(DICOM, P_DATA_TF, pdu_type=0x04) # <-- Binding for P-DATA-TF
bind_layers(DICOM, A_RELEASE_RQ, pdu_type=0x05)
bind_layers(DICOM, A_RELEASE_RP, pdu_type=0x06)
bind_layers(DICOM, A_ABORT, pdu_type=0x07)


# --- DICOM Session Helper Class (Optional, but useful for tests) ---
# (You might already have a more complete version of this)
class DICOMSession:
    """A simple helper to manage a DICOM association state."""
    def __init__(self, dst_ip, dst_port, dst_ae, src_ae="SCAPY_SCU", read_timeout=10):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dst_ae = _pad_ae_title(dst_ae)
        self.src_ae = _pad_ae_title(src_ae)
        self.sock = None
        self.stream = None
        self.assoc_established = False
        self.accepted_contexts = {} # Store accepted {context_id: (abs_syntax, trn_syntax)}
        self.peer_max_pdu = 16384 # Default max PDU peer can receive
        self.read_timeout = read_timeout

    def connect(self, retries=3, delay=1):
        """Establishes TCP connection."""
        for attempt in range(1, retries + 1):
            try:
                log.info(f"Attempting TCP connection to {self.dst_ip}:{self.dst_port} (Attempt {attempt}/{retries})")
                self.sock = socket.create_connection((self.dst_ip, self.dst_port), timeout=self.read_timeout)
                # Wrap socket for Scapy StreamSocket usage
                self.stream = StreamSocket(self.sock, basecls=DICOM)
                log.info(f"TCP Connection established to {self.dst_ip}:{self.dst_port}")
                return True
            except (socket.timeout, socket.error, ConnectionRefusedError) as e:
                log.warning(f"TCP Connection attempt {attempt} failed: {e}")
                if attempt == retries:
                    log.error("TCP Connection failed after multiple retries.")
                    return False
                time.sleep(delay)
        return False # Should not be reached

    def associate(self, requested_contexts=None):
        """Sends A-ASSOCIATE-RQ and waits for A-ASSOCIATE-AC using manual PDU build for RQ."""
        if not self.stream:
            if not self.connect():
                return False

        if requested_contexts is None:
            # Default: Request Verification SOP Class with Implicit VR LE
            requested_contexts = {VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}

        # --- Manually Build Variable Items Byte Payload ---
        variable_items_payload = b''
        context_id_map = {}

        # 1. Application Context Item (Type 0x10)
        try:
            app_context_uid_bytes = _uid_to_bytes(APP_CONTEXT_UID)
            app_context_len = len(app_context_uid_bytes)
            variable_items_payload += struct.pack("!BBH", 0x10, 0, app_context_len) + app_context_uid_bytes
            log.debug(f"Packed App Context Item: Type=0x10, Len={app_context_len}")
        except Exception as e:
            log.error(f"Failed to pack Application Context: {e}", exc_info=True); return False

        # 2. Presentation Context Items (Type 0x20)
        context_id_counter = 1
        for abs_syntax, trn_syntaxes in requested_contexts.items():
            try:
                context_id_map[context_id_counter] = abs_syntax
                abs_syntax_uid_bytes = _uid_to_bytes(abs_syntax)
                abs_syntax_subitem_len = len(abs_syntax_uid_bytes)
                abs_syntax_subitem_bytes = struct.pack("!BBH", 0x30, 0, abs_syntax_subitem_len) + abs_syntax_uid_bytes
                trn_syntax_subitems_bytes = b''
                for ts_uid in trn_syntaxes:
                    ts_uid_bytes = _uid_to_bytes(ts_uid)
                    ts_subitem_len = len(ts_uid_bytes)
                    trn_syntax_subitems_bytes += struct.pack("!BBH", 0x40, 0, ts_subitem_len) + ts_uid_bytes
                pres_context_data_header = struct.pack("!BBBB", context_id_counter, 0, 0, 0)
                pres_context_data = pres_context_data_header + abs_syntax_subitem_bytes + trn_syntax_subitems_bytes
                pres_context_len = len(pres_context_data)
                variable_items_payload += struct.pack("!BBH", 0x20, 0, pres_context_len) + pres_context_data
                log.debug(f"Packed Pres Context Item {context_id_counter}: Type=0x20, Len={pres_context_len}")
                context_id_counter += 2
            except Exception as e: log.error(f"Failed to pack Pres Ctx {context_id_counter}: {e}", exc_info=True)

        # 3. User Information Item (Type 0x50)
        try:
            user_info_subitems_payload = b''
            max_len_data = struct.pack("!I", 16384)
            user_info_subitems_payload += struct.pack("!BBH", 0x51, 0, 4) + max_len_data
            impl_class_uid_str = "1.2.826.0.1.3680043.9.3811.1.0" # Fixed UID
            impl_class_uid_bytes = _uid_to_bytes(impl_class_uid_str)
            impl_class_uid_len = len(impl_class_uid_bytes)
            user_info_subitems_payload += struct.pack("!BBH", 0x52, 0, impl_class_uid_len) + impl_class_uid_bytes
            impl_version_name = b"SCAPY_DICOM_TEST"[:16]
            impl_version_name_len = len(impl_version_name)
            user_info_subitems_payload += struct.pack("!BBH", 0x55, 0, impl_version_name_len) + impl_version_name
            user_info_len = len(user_info_subitems_payload)
            variable_items_payload += struct.pack("!BBH", 0x50, 0, user_info_len) + user_info_subitems_payload
            log.debug(f"Packed User Info Item: Type=0x50, Len={user_info_len}")
        except Exception as e: log.error(f"Failed to pack User Info Item: {e}", exc_info=True)

        # --- Manually build fixed part and header ---
        try:
            fixed_part = struct.pack("!HH", 1, 0) + self.dst_ae + self.src_ae + (b'\x00' * 32)
            a_associate_rq_payload = fixed_part + variable_items_payload
            pdu_length = len(a_associate_rq_payload)
            pdu_header = struct.pack("!BBI", 0x01, 0, pdu_length)
        except Exception as e: log.error(f"Failed to pack fixed fields/header: {e}", exc_info=True); return False

        # --- Final raw PDU bytes ---
        raw_pdu_to_send = pdu_header + a_associate_rq_payload
        log.debug(f"Raw A-ASSOCIATE-RQ PDU length: {len(raw_pdu_to_send)}")
        log.debug(f"Raw PDU Hex: {raw_pdu_to_send.hex('.')}")

        log.info(f"Sending A-ASSOCIATE-RQ to {self.dst_ip}:{self.dst_port} (manual build)")

        try:
            # --- Send raw bytes ---
            bytes_sent = self.stream.send(raw_pdu_to_send)
            # Optional: Check if bytes_sent matches len(raw_pdu_to_send)

            # --- Receive and Dissect Response ---
            log.info("Waiting for association response...")
            # *** FIX: Use recv() instead of raw_recv() ***
            # recv() uses the basecls (DICOM) for dissection
            response = self.stream.recv()

            if not response: # recv() returns None on timeout/close
                log.error("No response received for A-ASSOCIATE-RQ (timeout / connection closed).")
                self.close()
                return False

            log.debug("Received Response:")
            log.debug(response.show(dump=True)) # Show dissected response

        except socket.timeout:
            log.error(f"Socket timeout ({self.read_timeout}s) waiting for association response.")
            self.close(); return False
        except KeyboardInterrupt:
            log.warning("Operation interrupted by user."); self.close(); return False
        except Exception as e:
            log.error(f"Error sending/receiving association request: {e}", exc_info=True)
            self.close(); return False

        # --- Process Response (using dissected 'response' object) ---
        if response.haslayer(A_ASSOCIATE_AC):
            ac_layer = response[A_ASSOCIATE_AC]
            log.info("Association Accepted (A-ASSOCIATE-AC received)")
            self.accepted_contexts = {}
            try:
                # Manually parse AC variable items payload from response payload
                ac_payload_bytes = bytes(ac_layer.payload)
                log.debug(f"A-ASSOCIATE-AC raw payload length: {len(ac_payload_bytes)}")
                ac_stream = BytesIO(ac_payload_bytes)
                while True:
                    header = ac_stream.read(4)
                    if len(header) < 4: break
                    item_type, _, item_length = struct.unpack("!BBH", header)
                    item_data = ac_stream.read(item_length)
                    if len(item_data) < item_length: log.warning(f"Truncated item 0x{item_type:02X} in AC"); break

                    log.debug(f"  Parsing AC Item Type: 0x{item_type:02X}, Length: {item_length}")

                    if item_type == 0x10: # App Context
                        uid = item_data.rstrip(b'\x00').decode('ascii', errors='replace')
                        log.debug(f"    App Context UID: {uid}")
                    elif item_type == 0x21: # Pres Context AC
                        if len(item_data) >= 4:
                            ctx_id, _, result, _ = struct.unpack("!BBBB", item_data[:4])
                            log.debug(f"    Pres Ctx AC (ID: {ctx_id}): Result: {result}")
                            if result == 0: # Acceptance
                                log.info(f"      Pres Ctx ID {ctx_id} ACCEPTED")
                                ts_item_bytes = item_data[4:]
                                if len(ts_item_bytes) >= 4:
                                    ts_type, _, ts_len = struct.unpack("!BBH", ts_item_bytes[:4])
                                    if ts_type == 0x40 and len(ts_item_bytes) >= 4 + ts_len:
                                        ts_uid_bytes = ts_item_bytes[4:4 + ts_len]
                                        ts_uid = ts_uid_bytes.rstrip(b'\x00').decode('ascii', errors='replace')
                                        log.info(f"        Tx Syntax: {ts_uid}")
                                        abs_syntax = context_id_map.get(ctx_id, "<Unknown Abstract Syntax>")
                                        self.accepted_contexts[ctx_id] = (abs_syntax, ts_uid)
                                    else: log.warning(f"      Malformed/Truncated TS sub-item in AC Ctx {ctx_id}")
                                else: log.warning(f"      Missing/Truncated TS sub-item in AC Ctx {ctx_id}")
                            else: log.warning(f"      Pres Ctx ID {ctx_id} REJECTED (Reason: {result})")
                        else: log.warning("    Malformed/Truncated Pres Ctx AC item data.")
                    elif item_type == 0x50: # User Info
                        log.debug("    User Info Item:")
                        ui_stream = BytesIO(item_data)
                        while True: # Loop through sub-items
                            sub_header = ui_stream.read(4);
                            if len(sub_header) < 4: break
                            sub_type, _, sub_len = struct.unpack("!BBH", sub_header)
                            sub_data = ui_stream.read(sub_len);
                            if len(sub_data) < sub_len: log.warning(f"      Truncated user info sub 0x{sub_type:02X}"); break
                            if sub_type == 0x51: # Max Length
                                if sub_len == 4: self.peer_max_pdu = struct.unpack("!I", sub_data)[0]; log.info(f"        Peer max PDU: {self.peer_max_pdu}")
                                else: log.warning(f"        Malformed Max Len (len={sub_len})")
                            elif sub_type == 0x52: log.info(f"        Peer Impl Class UID: {sub_data.rstrip(b' ').rstrip(b' ').decode('ascii', errors='replace')}") # Strip trailing space/null
                            elif sub_type == 0x55:
                                try: log.info(f"        Peer Impl Version: {sub_data.decode('ascii')}")
                                except UnicodeDecodeError: log.warning(f"        Non-ASCII Impl Version: {sub_data.hex()}")
            except Exception as e: log.error(f"Error parsing AC variable items: {e}", exc_info=True)

            self.assoc_established = True
            return True # Association successful

        elif response.haslayer(A_ASSOCIATE_RJ):
            rj = response[A_ASSOCIATE_RJ]
            log.error("Association Rejected (A-ASSOCIATE-RJ received)")
            log.error(f"  Result: {rj.result} ({rj.get_field('result').i2s.get(rj.result, '?')})")
            log.error(f"  Source: {rj.source} ({rj.get_field('source').i2s.get(rj.source, '?')})")
            log.error(f"  Reason: {rj.reason_diag} ({rj.get_field('reason_diag').i2s.get(rj.reason_diag, '?')})")
            self.close(); return False
        else:
            log.error(f"Unexpected response PDU type received: {response.summary()}")
            if response.haslayer(A_ABORT):
                abort_layer = response[A_ABORT]
                log.error(f"  Received A-ABORT: Source={abort_layer.source}, Reason={abort_layer.reason_diag}")
            self.close(); return False
                    
    def send_p_data(self, pdv_list):
        """Sends one or more PDV items within a P-DATA-TF PDU by manually building the payload."""
        if not self.assoc_established or not self.stream:
            log.error("Cannot send P-DATA: Association not established.")
            return False

        # --- Manual Payload Construction ---
        # Create a temporary P_DATA_TF layer instance just to use its build_payload method
        p_data_tf_layer_builder = P_DATA_TF()
        p_data_tf_layer_builder.parsed_pdv_items = pdv_list

        # Manually build the payload bytes for this layer
        pdata_payload_bytes = p_data_tf_layer_builder.build_payload()
        log.debug(f"Manually built P-DATA payload length: {len(pdata_payload_bytes)}")
        # --- End Manual Payload Construction ---

        # Create the full PDU: DICOM UL header wrapping the manually built payload as Raw data.
        # The DICOM UL layer will calculate its 'length' field based on this Raw payload.
        full_pdu = DICOM() / Raw(load=pdata_payload_bytes)
        # Explicitly set the PDU type for the DICOM UL header
        full_pdu.pdu_type = 0x04 # P-DATA-TF

        log.info(f"Sending P-DATA-TF ({len(pdv_list)} PDV(s))")

        try:
            # Send the manually constructed PDU
            sent_len = self.stream.send(full_pdu)

            # Optional: Log the raw bytes sent for debugging
            # We need to re-build the packet to get the final bytes including the calculated length
            final_bytes = bytes(full_pdu)
            log.debug(f"Final Bytes Sent ({len(final_bytes)} bytes):")
            log.debug(final_bytes.hex('.')) # Use hex with separator for readability
            return sent_len > 0
        except Exception as e:
            log.error(f"Error sending P-DATA-TF: {e}", exc_info=True)
            self.assoc_established = False # Assume connection broken
            self.close()
            return False

    def find_accepted_context_id(self, sop_class_uid):
        """Finds the first accepted presentation context ID for a given abstract syntax UID."""
        for ctx_id, (abs_syntax, _trn_syntax) in self.accepted_contexts.items():
            if abs_syntax == sop_class_uid:
                log.debug(f"Found accepted context ID {ctx_id} for SOP Class {sop_class_uid}")
                return ctx_id
        log.warning(f"No accepted presentation context found for SOP Class {sop_class_uid}")
        return None

    def c_echo(self, msg_id=None):
        """
        Performs a C-ECHO verification.

        Args:
            msg_id (int, optional): The Message ID to use. If None, a default one is generated.

        Returns:
            int or None: The DICOM status code (e.g., 0x0000 for success) if a valid
                         C-ECHO response is received, otherwise None indicating an error
                         (e.g., association error, timeout, unexpected PDU, parsing failure).
        """
        if not self.assoc_established:
            log.error("Cannot perform C-ECHO: Association not established.")
            return None

        # 1. Find accepted context ID for Verification SOP Class
        echo_ctx_id = self.find_accepted_context_id(VERIFICATION_SOP_CLASS_UID)
        if echo_ctx_id is None:
            log.error("Cannot perform C-ECHO: No accepted context for Verification SOP Class.")
            return None # Indicate failure: context not accepted

        # 2. Prepare C-ECHO-RQ DIMSE Message
        if msg_id is None:
            msg_id = int(time.time()) % 10000
        dimse_command_bytes = build_c_echo_rq_dimse(msg_id)

        # 3. Create the PresentationDataValueItem object for C-ECHO-RQ
        pdv_rq = PresentationDataValueItem()
        pdv_rq.context_id = echo_ctx_id
        pdv_rq.data = dimse_command_bytes
        pdv_rq.is_command = True
        pdv_rq.is_last = True

        # 4. Send the PDV Item via P-DATA-TF
        log.info(f"Sending C-ECHO-RQ (Message ID: {msg_id}) via DICOMSession.c_echo...")
        if not self.send_p_data(pdv_list=[pdv_rq]):
            log.error("C-ECHO failed: Could not send P-DATA.")
            # send_p_data should handle closing on error
            return None # Indicate failure: send error

        # 5. Wait for and receive the response PDU
        log.info("Waiting for C-ECHO response...")
        response_pdata = None
        try:
            # Use the stream directly to receive the next PDU
            response_pdata = self.stream.recv()
        except socket.timeout:
            log.error(f"Socket timeout ({self.read_timeout}s) waiting for C-ECHO response.")
            self.abort() # Abort on timeout
            return None # Indicate failure: timeout
        except Exception as e:
            log.error(f"Error receiving C-ECHO response: {e}", exc_info=True)
            self.abort() # Abort on other errors
            return None # Indicate failure: socket/other error

        if not response_pdata:
            log.error("No C-ECHO response PDU received (connection closed?).")
            self.close() # Already closed or failed
            return None # Indicate failure: no response/closed

        # 6. Process the response
        log.debug("Processing C-ECHO response PDU:")
        log.debug(f"{response_pdata.show(dump=True)}")

        # Check PDU type
        if response_pdata.pdu_type == 0x04: # P-DATA-TF
            log.debug("Response is P-DATA-TF (Type 0x04). Checking parsed items...")
            # Check if dissector stored the instance and items
            if hasattr(response_pdata, 'pdata_instance') and \
               hasattr(response_pdata.pdata_instance, 'parsed_pdv_items') and \
               response_pdata.pdata_instance.parsed_pdv_items:

                parsed_items = response_pdata.pdata_instance.parsed_pdv_items
                log.debug(f"Found {len(parsed_items)} PDV items in response.")
                # Find the relevant PDV (usually the first/only one for C-ECHO RSP)
                for pdv in parsed_items:
                    if pdv.context_id == echo_ctx_id and pdv.is_command and pdv.is_last:
                        log.debug(f"Found relevant response PDV (CtxID={echo_ctx_id}). Parsing status...")
                        status = parse_dimse_status(pdv.data)
                        if status is not None:
                            log.info(f"C-ECHO completed with DIMSE Status: 0x{status:04X}")
                            return status # Return the parsed status code
                        else:
                            log.error("Failed to parse DIMSE status from C-ECHO response PDV.")
                            return None # Indicate failure: status parsing error
                # If loop finishes without finding the right PDV
                log.error("Did not find a suitable response PDV in the received P-DATA-TF.")
                return None # Indicate failure: PDV not found/matched
            else:
                log.error("P-DATA-TF received, but failed to find populated parsed_pdv_items via pdata_instance.")
                return None # Indicate failure: dissection access error

        elif response_pdata.haslayer(A_ABORT):
             log.error(f"Received A-ABORT instead of C-ECHO response:")
             # Logging handled within abort handler if needed, or add here
             self.assoc_established = False # Ensure state is updated
             self.close()
             return None # Indicate failure: aborted
        else:
            log.error(f"Received unexpected PDU type {response_pdata.pdu_type} instead of C-ECHO response.")
            response_pdata.show()
            # Consider aborting if the state is unexpected
            self.abort()
            return None # Indicate failure: unexpected PDU

    def _get_next_message_id(self):
        if not hasattr(self, '_current_message_id_counter'):
            # Initialize with a value that's somewhat unique per session start
            self._current_message_id_counter = int(time.time()) % 50000 
        self._current_message_id_counter += 1
        if self._current_message_id_counter > 0xFFFF: # UShort max
            self._current_message_id_counter = 1
        return self._current_message_id_counter

    def c_store(self, dataset_bytes, sop_class_uid, sop_instance_uid,
                original_dataset_transfer_syntax_uid):
        """
        Performs a C-STORE operation to send a dataset.
        """
        if not self.assoc_established:
            log.error("C-STORE: Association not established.")
            return None

        # 1. Find an accepted presentation context
        target_context_id = None
        for ctx_id, (abs_syntax, accepted_ts) in self.accepted_contexts.items():
            if abs_syntax == sop_class_uid:
                # Prioritize the original transfer syntax if available and accepted
                if accepted_ts == original_dataset_transfer_syntax_uid:
                    target_context_id = ctx_id
                    break
                # Otherwise, find any accepted context for this abstract syntax
                target_context_id = ctx_id

        if target_context_id is None:
            log.error(f"C-STORE: No accepted presentation context for SOP Class {sop_class_uid}.")
            return None

        # 2. Build C-STORE-RQ DIMSE command
        message_id = self._get_next_message_id()
        c_store_rq_bytes = build_c_store_rq_dimse(
            sop_class_uid=sop_class_uid,
            sop_instance_uid=sop_instance_uid,
            message_id=message_id
        )

        # 3. Prepare list of PDVs: command first, then data
        all_pdvs_for_c_store = []

        # --- FIX: Create the command PDV using the correct two-step pattern ---
        # a. Create the object
        cmd_pdv = PresentationDataValueItem()
        # b. Set the fields
        cmd_pdv.context_id = target_context_id
        cmd_pdv.is_command = True
        cmd_pdv.is_last = True
        cmd_pdv.data = c_store_rq_bytes
        all_pdvs_for_c_store.append(cmd_pdv)

        if dataset_bytes:
            # --- FIX: Create the data PDV using the correct two-step pattern ---
            # a. Create the object
            data_pdv = PresentationDataValueItem()
            # b. Set the fields
            data_pdv.context_id = target_context_id
            data_pdv.is_command = False
            data_pdv.is_last = True
            data_pdv.data = dataset_bytes
            all_pdvs_for_c_store.append(data_pdv)

        # 4. Send PDVs
        log.info(f"C-STORE: Sending {len(all_pdvs_for_c_store)} PDVs.")
        if not self.send_p_data(pdv_list=all_pdvs_for_c_store):
            log.error("C-STORE: Failed to send P-DATA for C-STORE.")
            return None

        # 5. Receive and process C-STORE-RSP
        log.info("C-STORE: Waiting for C-STORE-RSP...")
        try:
            response_pdu = self.stream.recv()
            if response_pdu and response_pdu.haslayer(P_DATA_TF):
                # A real implementation would parse the status from the response
                # For this example, we assume success if we get a P-DATA-TF back
                return 0x0000
            else:
                log.error(f"C-STORE: Received unexpected response: {response_pdu.summary() if response_pdu else 'None'}")
                return None
        except Exception as e:
            log.error(f"C-STORE: Error receiving C-STORE-RSP: {e}")
            self.abort()
            return None
        
    def release(self):
        """Sends A-RELEASE-RQ and waits for A-RELEASE-RP."""
        if not self.assoc_established or not self.stream:
            log.info("Cannot release: Association not established or already closed.")
            return True # Consider it released if not established

        log.info("Sending A-RELEASE-RQ...")
        release_rq = DICOM()/A_RELEASE_RQ()

        try:
            # Send the release request
            bytes_sent = self.stream.send(release_rq)
            if bytes_sent <= 0:
                 log.error("Failed to send A-RELEASE-RQ (socket reported 0 bytes sent).")
                 self.assoc_established = False
                 self.close()
                 return False

            # Wait for the response using recv()
            log.info("Waiting for A-RELEASE-RP response...")
            response = self.stream.recv() # Use recv() to get the next PDU

        except socket.timeout:
            log.warning(f"Socket timeout ({self.read_timeout}s) waiting for A-RELEASE-RP. Closing connection.")
            self.assoc_established = False
            self.close()
            return False
        except Exception as e:
            log.error(f"Error sending/receiving A-RELEASE-RQ: {e}", exc_info=True)
            self.assoc_established = False
            self.close()
            return False


        if not response:
            log.warning("No response received for A-RELEASE-RQ (recv returned None - likely timeout/closed). Closing connection.")
            self.assoc_established = False
            self.close()
            return False

        # Check the received PDU
        if response.haslayer(A_RELEASE_RP):
            log.info("Association released successfully (A-RELEASE-RP received).")
            self.assoc_established = False
            self.close() # Close connection after successful release
            return True
        elif response.haslayer(A_ABORT):
            log.warning(f"Received A-ABORT instead of A-RELEASE-RP:")
            response.show()
            abort_layer = response[A_ABORT]
            log.warning(f"  Abort Source: {abort_layer.get_field('source').i2s.get(abort_layer.source, '?')} ({abort_layer.source})")
            log.warning(f"  Abort Reason: {abort_layer.get_field('reason_diag').i2s.get(abort_layer.reason_diag, '?')} ({abort_layer.reason_diag})")
            self.assoc_established = False
            self.close() # Close connection after abort
            return False # Release failed
        else:
            log.warning(f"Unexpected response received for A-RELEASE-RQ: {response.summary()}")
            response.show()
            # Should we abort here? Or just close? Closing is safer.
            self.assoc_established = False
            self.close()
            return False # Release failed
        
    def abort(self):
        """Sends A-ABORT PDU."""
        if not self.stream:
            log.info("Cannot abort: Connection already closed.")
            return

        log.warning("Sending A-ABORT...")
        # Source 0 = User, Reason 0 = Not specified (typical for graceful user abort)
        abort_pdu = DICOM()/A_ABORT(source=0, reason_diag=0)
        try:
            self.stream.send(abort_pdu)
        except Exception as e:
            log.error(f"Failed to send A-ABORT: {e}")
        finally:
            self.assoc_established = False
            self.close() # Close connection after sending abort

    def close(self):
        """Closes the socket connection."""
        if self.stream:
            log.info("Closing DICOM TCP connection.")
            try:
                self.stream.close() # Closes underlying socket
            except Exception as e:
                log.warning(f"Error closing stream socket: {e}")
        self.sock = None
        self.stream = None
        self.assoc_established = False


# --- Example Usage (if run as main script) ---
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

    # --- Test P-DATA-TF Dissection ---
    log.info("--- Testing P-DATA-TF Dissection ---")
    # Example bytes from the CI log (C-ECHO-RSP inside P-DATA-TF)
    # 04.00.00.00.00.54 ............ DICOM UL Header (Type=04, Len=84)
    # 00.00.00.50 ................. PDV Item 1: Value Length=80
    # 01 .......................... Context ID=1
    # 03 .......................... Msg Hdr (Command=1, Last=1)
    # 00.00.00.00.04.00.00.00.42.00.00.00... DIMSE C-ECHO-RSP bytes (Value) ...09.00.02.00.00.00
    pdata_raw_bytes_from_log = bytes.fromhex(
        "0400000000000054"  # DICOM UL Header (Type 04, Len 84)
        "00000050"          # PDV Item 1: Value Length 80
        "01"                # Context ID 1
        "03"                # Msg Hdr (Cmd=1, Last=1)
        # C-ECHO-RSP DIMSE Command starts here (Value Part of PDV)
        "000000000400000042000000" # Group Length Tag, VR=UL, Len=4, Value=66 (0x42)
        "0000000212000000312e322e3834302e31303030382e312e3100" # Affected SOP Class UID
        "00000100020000003080"    # Command Field (C-ECHO-RSP = 0x8030)
        "0000011002000000ca1c"    # Message ID Responding To (matches RQ ID 7370=0x1CCA)
        "00000800020000000101"    # Command Data Set Type (No dataset)
        "00000900020000000000"    # Status (Success = 0x0000)
    )

    # Create a DICOM PDU from these bytes
    dicom_pdu = DICOM(pdata_raw_bytes_from_log)
    log.info("Input PDU Summary:")
    dicom_pdu.show()

    if dicom_pdu.haslayer(P_DATA_TF):
        log.info("PDU correctly dissected as P-DATA-TF.")
        pdata_layer = dicom_pdu[P_DATA_TF]
        log.info(f"Number of parsed PDV items: {len(pdata_layer.parsed_pdv_items)}")
        if pdata_layer.parsed_pdv_items:
            pdv1 = pdata_layer.parsed_pdv_items[0]
            log.info(f"  PDV Item 1 Summary: {pdv1.summary()}")
            log.info(f"  PDV Item 1 Data (Hex): {pdv1.data.hex('.')}")

            # Try parsing DIMSE status from the PDV data
            status = parse_dimse_status(pdv1.data)
            if status is not None:
                log.info(f"  Parsed DIMSE Status from PDV data: 0x{status:04X}")
            else:
                log.error("  Failed to parse DIMSE status from PDV data.")
        else:
            log.error("  No PDV items were parsed!")

        if isinstance(pdata_layer.payload, Raw):
             log.info(f"  Remaining Raw payload length: {len(pdata_layer.payload.load)}")
             log.info(f"  Remaining Raw payload hex: {pdata_layer.payload.load.hex('.')}")
        elif isinstance(pdata_layer.payload, NoPayload):
             log.info("  No remaining payload after P-DATA-TF.")
        else:
             log.warning(f"  Unexpected payload type after P-DATA-TF: {type(pdata_layer.payload)}")

    else:
        log.error("Failed to dissect input bytes as P-DATA-TF.")
        log.info(f"Guessed layer: {dicom_pdu.summary()}")
        if isinstance(dicom_pdu.payload, Raw):
             log.info(f"  Raw payload: {dicom_pdu.payload.load.hex('.')}")

    log.info("--- Testing C-ECHO Session (requires SCP at localhost:11112) ---")
    # Example C-ECHO against a local SCP (e.g., dcmtk storescp)
    # Start one first: storescp -aet SCAPY_TEST_SCP -od . --port 11112 -v -x=
    try:
        session = DICOMSession(
            dst_ip="127.0.0.1",
            dst_port=11112,
            dst_ae="SCAPY_TEST_SCP", # AET of the running storescp
            src_ae="SCAPY_ECHOTEST"
        )

        if session.associate():
            log.info("Association successful!")

            # Build C-ECHO-RQ DIMSE
            message_id = int(time.time()) % 10000
            dimse_rq_bytes = build_c_echo_rq_dimse(message_id=message_id)

            # Find accepted context for Verification
            echo_ctx_id = None
            for ctx_id, (abs_syntax, trn_syntax) in session.accepted_contexts.items():
                 # We need the abstract syntax from the AC parsing to be correct here
                 # Let's assume it was stored correctly (needs fix in associate method)
                 # if abs_syntax == VERIFICATION_SOP_CLASS_UID:
                 # For now, just find *any* accepted context ID from the AC phase
                 # (This relies on the manual parsing in associate() having worked)
                 if session.accepted_contexts: # Check if parsing yielded any contexts
                     echo_ctx_id = list(session.accepted_contexts.keys())[0] # Use the first one found
                     log.info(f"Using first accepted Presentation Context ID: {echo_ctx_id}")
                     break

            if echo_ctx_id is None:
                 log.error("No accepted presentation context found for C-ECHO.")
            else:
                # Create PDV item
                pdv_rq = PresentationDataValueItem()
                pdv_rq.context_id = echo_ctx_id
                pdv_rq.is_command = True
                pdv_rq.is_last = True
                pdv_rq.data = dimse_rq_bytes

                # Send P-DATA
                if session.send_p_data([pdv_rq]):
                    log.info("C-ECHO-RQ sent via P-DATA-TF. Waiting for response...")
                    # Receive response (expecting P-DATA-TF containing C-ECHO-RSP)
                    response_pdata = session.stream.recv() # Use recv to get next PDU

                    if response_pdata and response_pdata.haslayer(P_DATA_TF):
                        log.info("Received P-DATA-TF response.")
                        rsp_pdata_layer = response_pdata[P_DATA_TF]
                        if rsp_pdata_layer.parsed_pdv_items:
                            pdv_rsp = rsp_pdata_layer.parsed_pdv_items[0]
                            log.info(f"  Response PDV: {pdv_rsp.summary()}")
                            status = parse_dimse_status(pdv_rsp.data)
                            if status == 0x0000:
                                log.info(f"  C-ECHO SUCCESS (Status=0x{status:04X})")
                            elif status is not None:
                                log.error(f"  C-ECHO FAILED (Status=0x{status:04X})")
                            else:
                                log.error("  Failed to parse DIMSE status from C-ECHO response PDV.")
                        else:
                             log.error("  P-DATA-TF response did not contain any parsed PDV items.")
                    elif response_pdata:
                        log.error(f"Received unexpected response PDU type: {response_pdata.summary()}")
                    else:
                        log.error("No response received after sending C-ECHO-RQ.")

            # Release association
            session.release()
        else:
            log.error("Association failed.")

    except Exception as e:
        log.exception(f"Error during C-ECHO test: {e}")
