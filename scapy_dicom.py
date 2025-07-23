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


# --- Scapy Layer Definitions ---
class DICOM(Packet):
    name = "DICOM UL"
    fields_desc = [
        ByteEnumField("pdu_type", 0x01, {
            0x01: "A-ASSOCIATE-RQ", 0x02: "A-ASSOCIATE-AC", 0x03: "A-ASSOCIATE-RJ",
            0x04: "P-DATA-TF", 0x05: "A-RELEASE-RQ", 0x06: "A-RELEASE-RP", 0x07: "A-ABORT"
        }),
        ByteField("reserved1", 0),
        IntField("length", None),
    ]
    def post_build(self, p, pay):
        if self.length is None:
            length = len(pay)
            p = p[:2] + struct.pack("!I", length) + p[6:]
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
    
class DICOMVariableItem(Packet):
    name = "DICOM Variable Item"
    fields_desc = [
        ByteField("item_type", 0x10), ByteField("reserved", 0),
        ShortField("length", None),
        StrLenField("data", b"", length_from=lambda x: x.length),
    ]
    def post_build(self, p, pay):
        if self.length is None:
            length = len(self.data) if self.data else 0
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
        ShortField("protocol_version", 1), ShortField("reserved1", 0),
        StrFixedLenField("called_ae_title", b"DefaultCalled".ljust(16), 16),
        StrFixedLenField("calling_ae_title", b"DefaultCalling".ljust(16), 16),
        StrFixedLenField("reserved2", b"\x00"*32, 32),
        PacketListField("variable_items", [], DICOMVariableItem, length_from=lambda x: x.underlayer.length - 68),
    ]

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
class A_ASSOCIATE_RQ(Packet):
    name = "A-ASSOCIATE-RQ"
    fields_desc = [
        ShortField("protocol_version", 1), ShortField("reserved1", 0),
        StrFixedLenField("called_ae_title", b"", 16),
        StrFixedLenField("calling_ae_title", b"", 16),
        StrFixedLenField("reserved2", b"\x00"*32, 32),
    ]
    # This list will be populated by the custom dissector
    variable_items = []

    def do_dissect_payload(self, s):
        self.variable_items = []
        stream = BytesIO(s)
        while stream.tell() < len(s):
            try:
                header = stream.read(4)
                if len(header) < 4: break
                item_type, _, item_length = struct.unpack("!BBH", header)
                item_data = stream.read(item_length)
                if len(item_data) < item_length: break
                self.variable_items.append(DICOMVariableItem(header + item_data))
            except Exception:
                break
        remaining_bytes = stream.read()
        if remaining_bytes:
            self.payload = Raw(remaining_bytes)

    def do_build_payload(self):
        return b"".join(bytes(item) for item in self.variable_items)
    
class A_RELEASE_RQ(Packet): name = "A-RELEASE-RQ"; fields_desc = [IntField("reserved1", 0)]
class A_RELEASE_RP(Packet): name = "A-RELEASE-RP"; fields_desc = [IntField("reserved1", 0)]
class A_ABORT(Packet): name = "A-ABORT"; fields_desc = [ByteField("reserved1", 0), ByteField("reserved2", 0), ByteField("source", 0), ByteField("reason_diag", 0)]

class PresentationDataValueItem(Packet):
    name = "PresentationDataValueItem"
    fields_desc = [
        FieldLenField("length", None, length_of="value", fmt="!I"),
        # The 'value' contains the context_id, header, and data.
        # We define them as separate fields for easy access and construction.
        ByteField("context_id", 1),
        ByteField("message_control_header", 0x03),
        StrLenField("data", "", length_from=lambda pkt: pkt.length - 2)
    ]
    # Define properties to easily get/set the control header bits from keywords.
    def __init__(self, *args, **kwargs):
        super(PresentationDataValueItem, self).__init__(*args, **kwargs)
        if 'is_command' in kwargs: self.is_command = kwargs['is_command']
        if 'is_last' in kwargs: self.is_last = kwargs['is_last']

    is_command = property(
        lambda self: (self.message_control_header & 0x01) == 1,
        lambda self, v: setattr(self, 'message_control_header', (self.message_control_header & ~0x01) | (0x01 if v else 0x00))
    )
    is_last = property(
        lambda self: (self.message_control_header >> 1 & 0x01) == 1,
        lambda self, v: setattr(self, 'message_control_header', (self.message_control_header & ~0x02) | (0x02 if v else 0x00))
    )

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
    # __init__ and connect are unchanged
    def __init__(self, dst_ip, dst_port, dst_ae, src_ae="SCAPY_SCU", read_timeout=10):
        self.dst_ip, self.dst_port = dst_ip, dst_port
        self.dst_ae, self.src_ae = _pad_ae_title(dst_ae), _pad_ae_title(src_ae)
        self.sock, self.stream, self.assoc_established = None, None, False
        self.accepted_contexts, self.peer_max_pdu = {}, 16384
        self.read_timeout = read_timeout
        self._current_message_id_counter = int(time.time()) % 50000
    def connect(self, retries=3, delay=1):
        for attempt in range(1, retries + 1):
            try:
                self.sock = socket.create_connection((self.dst_ip, self.dst_port), timeout=self.read_timeout)
                self.stream = StreamSocket(self.sock, basecls=DICOM)
                return True
            except Exception:
                if attempt == retries: return False
                time.sleep(delay)
        return False
    # Simplified associate and c_echo to use the improved Scapy layers
    def associate(self, requested_contexts=None):
        if not self.stream and not self.connect(): return False
        if requested_contexts is None:
            requested_contexts = {VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}

        variable_items = [DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID))]
        ctx_id = 1
        for abs_syntax, trn_syntaxes in requested_contexts.items():
            sub_items_data = bytes(DICOMVariableItem(item_type=0x30, data=_uid_to_bytes(abs_syntax)))
            for ts in trn_syntaxes:
                sub_items_data += bytes(DICOMVariableItem(item_type=0x40, data=_uid_to_bytes(ts)))
            variable_items.append(DICOMVariableItem(item_type=0x20, data=struct.pack("!BBBB", ctx_id, 0, 0, 0) + sub_items_data))
            ctx_id += 2
        variable_items.append(DICOMVariableItem(item_type=0x50, data=bytes(DICOMVariableItem(item_type=0x51, data=struct.pack("!I", 16384)))))
        
        # Build packet using Scapy layers directly
        assoc_rq_payload = A_ASSOCIATE_RQ(called_ae_title=self.dst_ae, calling_ae_title=self.src_ae)
        assoc_rq_payload.variable_items = variable_items
        assoc_rq = DICOM() / assoc_rq_payload
        
        log.info(f"Sending A-ASSOCIATE-RQ to {self.dst_ip}:{self.dst_port}")
        response = self.stream.sr1(assoc_rq, timeout=self.read_timeout, verbose=0)

        if response and response.haslayer(A_ASSOCIATE_AC):
            log.info("Association Accepted (A-ASSOCIATE-AC received)")
            self.assoc_established = True
            for item in response[A_ASSOCIATE_AC].variable_items:
                if item.item_type == 0x21 and item.data[2] == 0:
                    ctx_id = item.data[0]
                    abs_syntax_key_list = list(requested_contexts.keys())
                    key_index = (ctx_id -1) // 2
                    if key_index < len(abs_syntax_key_list):
                        abs_syntax = abs_syntax_key_list[key_index]
                        ts_item_data = item.data[4:]
                        ts_uid = DICOMVariableItem(ts_item_data).data.rstrip(b'\x00').decode()
                        self.accepted_contexts[ctx_id] = (abs_syntax, ts_uid)
            return True
        log.error(f"Association failed. Response: {response.summary() if response else 'None'}")
        return False

    def _get_next_message_id(self):
        self._current_message_id_counter += 1
        return self._current_message_id_counter & 0xFFFF
    def _find_accepted_context_id(self, sop_class_uid):
        for ctx_id, (abs_syntax, _) in self.accepted_contexts.items():
            if abs_syntax == sop_class_uid: return ctx_id
        return None
        
    def c_echo(self):
        if not self.assoc_established: return None
        echo_ctx_id = self._find_accepted_context_id(VERIFICATION_SOP_CLASS_UID)
        if echo_ctx_id is None: return None
        
        msg_id = self._get_next_message_id()
        dimse_rq = build_c_echo_rq_dimse(msg_id)
        pdv_rq = PresentationDataValueItem(context_id=echo_ctx_id, data=dimse_rq, is_command=True, is_last=True)
        pdata_rq = DICOM() / P_DATA_TF(pdv_items=[pdv_rq])
        
        log.info(f"Sending C-ECHO-RQ (Message ID: {msg_id})")
        response = self.stream.sr1(pdata_rq, timeout=self.read_timeout, verbose=0)
        
        if response and response.haslayer(P_DATA_TF) and response[P_DATA_TF].pdv_items:
            pdv_rsp = response[P_DATA_TF].pdv_items[0]
            status = parse_dimse_status(pdv_rsp.data)
            log.info(f"C-ECHO completed with DIMSE Status: {status}")
            return status
        return None
    
    def release(self):
        if not self.assoc_established: return True
        log.info("Sending A-RELEASE-RQ...")
        response = self.stream.sr1(DICOM()/A_RELEASE_RQ(), timeout=self.read_timeout, verbose=0)
        self.close()
        if response and response.haslayer(A_RELEASE_RP):
            log.info("Association released successfully.")
            return True
        log.warning("Did not receive A-RELEASE-RP.")
        return False

    def close(self):
        if self.stream: self.stream.close()
        self.sock, self.stream, self.assoc_established = None, None, False
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
