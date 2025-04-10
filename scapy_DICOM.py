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
import struct

from scapy.all import Packet, bind_layers, PacketListField, conf
from scapy.fields import (
    ByteEnumField, ByteField, ShortField, IntField, FieldLenField,
    StrFixedLenField, StrLenField, ShortEnumField, Field, BitField, 
    StrField
)
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket
from scapy.packet import NoPayload, Raw

log = logging.getLogger("scapy.contrib.dicom")

# --- Constants ---
# Default DICOM Port
DICOM_PORT = 104
# Well-known Application Context UID
APP_CONTEXT_UID = "1.2.840.10008.3.1.1.1"
# Default Transfer Syntax UID (Implicit VR Little Endian)
DEFAULT_TRANSFER_SYNTAX_UID = "1.2.840.10008.1.2"
# Example SOP Class UID (Verification)
VERIFICATION_SOP_CLASS_UID = "1.2.840.10008.1.1"

# --- Helper Functions ---
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
# Moved from test_integration.py
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

            # Check if element exceeds group boundary or available data
            if next_element_offset > len(dimse_bytes):
                 log.warning(f"parse_dimse_status: Element ({tag_group:04X},{tag_elem:04X}) length ({value_len}) exceeds available data.")
                 break
            # No need to check group_end_offset strictly here, as elements *should* fit,
            # but it's good practice if parsing more complex structures.

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
        IntField("length", None),   # PDU Length (exclusive of Type, Reserved, Length fields)
    ]

    def post_build(self, p, pay):
        # Calculate PDU length if not provided
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
        # Assumes length field is ShortField at offset 2
        if hasattr(self, 'length') and self.length is None and len(p) >= 4:
            length = len(pay) + len(p) - 4 # Length of data part
            p = p[:2] + struct.pack("!H", length) + p[4:]
        return p + pay

class UIDField(StrLenField):
    """Custom field for handling DICOM UIDs (ASCII string, odd length padded with NULL)."""
    def i2m(self, pkt, x):
        if x is None:
            return b''
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
            if (len(x)-1) % 2 != 0: # Odd length *before* removing null
                 return x[:-1].decode('ascii')
        return x.decode('ascii')

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        if l is None:
             # Handle cases where length is implicitly defined (e.g. rest of packet)
             # This might need adjustment based on context
             l = len(s)
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
            0x50: "User Information"
            # Other types exist (e.g., 0x51-0x55 as sub-items within User Info)
        }),
        ByteField("reserved", 0),  # Reserved, shall be 0x00
        ShortField("length", None), # Length of following data
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
class PresentationContextRQItem(DICOMVariableItem):
    """
    Presentation Context Item for A-ASSOCIATE-RQ.
    Note: The abstract/transfer syntax items are typically packed into the 'data' field.
    This class helps structure the fixed part of the data.
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
        # Abstract Syntax and Transfer Syntax items follow here, concatenated as bytes
        PacketListField("sub_items", [], DULSubItem, length_from=lambda x: x.length - 4) # Length calculation needs care
    ]
    # Override post_build needed if using PacketListField directly
    def post_build(self, p, pay):
        # Manually calculate length for the variable item header
        sub_items_pay = b"".join(bytes(item) for item in self.sub_items)
        data_len = 4 + len(sub_items_pay)
        p = p[:2] + struct.pack("!H", data_len) + p[4:8] # Item Len + Context ID/Reserved
        return p[:8] + sub_items_pay + pay # Fixed fields + subitems + potential outer payload

class PresentationContextACItem(DICOMVariableItem):
    """
    Presentation Context Item for A-ASSOCIATE-AC.
    Note: The transfer syntax item is typically packed into the 'data' field.
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
        # Accepted Transfer Syntax item follows here as bytes
        PacketListField("sub_items", [], TransferSyntaxSubItem, length_from=lambda x: x.length - 4) # Usually just one TransferSyntaxSubItem
    ]
    # Override post_build needed if using PacketListField directly
    def post_build(self, p, pay):
         # Manually calculate length for the variable item header
        sub_items_pay = b"".join(bytes(item) for item in self.sub_items)
        data_len = 4 + len(sub_items_pay)
        p = p[:2] + struct.pack("!H", data_len) + p[4:8] # Item Len + Context ID/Reserved/Result
        return p[:8] + sub_items_pay + pay # Fixed fields + subitems + potential outer payload

# --- User Information Item and Sub-items ---
# PS3.7 Annex D & PS3.8 Section 9.3.2.3
class UserInformationItem(DICOMVariableItem):
    """
    User Information Item (Type 0x50). Contains User Data sub-items.
    The 'data' field holds concatenated User Data sub-items.
    """
    name = "User Information"
    item_type = 0x50 # Override default
    fields_desc = [
        ByteField("item_type", 0x50), # Fixed type
        ByteField("reserved", 0),
        ShortField("length", None),
        # User Data Sub-Items follow here, concatenated as bytes
        PacketListField("user_data_subitems", [], DULSubItem, length_from=lambda x: x.length)
    ]
    # Override post_build needed if using PacketListField directly
    def post_build(self, p, pay):
        # Manually calculate length for the variable item header
        sub_items_pay = b"".join(bytes(item) for item in self.user_data_subitems)
        data_len = len(sub_items_pay)
        p = p[:2] + struct.pack("!H", data_len) + p[4:] # Item Len
        return p[:4] + sub_items_pay + pay # Fixed fields + subitems + potential outer payload


class MaxLengthSubItem(DULSubItem):
    """Maximum Length User Data Sub-item (PS3.7 D.1)"""
    name = "Maximum Length Received Sub-item"
    fields_desc = [
        ByteField("item_type", 0x51),
        ByteField("reserved", 0),
        ShortField("length", 4), # Fixed length 4
        IntField("max_length_received", 16384) # Max PDU size we can receive
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
        self.implementation_version_name = self.implementation_version_name[:16]
        if self.length is None:
            length = len(self.implementation_version_name)
            p = p[:2] + struct.pack("!H", length) + p[4:]
        return p + pay


class AsyncOperationsWindowSubItem(DULSubItem):
    """Asynchronous Operations Window User Data Sub-item (PS3.7 D.2)"""
    # Note: Negotiation is deprecated, but field might still be sent.
    name = "Asynchronous Operations Window Sub-item"
    fields_desc = [
        ByteField("item_type", 0x53),
        ByteField("reserved", 0),
        ShortField("length", 4), # Fixed length 4
        ShortField("max_operations_invoked", 1),
        ShortField("max_operations_performed", 1),
    ]

class SCUSCPRoleSelectionSubItem(DULSubItem):
    """SCU/SCP Role Selection User Data Sub-item (PS3.7 D.4)"""
    name = "SCU/SCP Role Selection Sub-item"
    fields_desc = [
        ByteField("item_type", 0x54),
        ByteField("reserved", 0),
        ShortField("item_length", None), # Total length of this sub-item's data
        ShortField("uid_length", None), # Length of the SOP Class UID field
        UIDField("sop_class_uid", "", length_from=lambda x: x.uid_length),
        ByteField("scu_role", 0), # 0 = non-support, 1 = support
        ByteField("scp_role", 0), # 0 = non-support, 1 = support
    ]

    def post_build(self, p, pay):
        # Calculate lengths if not provided
        sop_class_bytes = _uid_to_bytes(self.sop_class_uid)
        uid_len = len(sop_class_bytes)
        item_len = 4 + uid_len # uid_length field(2) + uid data + scu_role(1) + scp_role(1)

        # Pack lengths into the byte string
        p = p[:4] + struct.pack("!H", uid_len) + sop_class_bytes + p[6+uid_len:] # Insert UID len and UID data
        p = p[:2] + struct.pack("!H", item_len) + p[4:] # Insert Item len

        # Ensure roles are set correctly
        p = p[:6+uid_len] + bytes([self.scu_role, self.scp_role]) + pay

        return p + pay


# --- Association Control Service PDUs ---
# PS3.8 Section 9.3
class A_ASSOCIATE_RQ(Packet):
    """A-ASSOCIATE-RQ PDU (PS3.8 Section 9.3.2)"""
    name = "A-ASSOCIATE-RQ"
    fields_desc = [
        ShortField("protocol_version", 0x0001), # Current version is 1
        ShortField("reserved1", 0), # Reserved, shall be 0x0000
        StrFixedLenField("called_ae_title", b"DefaultCalled ".ljust(16), 16), # Space padded
        StrFixedLenField("calling_ae_title", b"DefaultCalling".ljust(16), 16), # Space padded
        StrFixedLenField("reserved2", b"\x00"*32, 32), # Reserved, shall be 0x00...
        # Variable Items (Application Context, Presentation Context(s), User Information)
        PacketListField("variable_items", [], DICOMVariableItem, length_from=lambda pkt: pkt.underlayer.length - 68) # 68 bytes fixed header
    ]
    def dissect_payload(self, s):
        """Manually dissect variable items"""
        # Assumes underlayer (DICOM) has set the length correctly
        # Calculate expected payload length based on DICOM UL header length
        total_payload_len = getattr(self.underlayer, 'length', len(s)) # Use length from UL PDU if available
        if total_payload_len > 68: # Ensure length accounts for fixed header
            total_payload_len -= 68
        else:
            # If length is too small or not set, guess based on available bytes 's'
            # This might happen if the DICOM layer itself wasn't fully dissected
            log.warning("A-ASSOCIATE-RQ/AC UL length seems invalid or missing, guessing payload length from available bytes.")
            total_payload_len = len(s)

        payload_bytes = s[:total_payload_len]
        remaining_bytes = s[total_payload_len:]

        items = []
        stream = BytesIO(payload_bytes) # Use BytesIO for easier reading

        while True:
            header = stream.read(4)
            if len(header) < 4:
                # End of stream or truncated item
                if len(header) > 0:
                    log.warning("Trailing bytes found after last complete variable item in A-ASSOCIATE-RQ/AC.")
                    # Add leftover bytes to remaining_bytes to avoid losing them
                    remaining_bytes = header + remaining_bytes
                break # Exit loop

            item_type, _, item_length = struct.unpack("!BBH", header)
            item_data = stream.read(item_length)

            if len(item_data) < item_length:
                log.warning(f"Variable item {item_type:02X} truncated. Expected {item_length}, got {len(item_data)}.")
                # Put back partially read header and data to remaining_bytes
                remaining_bytes = header + item_data + remaining_bytes
                break # Stop on truncation

            # Attempt to dissect this item
            try:
                # Reconstruct full item bytes for dissection
                full_item_bytes = header + item_data
                # Use the generic class to dissect based on type/length
                # This relies on DICOMVariableItem and its children being defined
                item_pkt = DICOMVariableItem(full_item_bytes)
                items.append(item_pkt)
                log.debug(f"Dissected Variable Item: {item_pkt.summary()}")
            except Exception as e:
                log.error(f"Failed to dissect variable item type {item_type:02X}: {e}")
                # Append as Raw data to avoid losing bytes
                items.append(Raw(header + item_data))

        self.variable_items = items # Assign the manually dissected list
        self.payload = Raw(remaining_bytes) if remaining_bytes else NoPayload() # Assign any leftover bytes

class A_ASSOCIATE_AC(A_ASSOCIATE_RQ):
    """A-ASSOCIATE-AC PDU (PS3.8 Section 9.3.3)"""
    # Structure identical to RQ up to reserved2 field
    name = "A-ASSOCIATE-AC"


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
            1: "No reason given", 2: "Protocol version not supported",
            # Source 3 (Presentation)
            0: "Reserved", 1: "Temporary congestion", 2: "Local limit exceeded",
            # Others Reserved
        })
    ]

class A_RELEASE_RQ(Packet):
    """A-RELEASE-RQ PDU (PS3.8 Section 9.3.6)"""
    name = "A-RELEASE-RQ"
    fields_desc = [
        IntField("reserved1", 0), # 4 bytes reserved, shall be 0x00000000
    ]

class A_RELEASE_RP(Packet):
    """A-RELEASE-RP PDU (PS3.8 Section 9.3.7)"""
    name = "A-RELEASE-RP"
    fields_desc = [
        IntField("reserved1", 0), # 4 bytes reserved, shall be 0x00000000
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
            # Source 2 (Provider)
            0: "Not specified", 1: "Unrecognized PDU", 2: "Unexpected PDU",
            4: "Unrecognized PDU parameter", 5: "Unexpected PDU parameter",
            6: "Invalid PDU parameter value"
            # 3 is reserved
        }) # Reason/Diag - interpretation depends on source
    ]
class PresentationDataValueItem(Packet):
    """
    Represents a single PDV Item conceptually.
    Serialization and parsing handle the explicit length field.
    """
    name = "PDV Item"
    # Only fields defining the *value* part (excluding the length prefix)
    fields_desc = [
        ByteField("context_id", 0),
        ByteField("message_control_header", 0),
        # Data is handled as raw bytes, assigned directly or parsed manually
    ]
    # Store data as an attribute, not a Scapy field
    data = b""
    # Store parsed length info optionally
    _parsed_pdv_value_len = None

    # --- Properties for message_control_header ---
    @property
    def is_last(self):
        return (self.message_control_header >> 1) & 0x01
    @is_last.setter
    def is_last(self, value):
        if value: self.message_control_header |= 0x02
        else: self.message_control_header &= ~0x02
    @property
    def is_command(self):
        return self.message_control_header & 0x01
    @is_command.setter
    def is_command(self, value):
        if value: self.message_control_header |= 0x01
        else: self.message_control_header &= ~0x01

    def build_bytes(self):
        """Manually builds the complete PDV Item bytes including the length prefix."""
        try:
            packed_fields = struct.pack("!BB", self.context_id & 0xFF, self.message_control_header & 0xFF)
        except Exception as e:
            log.error(f"PDV build_bytes: Error packing fields: {e}", exc_info=True)
            packed_fields = b'\x00\x00'
        value_payload = packed_fields + self.data
        pdv_value_len = len(value_payload)
        full_pdv_bytes = struct.pack("!I", pdv_value_len) + value_payload
        log.debug(f"PDV build_bytes: ValueLen={pdv_value_len}. TotalBytes={len(full_pdv_bytes)}.")
        return full_pdv_bytes

    @staticmethod
    def from_bytes(pdv_bytes):
        """
        Parses a complete PDV byte string (including length prefix)
        and returns a tuple (context_id, msg_hdr, data_bytes, value_len)
        or None on failure.
        """
        log.debug(f"PDV from_bytes: ENTER. Received {len(pdv_bytes)} bytes.")
        if len(pdv_bytes) < 4:
            log.error("PDV from_bytes: Input too short for length field.")
            return None
        try:
            pdv_value_len = struct.unpack("!I", pdv_bytes[:4])[0]
            expected_total_len = 4 + pdv_value_len
            log.debug(f"PDV from_bytes: Read value length: {pdv_value_len}. Expecting total item length: {expected_total_len}. Got: {len(pdv_bytes)}")

            if len(pdv_bytes) < expected_total_len:
                log.error(f"PDV from_bytes: Truncated item. Expected {expected_total_len} bytes, got {len(pdv_bytes)}.")
                return None

            value_bytes = pdv_bytes[4:expected_total_len]
            if len(value_bytes) < 2:
                 log.error("PDV from_bytes: Value part too short for context_id and msg_hdr.")
                 return None

            context_id = value_bytes[0]
            msg_hdr = value_bytes[1]
            data_bytes = value_bytes[2:]
            log.debug(f"PDV from_bytes: Parsed values: ctx={context_id}, hdr={msg_hdr}, data_len={len(data_bytes)}")
            return (context_id, msg_hdr, data_bytes, pdv_value_len)

        except struct.error as e:
            log.error(f"PDV from_bytes: Error unpacking length: {e}")
            return None
        except Exception as e:
            log.error(f"PDV from_bytes: Unexpected parsing error: {e}", exc_info=True)
            return None

    # Prevent Scapy's default building/dissection for this specific class
    def build(self):
        log.warning("PDV build() called - use build_bytes() instead.")
        return self.build_bytes()

    def do_dissect(self, s):
        log.error("PDV do_dissect called - use PresentationDataValueItem.from_bytes() instead.")
        return s # Return original string, indicating no dissection performed by Scapy

    def summary(self):
        cmd_data = "Command" if self.is_command else "Data"
        last = "Last" if self.is_last else "More"
        data_len = len(getattr(self, 'data', b''))
        pdv_len_val = getattr(self, 'pdv_value_len', 'N/A') # Use stored length if parsed
        return f"PDV Item (Context: {self.context_id}, {cmd_data}, {last}, ValueLen: {pdv_len_val}, DataLen: {data_len})"


class P_DATA_TF(Packet):
    """
    P-DATA-TF PDU (PS3.8 Section 9.3.5)
    Payload contains concatenated PDV Items. Dissection parses them manually.
    """
    name = "P-DATA-TF"
    fields_desc = []
    parsed_pdv_items = []

    def dissect_payload(self, s):
        """
        Manually parse the PDU payload 's' into PresentationDataValueItem objects.
        Consume exactly the number of bytes specified by the DICOM UL length.
        """
        self.parsed_pdv_items = []
        total_payload_len = getattr(self.underlayer, 'length', len(s))
        log.debug(f"P_DATA_TF.dissect_payload: Starting. UL length = {total_payload_len}. Available bytes = {len(s)}.")

        if total_payload_len > len(s):
             log.warning(f"P_DATA_TF.dissect_payload: UL length {total_payload_len} > available bytes {len(s)}. Processing available bytes.")
             total_payload_len = len(s)

        payload_bytes = s[:total_payload_len]
        remaining_s = s[total_payload_len:] # Bytes *after* the expected PDU payload

        offset = 0
        while offset < len(payload_bytes):
            current_pdv_start_offset = offset
            log.debug(f"  P_DATA_TF: Loop iteration, offset={offset}/{len(payload_bytes)}")

            if offset + 4 > len(payload_bytes):
                log.warning(f"  P_DATA_TF: Insufficient bytes remaining ({len(payload_bytes) - offset}) for PDV length field.")
                break

            try:
                # Read length prefix of the potential PDV
                pdv_value_len = struct.unpack("!I", payload_bytes[offset : offset + 4])[0]
                current_pdv_total_len = 4 + pdv_value_len
                pdv_item_end_offset = offset + current_pdv_total_len

                log.debug(f"  P_DATA_TF: Potential PDV at offset {offset}. Declared value length={pdv_value_len}. Total item length={current_pdv_total_len}.")

                # Check if the *entire* item fits within the remaining payload bytes
                if pdv_item_end_offset > len(payload_bytes):
                    log.error(f"  P_DATA_TF: Declared PDV item length ({current_pdv_total_len}) exceeds remaining PDU payload ({len(payload_bytes) - offset} bytes).")
                    break # Stop processing, remaining bytes will be Raw

                # Extract the bytes for this potential PDV item
                pdv_full_bytes = payload_bytes[offset : pdv_item_end_offset]

                # Attempt to parse the extracted bytes
                parsed_data = PresentationDataValueItem.from_bytes(pdv_full_bytes)

                if parsed_data is not None:
                    # Success: Unpack tuple and create object
                    ctx_id, msg_hdr, d_bytes, val_len = parsed_data
                    pdv_item_obj = PresentationDataValueItem(
                        context_id=ctx_id,
                        message_control_header=msg_hdr
                    )
                    pdv_item_obj.data = d_bytes
                    pdv_item_obj._parsed_pdv_value_len = val_len

                    self.parsed_pdv_items.append(pdv_item_obj)
                    log.debug(f"  P_DATA_TF: Successfully parsed and added PDV: {pdv_item_obj.summary()}")
                    offset = pdv_item_end_offset # Advance offset *only on success*
                else:
                    # from_bytes returned None (it logged the specific error)
                    log.warning(f"  P_DATA_TF: Failed to parse PDV item bytes at offset {current_pdv_start_offset}. Stopping PDU dissection.")
                    break # Stop processing this PDU

            except Exception as e:
                 log.error(f"P-DATA-TF: Unexpected error during PDV processing at offset {offset}: {e}", exc_info=True)
                 break # Stop processing this PDU on any exception

        # Assign remaining payload based on where processing stopped
        if offset < len(payload_bytes):
            # Loop terminated early (error or incomplete read)
            log.warning(f"P-DATA_TF: Assigning remaining {len(payload_bytes[offset:])} bytes of PDU payload as Raw.")
            self.payload = Raw(payload_bytes[offset:])
        else:
            # Successfully processed all bytes within the PDU length
            self.payload = NoPayload()

        log.debug(f"P_DATA_TF.dissect_payload: Finished. Parsed {len(self.parsed_pdv_items)} items. Consumed {offset} bytes. Final payload type: {type(self.payload)}")
        # Return the bytes that came *after* the declared PDU length
        return remaining_s
    
# --- Layer Binding ---
bind_layers(TCP, DICOM, sport=DICOM_PORT)
bind_layers(TCP, DICOM, dport=DICOM_PORT)
# Also bind for common alternative port 11112 often used
bind_layers(TCP, DICOM, sport=11112)
bind_layers(TCP, DICOM, dport=11112)

# Bind DICOM PDU Types
bind_layers(DICOM, A_ASSOCIATE_RQ, pdu_type=0x01)
bind_layers(DICOM, A_ASSOCIATE_AC, pdu_type=0x02)
bind_layers(DICOM, A_ASSOCIATE_RJ, pdu_type=0x03)
bind_layers(DICOM, P_DATA_TF, pdu_type=0x04)
bind_layers(DICOM, A_RELEASE_RQ, pdu_type=0x05)
bind_layers(DICOM, A_RELEASE_RP, pdu_type=0x06)
bind_layers(DICOM, A_ABORT, pdu_type=0x07)

# Potential bindings for Variable Items (mainly for building)
# Note: Dissection might require custom logic due to TLV within StrLenField
bind_layers(DICOMVariableItem, AbstractSyntaxSubItem, item_type=0x30)
bind_layers(DICOMVariableItem, TransferSyntaxSubItem, item_type=0x40)

# Bind User Info sub-items (again, mainly for building assistance)
# These are contained within the 'data' field of a UserInformationItem (0x50)
# Automatic dissection from UserInformationItem.data is not standard Scapy behaviour
bind_layers(DULSubItem, MaxLengthSubItem, item_type=0x51)
bind_layers(DULSubItem, ImplementationClassUIDSubItem, item_type=0x52)
bind_layers(DULSubItem, AsyncOperationsWindowSubItem, item_type=0x53)
bind_layers(DULSubItem, SCUSCPRoleSelectionSubItem, item_type=0x54)
bind_layers(DULSubItem, ImplementationVersionNameSubItem, item_type=0x55)


# ------------------- Network Manager (Helper Class for Testing/Usage) -------------------
class DICOMSession:
    """
    A helper class to manage a DICOM Association session.
    Handles connection, association negotiation, data sending, and release/abort.
    """
    def __init__(self, dst_ip, dst_port=DICOM_PORT, src_ae="SCAPY_SCU", dst_ae="ANY_SCP",
                 connect_timeout=5, read_timeout=30):
        """
        Initializes the DICOM Session parameters.

        Args:
            dst_ip (str): Destination IP address.
            dst_port (int): Destination port (default: 104).
            src_ae (str): Calling AE Title (max 16 chars).
            dst_ae (str): Called AE Title (max 16 chars).
            connect_timeout (int): Socket connection timeout in seconds.
            read_timeout (int): Socket read timeout in seconds.
        """
        if len(src_ae) > 16 or len(dst_ae) > 16:
            raise ValueError("AE titles must be <= 16 characters (DICOM PS3.7 D.3.3.3)")

        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_ae_title = _pad_ae_title(src_ae)
        self.dst_ae_title = _pad_ae_title(dst_ae)
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

        self.s = None
        self.stream = None
        self.assoc_established = False
        self.next_context_id = 1
        self.accepted_contexts = {} # Store accepted {context_id: (abs_syntax, trn_syntax)}
        self.max_pdu_length = 16384 # Default max PDU length we can receive
        self.peer_max_pdu_length = None # Max PDU length peer can receive (from AC)
        self.implementation_class_uid = ImplementationClassUIDSubItem().implementation_class_uid # Default Scapy UID
        self.implementation_version_name = ImplementationVersionNameSubItem().implementation_version_name # Default Scapy Version

    def _connect(self, retries=3, delay=2):
        """Establish TCP connection with retry logic."""
        if self.s: # Close existing socket if any
            try: self.s.close()
            except socket.error: pass
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(self.connect_timeout)
        for attempt in range(retries):
            try:
                log.info(f"Attempting TCP connection to {self.dst_ip}:{self.dst_port} (Attempt {attempt + 1}/{retries})")
                self.s.connect((self.dst_ip, self.dst_port))
                self.s.settimeout(self.read_timeout) # Set read timeout after connection
                log.info(f"TCP Connection established to {self.dst_ip}:{self.dst_port}")
                self.stream = StreamSocket(self.s, DICOM)
                return True
            except socket.timeout:
                log.warning(f"Connection attempt timed out ({self.connect_timeout}s)")
                if attempt == retries - 1:
                     log.error(f"Connection failed after {retries} attempts (Timeout).")
                     raise ConnectionError(f"Connection to {self.dst_ip}:{self.dst_port} timed out after {retries} attempts.")
                time.sleep(delay)
            except socket.error as e:
                log.warning(f"Connection attempt failed: {e}")
                if attempt == retries - 1:
                    log.error(f"Connection failed after {retries} attempts: {e}")
                    raise ConnectionError(f"Connection to {self.dst_ip}:{self.dst_port} failed: {e}")
                time.sleep(delay)
        return False # Should not be reached if exceptions are raised

    def _build_presentation_contexts(self, requested_contexts):
        """
        Build PresentationContextRQItems from a dict and store mapping.
        Uses manual byte packing for reliability with nested items.
        """
        pc_items = []
        self.requested_contexts_map = {} # Clear previous request map
        current_context_id = self.next_context_id # Start with the next available odd ID

        for abstract_syntax, transfer_syntaxes in requested_contexts.items():
            if not isinstance(transfer_syntaxes, list):
                transfer_syntaxes = [transfer_syntaxes]
            if not transfer_syntaxes:
                log.warning(f"No transfer syntaxes provided for {abstract_syntax}. Skipping context.")
                continue

            # Store the request details before creating bytes
            self.requested_contexts_map[current_context_id] = (abstract_syntax, transfer_syntaxes)

            # --- Create sub-item bytes DIRECTLY using helpers ---
            # Abstract Syntax Sub-Item Bytes
            abs_syntax_uid_bytes = _uid_to_bytes(abstract_syntax) # Use helper directly
            abs_syntax_item_len = len(abs_syntax_uid_bytes)
            # Format: Type(1) + Reserved(1) + Length(2) + Value(N)
            abs_syntax_item_bytes_full = struct.pack("!BBH", 0x30, 0, abs_syntax_item_len) + abs_syntax_uid_bytes

            # Transfer Syntax Sub-Item Bytes
            trn_syntax_items_bytes_full = b""
            for ts in transfer_syntaxes:
                ts_uid_bytes = _uid_to_bytes(ts) # Use helper directly
                ts_item_len = len(ts_uid_bytes)
                # Format: Type(1) + Reserved(1) + Length(2) + Value(N)
                trn_syntax_items_bytes_full += struct.pack("!BBH", 0x40, 0, ts_item_len) + ts_uid_bytes
            # --- End direct byte creation ---

            # Combine sub-item bytes
            sub_items_bytes = abs_syntax_item_bytes_full + trn_syntax_items_bytes_full

            # Manually construct the 'data' part for the Presentation Context RQ item
            # Data = Context ID (1) + Reserved (3) + Sub-items
            pc_data_bytes = struct.pack("!BBBB", current_context_id, 0, 0, 0) + sub_items_bytes

            # Create the Variable Item (Type 0x20) containing this raw data.
            # Let DICOMVariableItem calculate its own length based on the data provided.
            pc_item = DICOMVariableItem(item_type=0x20, data=pc_data_bytes)
            pc_items.append(pc_item)

            # Increment context ID (must be odd)
            current_context_id += 2

        # Update the next ID to use for future associations (if any within the same session object)
        self.next_context_id = current_context_id
        return pc_items

    def _build_user_information(self, role_selection=None):
        """
        Build the UserInformationItem with standard sub-items.
        Uses manual byte packing for reliability.
        """
        all_sub_item_bytes = b""

        # --- Manually build bytes for each standard sub-item ---

        # 1. Max Length Sub-Item (Type 0x51)
        max_len_value = self.max_pdu_length
        all_sub_item_bytes += struct.pack("!BBHI", 0x51, 0, 4, max_len_value)
        log.debug(f"Built MaxLengthSubItem bytes (Value: {max_len_value})")

        # 2. Implementation Class UID Sub-Item (Type 0x52)
        impl_uid_input = self.implementation_class_uid # Get value from self
        impl_uid_bytes_val = _uid_to_bytes(impl_uid_input) # Use robust helper
        impl_uid_len = len(impl_uid_bytes_val)
        all_sub_item_bytes += struct.pack("!BBH", 0x52, 0, impl_uid_len) + impl_uid_bytes_val
        # Log the decoded string for clarity if possible
        try:
            log.debug(f"Built ImplementationClassUIDSubItem bytes (UID: {impl_uid_bytes_val.decode('ascii').rstrip(' ')}")
        except: # noqa
             log.debug(f"Built ImplementationClassUIDSubItem bytes (raw: {impl_uid_bytes_val})")


        # 3. Implementation Version Name Sub-Item (Type 0x55)
        impl_ver_input = self.implementation_version_name # Get value from self
        impl_ver_str = ""
        if isinstance(impl_ver_input, bytes):
            impl_ver_str = impl_ver_input.decode('ascii', errors='ignore') # Decode if bytes
        elif isinstance(impl_ver_input, str):
            impl_ver_str = impl_ver_input # Use directly if string
        else:
            log.warning(f"Unexpected type for implementation_version_name: {type(impl_ver_input)}. Using empty string.")

        impl_ver_str = impl_ver_str[:16] # Ensure max 16 chars AFTER potential decode
        impl_ver_bytes_val = impl_ver_str.encode('ascii') # NOW encode the guaranteed string
        impl_ver_len = len(impl_ver_bytes_val)
        all_sub_item_bytes += struct.pack("!BBH", 0x55, 0, impl_ver_len) + impl_ver_bytes_val
        log.debug(f"Built ImplementationVersionNameSubItem bytes (Version: {impl_ver_str})")


        # 4. Async Operations Window Sub-Item (Type 0x53) - Optional but common
        # ... (rest of the function remains the same) ...
        # 5. SCU/SCP Role Selection Sub-Items (Type 0x54) - If provided
        # ...

        # --- Create the final User Information Variable Item ---
        user_info_item = DICOMVariableItem(item_type=0x50, data=all_sub_item_bytes)
        return user_info_item

    def associate(self, requested_contexts=None):
        """
        Attempt to establish a DICOM Association.

        Args:
            requested_contexts (dict): A dictionary where keys are Abstract Syntax UIDs
                                      and values are lists of Transfer Syntax UIDs.
                                      Example: {'1.2.840.10008.1.1': ['1.2.840.10008.1.2']}

        Returns:
            bool: True if association accepted, False otherwise.
        """
        if self.assoc_established:
            log.warning("Association already established.")
            return True

        if not self._connect():
            return False # Connection failed

        if requested_contexts is None:
            # Default: Offer Verification SOP Class with Default Transfer Syntax
            requested_contexts = {
                VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
            }

        # --- Build A-ASSOCIATE-RQ ---
        # 1. Application Context Item
        app_context_bytes = _uid_to_bytes(APP_CONTEXT_UID)
        app_context_item = DICOMVariableItem(item_type=0x10, data=app_context_bytes)

        # 2. Presentation Context Items
        pres_context_items = self._build_presentation_contexts(requested_contexts)

        # 3. User Information Item
        # Example: Add role selection for Verification (SCU=1, SCP=0)
        roles = [(VERIFICATION_SOP_CLASS_UID, 1, 0)]
        # You might want to add roles based on the requested_contexts dynamically
        user_info_item = self._build_user_information(role_selection=roles)

        # Assemble Variable Items list
        variable_items = [app_context_item] + pres_context_items + [user_info_item]

        # Create A-ASSOCIATE-RQ PDU
        assoc_rq = A_ASSOCIATE_RQ(
            calling_ae_title=self.src_ae_title,
            called_ae_title=self.dst_ae_title,
            variable_items=variable_items
        )

        # Wrap in DICOM UL PDU
        dicom_pkt = DICOM(pdu_type=0x01) / assoc_rq

        log.info(f"Sending A-ASSOCIATE-RQ to {self.dst_ip}:{self.dst_port}")
        log.debug(f"A-ASSOCIATE-RQ Details:\n{dicom_pkt.show(dump=True)}")

        try:
            self.stream.send(dicom_pkt)
            log.info("Waiting for A-ASSOCIATE response...")
            response = self.stream.recv()

            if not response:
                log.error("No response received from peer.")
                self.close()
                return False

            log.debug(f"Received Response:\n{response.show(dump=True)}")

            if response.haslayer(A_ASSOCIATE_AC):
                log.info("Association Accepted (A-ASSOCIATE-AC received)")
                self.assoc_established = True
                # Parse AC PDU for negotiated parameters
                ac_pdu = response[A_ASSOCIATE_AC]
                self._parse_associate_ac(ac_pdu)
                return True
            elif response.haslayer(A_ASSOCIATE_RJ):
                rj_pdu = response[A_ASSOCIATE_RJ]
                log.error(f"Association Rejected (A-ASSOCIATE-RJ received): "
                          f"Result={rj_pdu.get_field('result').i2s[rj_pdu.result]}, "
                          f"Source={rj_pdu.get_field('source').i2s[rj_pdu.source]}, "
                          f"Reason={rj_pdu.get_field('reason_diag').i2s[rj_pdu.reason_diag]}")
                self.close()
                return False
            else:
                log.error(f"Unexpected PDU type received: {response.pdu_type}. Aborting.")
                self.abort() # Send A-ABORT
                return False

        except socket.timeout:
            log.error("Timeout waiting for A-ASSOCIATE response.")
            self.close()
            return False
        except Exception as e:
            log.error(f"Error during association: {e}")
            self.abort() # Attempt abort on error
            return False

    def _parse_associate_ac(self, ac_pdu):
        """
        Parse the A-ASSOCIATE-AC PDU to store negotiated parameters.
        Manually parses variable items from raw bytes due to Scapy dissection limitations.
        """
        self.accepted_contexts = {} # Reset accepted contexts
        self.peer_max_pdu_length = None # Reset peer max length

        log.debug(f"AC Called AE Title: {ac_pdu.called_ae_title.decode().strip()}")
        log.debug(f"AC Calling AE Title: {ac_pdu.calling_ae_title.decode().strip()}")

        # --- Manual parsing of Variable Items ---
        # Extract the raw bytes containing the *remaining* variable items.
        # These often end up in the payload (e.g., Raw layer) after Scapy's
        # initial (often incomplete) dissection of the PacketListField.
        variable_items_bytes = b''
        first_item_bytes = b''

        # 1. Check if Scapy dissected *any* items into the list field
        if ac_pdu.variable_items:
             # If Scapy put items here, we need to re-serialize the first one
             # to get its bytes, as the rest will be in the payload.
             # This assumes Scapy only manages to dissect the very first item correctly.
             try:
                 # Rebuild the first item Scapy found
                 first_item_bytes = bytes(ac_pdu.variable_items[0])
                 log.debug(f"Rebuilt bytes of first item dissected by Scapy (len={len(first_item_bytes)}).")
             except Exception as e_build:
                 log.warning(f"Could not rebuild first dissected variable item: {e_build}. Proceeding with payload only.")
                 first_item_bytes = b'' # Reset if rebuild fails

        # 2. Get the bytes from the payload (likely Raw layer)
        payload_bytes = b''
        if isinstance(ac_pdu.payload, (bytes, bytearray)):
            payload_bytes = bytes(ac_pdu.payload)
        elif hasattr(ac_pdu.payload, 'load') and isinstance(ac_pdu.payload.load, (bytes, bytearray)):
            # Handles Raw layer or similar layers with a 'load' attribute
            payload_bytes = bytes(ac_pdu.payload.load)
        elif not isinstance(ac_pdu.payload, NoPayload):
            # Attempt to convert other layer types to bytes, might be lossy
            try:
                 payload_bytes = bytes(ac_pdu.payload)
                 log.warning(f"Converted unexpected payload type {type(ac_pdu.payload)} to bytes.")
            except Exception:
                 log.warning(f"Could not get bytes from unexpected payload type {type(ac_pdu.payload)}.")


        # 3. Combine bytes from potentially dissected first item and the remaining payload
        # This reconstructs the full byte sequence of all variable items.
        variable_items_bytes = first_item_bytes + payload_bytes

        if not variable_items_bytes:
             log.warning("Could not extract any variable item bytes from A-ASSOCIATE-AC PDU.")
             # Association might still be technically valid if peer sends 0 items? Unlikely.
             return # Exit parsing if no bytes found


        log.debug(f"Manually parsing {len(variable_items_bytes)} bytes of AC variable items (reconstructed).")
        offset = 0
        total_len = len(variable_items_bytes)

        # --- The rest of the parsing loop remains the same ---
        while offset < total_len:
            # Check for sufficient bytes for header (Type, Res, Len)
            if offset + 4 > total_len:
                log.warning(f"Truncated variable item header at offset {offset}. Stopping parse.")
                break
            # ... (rest of the while loop as before) ...
            # Read item header
            item_type, _, item_length = struct.unpack("!BBH", variable_items_bytes[offset:offset+4])
            item_data_offset = offset + 4
            item_end_offset = item_data_offset + item_length

            # Check if item length exceeds available bytes
            if item_end_offset > total_len:
                log.warning(f"Variable item (Type {item_type:02X}) length ({item_length}) exceeds available data ({total_len - item_data_offset} left). Stopping parse.")
                break

            item_data_bytes = variable_items_bytes[item_data_offset:item_end_offset]
            log.debug(f"  Found Item Type: 0x{item_type:02X}, Length: {item_length}")

            # --- Process item based on type ---
            if item_type == 0x10: # Application Context
                 app_ctx_uid = UIDField("dummy", "").m2i(None, item_data_bytes)
                 log.debug(f"    Application Context UID: {app_ctx_uid}")

            elif item_type == 0x21: # Presentation Context AC
                 self._parse_presentation_context_ac_item(item_data_bytes)

            elif item_type == 0x50: # User Information
                 self._parse_user_information_item(item_data_bytes)

            else:
                log.debug(f"    Skipping unknown/unhandled variable item type 0x{item_type:02X}")

            # Move to the next item
            offset = item_end_offset

        if offset != total_len:
            log.warning(f"Finished parsing AC variable items, but {total_len - offset} bytes remain unprocessed.")

    def _parse_presentation_context_ac_item(self, data_bytes):
        """Helper to parse the data part of a Presentation Context AC item."""
        if len(data_bytes) < 4:
            log.warning(f"Malformed Presentation Context AC item received (data length {len(data_bytes)} < 4)")
            return

        context_id, _, result_reason, _ = struct.unpack("!BBBB", data_bytes[:4])
        log.debug(f"    Presentation Context AC Item (ID: {context_id}):")

        original_request = self.requested_contexts_map.get(context_id)
        if original_request:
            original_abstract_syntax = original_request[0]
        else:
            original_abstract_syntax = "Unknown (Context ID not in RQ map?)"
            log.warning(f"      Received AC for Presentation Context ID {context_id} which was not in our RQ map.")

        result_map = {0: "Acceptance", 1: "User Rejection", 2: "Provider Rejection (no reason)",
                      3: "Abstract Syntax Not Supported", 4: "Transfer Syntaxes Not Supported"}
        result_str = result_map.get(result_reason, f"Unknown ({result_reason})")
        log.debug(f"      Result: {result_str} ({result_reason})")

        if result_reason == 0: # Acceptance
            # Try to parse the accepted Transfer Syntax Sub-item (starts immediately after result/reserved)
            sub_item_data = data_bytes[4:]
            accepted_transfer_syntax = "Error parsing Transfer Syntax"
            if len(sub_item_data) >= 4 and sub_item_data[0] == 0x40: # Transfer Syntax type
                # Read TS sub-item length
                ts_len = struct.unpack("!H", sub_item_data[2:4])[0]
                ts_data_offset = 4
                ts_end_offset = ts_data_offset + ts_len
                if ts_end_offset <= len(sub_item_data):
                     ts_uid_bytes = sub_item_data[ts_data_offset:ts_end_offset]
                     try:
                         accepted_transfer_syntax = UIDField("dummy", "").m2i(None, ts_uid_bytes)
                         log.info(f"      Presentation Context ID {context_id} ACCEPTED")
                         log.info(f"        Abstract Syntax: {original_abstract_syntax}")
                         log.info(f"        Transfer Syntax: {accepted_transfer_syntax}")
                         # Store accepted context details
                         self.accepted_contexts[context_id] = (original_abstract_syntax, accepted_transfer_syntax)
                     except Exception as e_parse:
                         log.warning(f"      Error parsing accepted Transfer Syntax UID for context {context_id}: {e_parse}")
                else:
                     log.warning(f"      Transfer Syntax sub-item length ({ts_len}) exceeds available data ({len(sub_item_data) - ts_data_offset} left).")
            else:
                 log.warning(f"      No valid Transfer Syntax sub-item (Type 0x40) found in accepted AC context {context_id}")
        else:
             log.info(f"      Presentation Context ID {context_id} ({original_abstract_syntax}) REJECTED/FAILED (Reason: {result_str})")


    def _parse_user_information_item(self, data_bytes):
        """Helper to parse the sub-items within a User Information item's data."""
        log.debug("    User Information Item:")
        sub_offset = 0
        sub_total_len = len(data_bytes)
        while sub_offset < sub_total_len:
             if sub_offset + 4 > sub_total_len:
                 log.warning("      Truncated User Information sub-item header.")
                 break

             sub_type, _, sub_len = struct.unpack("!BBH", data_bytes[sub_offset:sub_offset+4])
             sub_data_offset = sub_offset + 4
             sub_end_offset = sub_data_offset + sub_len

             if sub_end_offset > sub_total_len:
                 log.warning(f"      User Information sub-item (Type {sub_type:02X}) length ({sub_len}) exceeds available data.")
                 break

             sub_item_payload_bytes = data_bytes[sub_data_offset:sub_end_offset]
             log.debug(f"      Found Sub-Item Type: 0x{sub_type:02X}, Length: {sub_len}")

             # Example: Parse Max Length sub-item
             if sub_type == 0x51: # Max Length
                 if sub_len == 4:
                     try:
                         self.peer_max_pdu_length = struct.unpack("!I", sub_item_payload_bytes)[0]
                         log.info(f"        Peer maximum PDU length: {self.peer_max_pdu_length}")
                     except struct.error:
                         log.warning("        Could not unpack Max Length sub-item value.")
                 else:
                      log.warning(f"        Invalid length ({sub_len}) for Max Length sub-item (expected 4).")
             elif sub_type == 0x52: # Implementation Class UID
                  try:
                       peer_impl_uid = UIDField("dummy", "").m2i(None, sub_item_payload_bytes)
                       log.info(f"        Peer Implementation Class UID: {peer_impl_uid}")
                  except Exception as e_uid:
                       log.warning(f"        Could not parse Peer Implementation Class UID: {e_uid}")
             elif sub_type == 0x55: # Implementation Version Name
                  try:
                       peer_impl_ver = sub_item_payload_bytes.decode('ascii')
                       log.info(f"        Peer Implementation Version Name: {peer_impl_ver}")
                  except Exception as e_ver:
                       log.warning(f"        Could not parse Peer Implementation Version Name: {e_ver}")
             # Could parse other items like Async Ops, Role Selection if needed

             # Move to the next sub-item
             sub_offset = sub_end_offset

    def send_p_data(self, pdv_list):
        """
        Builds and sends a P-DATA-TF PDU containing the given PDV items.

        Args:
            pdv_list (list): A list of PresentationDataValueItem objects.

        Returns:
            bool: True if send successful, False otherwise.
        """
        if not self.assoc_established:
            log.error("Cannot send P-DATA: No active association.")
            return False
        if not pdv_list:
            log.warning("send_p_data called with empty PDV list.")
            return True # Nothing to send

        # Manually build the concatenated PDV payload
        all_pdv_bytes = b""
        try:
            for pdv in pdv_list:
                all_pdv_bytes += pdv.build_bytes() # Use explicit build method
        except Exception as e:
             log.error(f"Error building PDV bytes: {e}", exc_info=True)
             return False

        # Create the PDU structure
        p_data_tf_pdu = P_DATA_TF() # Empty PDU, payload added as Raw
        # Explicitly add the concatenated bytes as the payload for P_DATA_TF
        dicom_pkt = DICOM(pdu_type=0x04) / p_data_tf_pdu / Raw(load=all_pdv_bytes)

        # Let DICOM.post_build calculate the final length
        # Check PDU size against peer's max length if known
        try:
            final_bytes_to_send = bytes(dicom_pkt) # Trigger serialization
        except Exception as e:
             log.error(f"Error serializing final DICOM packet: {e}", exc_info=True)
             return False

        total_len = len(final_bytes_to_send)
        if self.peer_max_pdu_length and total_len > self.peer_max_pdu_length:
            log.error(f"PDU size ({total_len} bytes) exceeds peer maximum ({self.peer_max_pdu_length} bytes). Cannot send.")
            return False

        log.info(f"Sending P-DATA-TF ({len(pdv_list)} PDV(s))")
        # Logging the object structure might be less useful now
        # log.debug(f"P-DATA-TF Object Structure:\n{dicom_pkt.show(dump=True)}")
        log.debug(f"Final Bytes Sent ({len(final_bytes_to_send)} bytes):")
        log.debug(final_bytes_to_send.hex('.'))

        try:
            self.stream.send(final_bytes_to_send)
            return True
        except Exception as e:
            log.error(f"Failed to send P-DATA-TF: {e}")
            # Consider aborting or attempting recovery depending on the error
            self.abort()
            return False 
            
    def release(self):
        """Sends A-RELEASE-RQ and waits for A-RELEASE-RP."""
        if not self.assoc_established:
            log.warning("Cannot release: No active association.")
            return True # Already released or never associated

        release_rq = A_RELEASE_RQ()
        dicom_pkt = DICOM(pdu_type=0x05) / release_rq

        log.info("Sending A-RELEASE-RQ...")
        try:
            self.stream.send(dicom_pkt)
            log.info("Waiting for A-RELEASE-RP...")
            response = self.stream.recv()

            if response and response.haslayer(A_RELEASE_RP):
                log.info("Association released successfully (A-RELEASE-RP received).")
                self.assoc_established = False
                self.close()
                return True
            elif response:
                 log.warning(f"Unexpected response received during release: {response.summary()}. Aborting.")
                 # Peer should not send data after receiving A-RELEASE-RQ, might send A-ABORT
                 self.abort()
                 return False
            else:
                log.warning("No response received for A-RELEASE-RQ (peer might have closed connection).")
                self.assoc_established = False
                self.close()
                return True # Treat as success if peer just closes

        except socket.timeout:
            log.error("Timeout waiting for A-RELEASE-RP.")
            self.abort() # Abort if release times out
            return False
        except Exception as e:
            log.error(f"Error during release: {e}")
            self.abort()
            return False

    def abort(self, source=0, reason=0):
        """
        Sends an A-ABORT PDU.

        Args:
            source (int): Abort source (0=user, 2=provider).
            reason (int): Abort reason/diagnostic code.
        """
        if not self.stream:
             log.info("Cannot send A-ABORT: No connection.")
             self.close() # Ensure socket is closed
             return

        abort_pdu = A_ABORT(source=source, reason_diag=reason)
        dicom_pkt = DICOM(pdu_type=0x07) / abort_pdu

        log.info(f"Sending A-ABORT (Source={source}, Reason={reason})...")
        try:
            # Send might fail if socket already closed by peer or network issue
            self.stream.send(dicom_pkt)
        except Exception as e:
            log.warning(f"Exception sending A-ABORT (socket likely closed): {e}")
            pass # Ignore send errors during abort

        self.assoc_established = False
        self.close()

    def close(self):
        """Closes the socket connection."""
        if self.s:
            log.info("Closing DICOM TCP connection.")
            try:
                self.s.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass # Ignore if already closed
            try:
                self.s.close()
            except socket.error:
                pass # Ignore if already closed
            self.s = None
            self.stream = None
        self.assoc_established = False
        self.accepted_contexts = {}
        self.next_context_id = 1

