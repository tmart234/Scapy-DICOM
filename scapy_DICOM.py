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
# import struct # Already imported above

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
# logging.basicConfig(level=logging.DEBUG)


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
    """
    Represents a single PDV Item conceptually.
    Serialization (`build_bytes`) and manual parsing within P_DATA_TF handle the structure.
    """
    name = "PDV Item"
    # No Scapy fields_desc needed as it's manually handled

    # --- Attributes to hold parsed data ---
    context_id = 0
    message_control_header = 0
    data = b""
    _parsed_pdv_value_len = None # Store the length read during dissection

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
            # Ensure context_id and header are within byte range
            ctx_id = self.context_id & 0xFF
            msg_hdr = self.message_control_header & 0xFF
            packed_fields = struct.pack("!BB", ctx_id, msg_hdr)
        except Exception as e:
            log.error(f"PDV build_bytes: Error packing fields: {e}", exc_info=True)
            packed_fields = b'\x00\x00' # Default to 0 on error

        # Ensure data is bytes
        data_payload = self.data if isinstance(self.data, bytes) else b''

        value_payload = packed_fields + data_payload
        pdv_value_len = len(value_payload)
        full_pdv_bytes = struct.pack("!I", pdv_value_len) + value_payload # Big Endian Length
        log.debug(f"PDV build_bytes: ValueLen={pdv_value_len}. TotalBytes={len(full_pdv_bytes)}.")
        return full_pdv_bytes

    # Removed from_bytes as parsing is now done in P_DATA_TF.dissect_payload

    # Prevent Scapy's default building/dissection for this specific class
    def build(self):
        # This method is typically called by Scapy internally.
        # We want to use our manual build_bytes() instead.
        log.warning("PDV build() called unexpectedly - use build_bytes() directly if needed.")
        # Return empty bytes or raise error? Returning bytes() might be safer.
        return b'' # Avoid Scapy trying to build based on non-existent fields_desc

    def do_build(self):
        # Overriding do_build might be necessary if build() isn't enough
        log.debug("PDV do_build() called.")
        return self.build_bytes() # Delegate to manual builder

    def do_dissect(self, s):
        # Dissection is handled entirely by P_DATA_TF.dissect_payload
        log.error("PDV do_dissect called - This should not happen. Parsing occurs in P_DATA_TF.")
        # Return the original bytes, indicating Scapy shouldn't process further
        return s

    def summary(self):
        cmd_data = "Command" if self.is_command else "Data"
        last = "Last" if self.is_last else "More"
        data_len = len(self.data) if hasattr(self, 'data') else 'N/A'
        # Use the stored length if available from dissection
        pdv_len_val = self._parsed_pdv_value_len if self._parsed_pdv_value_len is not None else 'N/A'
        return f"PDV Item (Context: {self.context_id}, {cmd_data}, {last}, ValueLen: {pdv_len_val}, DataLen: {data_len})"

# ---- FIXED P_DATA_TF ----
class P_DATA_TF(Packet):
    """
    P-DATA-TF PDU (PS3.8 Section 9.3.5)
    Payload contains concatenated PDV Items. Dissection parses them manually.
    """
    name = "P-DATA-TF"
    # No fields_desc needed, payload is manually parsed/built

    # Store parsed items here
    parsed_pdv_items = []

    def dissect_payload(self, s):
        """
        Manually parse the PDU payload 's' into PresentationDataValueItem objects.
        Consume exactly the number of bytes specified by the DICOM UL length.
        """
        self.parsed_pdv_items = []
        # Determine the exact number of bytes belonging to this PDU's payload
        total_payload_len = getattr(self.underlayer, 'length', len(s))
        log.debug(f"P_DATA_TF.dissect_payload: Starting. UL length = {total_payload_len}. Available bytes = {len(s)}.")

        # Determine the actual bytes to process from 's'
        if total_payload_len > len(s):
            log.warning(f"P_DATA_TF.dissect_payload: UL length {total_payload_len} > available bytes {len(s)}. Processing only available bytes.")
            payload_to_process = s
            remaining_after_pdu = b'' # No bytes left after this PDU
        else:
            payload_to_process = s[:total_payload_len]
            remaining_after_pdu = s[total_payload_len:] # Bytes belonging to the *next* PDU

        stream = BytesIO(payload_to_process)
        processed_bytes_count = 0

        while processed_bytes_count < len(payload_to_process):
            start_offset = stream.tell()
            log.debug(f" P_DATA_TF loop: Current offset={start_offset}, Total to process={len(payload_to_process)}")

            # Read PDV Item Length (4 bytes, Big Endian)
            packed_length_bytes = stream.read(4)
            if len(packed_length_bytes) < 4:
                if len(packed_length_bytes) > 0:
                    log.warning(f" P_DATA_TF loop: Truncated PDV length field (got {len(packed_length_bytes)} bytes). Stopping parse.")
                    stream.seek(start_offset) # Rewind to include these bytes as leftovers
                else:
                    log.debug(" P_DATA_TF loop: End of PDU payload stream.")
                break # Stop processing

            try:
                pdv_value_len = struct.unpack("!I", packed_length_bytes)[0]
                log.debug(f" P_DATA_TF loop: Read PDV Value Length = {pdv_value_len}")
            except struct.error as e:
                log.error(f" P_DATA_TF loop: Error unpacking PDV length: {e}. Stopping parse.")
                stream.seek(start_offset) # Rewind
                break

            # Check if the declared length fits within the remaining PDU payload
            bytes_remaining_in_payload = len(payload_to_process) - stream.tell()
            if pdv_value_len > bytes_remaining_in_payload:
                log.warning(f" P_DATA_TF loop: PDV value length ({pdv_value_len}) exceeds remaining PDU payload ({bytes_remaining_in_payload}). Truncated item? Stopping parse.")
                stream.seek(start_offset) # Rewind
                break

            # Read the PDV Value (Context ID, Msg Hdr, Data)
            pdv_value_bytes = stream.read(pdv_value_len)
            if len(pdv_value_bytes) < pdv_value_len:
                 # This shouldn't happen due to the check above, but safety first
                 log.error(f" P_DATA_TF loop: Short read for PDV value. Expected {pdv_value_len}, got {len(pdv_value_bytes)}. Stopping parse.")
                 stream.seek(start_offset) # Rewind
                 break

            # Check minimum length for Context ID and Message Control Header
            if len(pdv_value_bytes) < 2:
                 log.error(f" P_DATA_TF loop: PDV value too short ({len(pdv_value_bytes)} bytes) for Context ID and Header. Stopping parse.")
                 stream.seek(start_offset) # Rewind
                 break

            # Parse the PDV Item components
            context_id = pdv_value_bytes[0]
            msg_hdr = pdv_value_bytes[1]
            data_bytes = pdv_value_bytes[2:]

            # Create and populate the PresentationDataValueItem instance
            pdv_item = PresentationDataValueItem()
            pdv_item.context_id = context_id
            pdv_item.message_control_header = msg_hdr
            pdv_item.data = data_bytes
            pdv_item._parsed_pdv_value_len = pdv_value_len # Store the parsed length

            self.parsed_pdv_items.append(pdv_item)
            log.debug(f" P_DATA_TF loop: Successfully parsed and added: {pdv_item.summary()}")

            # Update processed bytes count for the outer loop condition
            processed_bytes_count = stream.tell()

        # After loop: Check if any bytes remain in the stream (part of this PDU but unparsed)
        leftover_pdu_bytes = stream.read()
        if leftover_pdu_bytes:
            log.warning(f"P_DATA_TF.dissect_payload: {len(leftover_pdu_bytes)} unparsed bytes remaining within PDU payload.")
            # Prepend these leftovers to the bytes belonging to the next PDU
            remaining_after_pdu = leftover_pdu_bytes + remaining_after_pdu

        # Assign the remaining bytes (belonging to the *next* PDU or unparsed) to payload
        self.payload = Raw(remaining_after_pdu) if remaining_after_pdu else NoPayload()
        log.debug(f"P_DATA_TF.dissect_payload: Finished. Parsed {len(self.parsed_pdv_items)} PDV items. Next layer payload length: {len(remaining_after_pdu)}")


    def build_payload(self):
        """Builds the P-DATA-TF payload by concatenating the bytes of PDV items."""
        log.debug(f"P_DATA_TF.build_payload: Building from {len(self.parsed_pdv_items)} items.")
        payload = b"".join(item.build_bytes() for item in self.parsed_pdv_items)
        return payload

    # Override post_build to ensure payload comes from build_payload
    def post_build(self, p, pay):
        """Ensures the payload is built from parsed_pdv_items if they exist."""
        # 'p' is the header bytes, 'pay' is the payload from subsequent layers (should be empty for P-DATA-TF)
        if self.parsed_pdv_items:
            built_payload = self.build_payload()
            log.debug(f"P_DATA_TF.post_build: Using built payload (len={len(built_payload)}) from parsed_pdv_items.")
            # The DICOM UL layer above this will handle adding the PDU length header
            return p + built_payload + pay # Should normally just be 'p + built_payload'
        else:
            # If no items, just return header and any existing payload (e.g., Raw)
             log.debug("P_DATA_TF.post_build: No parsed_pdv_items, returning header + existing payload.")
             return p + pay


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

# NOTE: Binding Variable Items (0x10, 0x20, 0x21, 0x50 etc.) to specific payload
# within A-ASSOCIATE-RQ/AC is complex due to the list structure. Manual dissection
# as implemented in A_ASSOCIATE_RQ.dissect_payload is generally more reliable.
# Similarly, binding sub-items within User Info or Presentation Context is tricky.


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
        """Sends A-ASSOCIATE-RQ and waits for A-ASSOCIATE-AC."""
        if not self.stream:
            if not self.connect():
                return False

        if requested_contexts is None:
            # Default: Request Verification SOP Class with Implicit VR LE
             requested_contexts = {VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}

        # --- Build Variable Items ---
        # 1. Application Context Item
        app_context = DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID))
        # Manually calculate app_context length and ensure correct build (optional but safer)
        app_context.length = len(app_context.data)


        # 2. Presentation Context Items
        pres_items_list = []
        context_id_counter = 1 # Context IDs must be odd
        for abs_syntax, trn_syntaxes in requested_contexts.items():
            # Build Abstract Syntax Sub-item
            abs_syntax_item = AbstractSyntaxSubItem(abstract_syntax_uid=abs_syntax)
            abs_syntax_bytes = bytes(abs_syntax_item) # Build bytes early

            # Build Transfer Syntax Sub-items list
            trn_syntax_items_bytes = b"".join(
                bytes(TransferSyntaxSubItem(transfer_syntax_uid=ts)) for ts in trn_syntaxes
            ) # Build bytes early

            # Combine sub-items into Presentation Context 'data'
            # Fixed part (context_id, reserved) + abstract syntax bytes + transfer syntax bytes
            pres_data_header = struct.pack("!BBBB", context_id_counter, 0, 0, 0)
            pres_total_data = pres_data_header + abs_syntax_bytes + trn_syntax_items_bytes

            # *** FIX: Explicitly create and set length for the Pres Context Item ***
            pres_item = DICOMVariableItem(item_type=0x20) # Create item
            pres_item.data = pres_total_data            # Set data
            pres_item.length = len(pres_total_data)     # Explicitly set length

            pres_items_list.append(pres_item)
            context_id_counter += 2 # Increment by 2 to keep it odd

        # 3. User Information Item
        user_info_subitems = [
            MaxLengthSubItem(max_length_received=16384), # Let peer know our max receive size
            ImplementationClassUIDSubItem(), # Uses Scapy's default
            ImplementationVersionNameSubItem() # Uses Scapy's default
        ]
        user_info_data = b"".join(bytes(item) for item in user_info_subitems)
        user_info_item = DICOMVariableItem(item_type=0x50, data=user_info_data)
        # Manually calculate user_info length and ensure correct build (optional but safer)
        user_info_item.length = len(user_info_item.data)
        # Combine all variable items
        all_variable_items = [app_context] + pres_items_list + [user_info_item]

        # --- Build A-ASSOCIATE-RQ PDU ---
        assoc_rq = DICOM()/A_ASSOCIATE_RQ(
            called_ae_title=self.dst_ae,
            calling_ae_title=self.src_ae,
        )
        # Assign manually built items
        assoc_rq[A_ASSOCIATE_RQ].variable_items = all_variable_items

        log.info(f"Sending A-ASSOCIATE-RQ to {self.dst_ip}:{self.dst_port}")
        log.debug(f"A-ASSOCIATE-RQ Details:\n{assoc_rq.show(dump=True)}")

        try:
            response = self.stream.sr1(assoc_rq, timeout=self.read_timeout, verbose=False)
        except KeyboardInterrupt:
             log.warning("Operation interrupted by user during association.")
             self.close()
             return False
        except Exception as e:
            log.error(f"Error sending/receiving association request: {e}", exc_info=True)
            self.close()
            return False


        if not response:
            log.error("No response received for A-ASSOCIATE-RQ (timeout).")
            self.close()
            return False

        log.debug("Received Response:")
        log.debug(response.show(dump=True))

        if response.haslayer(A_ASSOCIATE_AC):
            ac_layer = response[A_ASSOCIATE_AC]
            log.info("Association Accepted (A-ASSOCIATE-AC received)")
            # --- Manually Parse AC Variable Items ---
            # (Scapy's dissection might be okay now, but manual parsing is safer)
            self.accepted_contexts = {}
            try:
                # Use the manually parsed list from dissect_payload
                ac_variable_items = getattr(ac_layer, 'variable_items', [])
                log.debug(f"Rebuilt bytes of first item dissected by Scapy (len={len(bytes(ac_variable_items[0])) if ac_variable_items else 0}).")
                total_ac_var_bytes = b''.join(bytes(item) for item in ac_variable_items) # Reconstruct bytes
                log.debug(f"Manually parsing {len(total_ac_var_bytes)} bytes of AC variable items (reconstructed).")
                ac_stream = BytesIO(total_ac_var_bytes)

                while True:
                    header = ac_stream.read(4)
                    if len(header) < 4: break
                    item_type, _, item_length = struct.unpack("!BBH", header)
                    item_data = ac_stream.read(item_length)
                    if len(item_data) < item_length: break # Truncated

                    log.debug(f"  Found Item Type: 0x{item_type:02X}, Length: {item_length}")

                    if item_type == 0x10: # Application Context
                        uid = item_data.rstrip(b'\x00').decode('ascii')
                        log.debug(f"    Application Context UID: {uid}")
                        if uid != APP_CONTEXT_UID: log.warning("Peer accepted different App Context UID!")

                    elif item_type == 0x21: # Presentation Context AC
                        if len(item_data) >= 4:
                            ctx_id, _, result, _ = struct.unpack("!BBBB", item_data[:4])
                            log.debug(f"    Presentation Context AC Item (ID: {ctx_id}):")
                            log.debug(f"      Result: {result}")
                            if result == 0: # Acceptance
                                log.info(f"      Presentation Context ID {ctx_id} ACCEPTED")
                                # Parse nested Transfer Syntax Item
                                ts_item_bytes = item_data[4:]
                                if len(ts_item_bytes) >= 4:
                                    ts_type, _, ts_len = struct.unpack("!BBH", ts_item_bytes[:4])
                                    if ts_type == 0x40 and len(ts_item_bytes) >= 4 + ts_len:
                                        ts_uid_bytes = ts_item_bytes[4:4 + ts_len]
                                        ts_uid = ts_uid_bytes.rstrip(b'\x00').decode('ascii')
                                        log.info(f"        Transfer Syntax: {ts_uid}")
                                        # Find matching requested abstract syntax (requires storing original request)
                                        # For now, just store accepted context ID and TS UID
                                        # Need original request details to map abs_syntax
                                        self.accepted_contexts[ctx_id] = ("<Unknown Abstract Syntax>", ts_uid)
                                    else: log.warning(f"      Malformed Transfer Syntax sub-item in AC Context {ctx_id}")
                                else: log.warning(f"      Missing Transfer Syntax sub-item in AC Context {ctx_id}")
                            else:
                                log.warning(f"      Presentation Context ID {ctx_id} REJECTED (Reason: {result})")
                        else: log.warning("    Malformed Presentation Context AC item.")

                    elif item_type == 0x50: # User Information
                        log.debug("    User Information Item:")
                        ui_stream = BytesIO(item_data)
                        while True:
                             sub_header = ui_stream.read(4)
                             if len(sub_header) < 4: break
                             sub_type, _, sub_len = struct.unpack("!BBH", sub_header)
                             sub_data = ui_stream.read(sub_len)
                             if len(sub_data) < sub_len: break # Truncated

                             if sub_type == 0x51: # Max Length
                                 if sub_len == 4:
                                     max_len = struct.unpack("!I", sub_data)[0]
                                     self.peer_max_pdu = max_len
                                     log.info(f"        Peer maximum PDU length: {max_len}")
                                 else: log.warning(f"        Malformed Max Length sub-item (len={sub_len})")
                             elif sub_type == 0x52: # Impl Class UID
                                 uid = sub_data.rstrip(b'\x00').decode('ascii')
                                 log.info(f"        Peer Implementation Class UID: {uid}")
                             elif sub_type == 0x55: # Impl Version Name
                                 name = sub_data.decode('ascii')
                                 log.info(f"        Peer Implementation Version Name: {name}")
                             # Add parsing for other User Info sub-items if needed (0x53, 0x54)
            except Exception as e:
                 log.error(f"Error parsing A-ASSOCIATE-AC variable items manually: {e}", exc_info=True)
            # Need to retrieve Abstract Syntax UIDs from original request to fully populate accepted_contexts
            # This requires storing `requested_contexts` or parsing the sent RQ packet.
            # For now, we mark abstract syntax as unknown in `self.accepted_contexts`.

            self.assoc_established = True
            return True

        elif response.haslayer(A_ASSOCIATE_RJ):
            rj = response[A_ASSOCIATE_RJ]
            log.error("Association Rejected (A-ASSOCIATE-RJ received)")
            log.error(f"  Result: {rj.result} ({rj.get_field('result').i2s[rj.result]})")
            log.error(f"  Source: {rj.source} ({rj.get_field('source').i2s[rj.source]})")
            # Need careful handling of reason_diag enum keys if they were changed
            reason_str = rj.get_field('reason_diag').i2s.get(rj.reason_diag, f"Unknown ({rj.reason_diag})")
            log.error(f"  Reason: {rj.reason_diag} ({reason_str})")
            self.close()
            return False
        else:
            log.error(f"Unexpected response received for A-ASSOCIATE-RQ: {response.summary()}")
            self.close()
            return False

    def send_p_data(self, pdv_list):
        """Sends one or more PDV items within a P-DATA-TF PDU."""
        if not self.assoc_established or not self.stream:
            log.error("Cannot send P-DATA: Association not established.")
            return False

        # Create P-DATA-TF packet
        p_data_tf = DICOM()/P_DATA_TF()
        # Assign PDV items to the list that build_payload uses
        p_data_tf[P_DATA_TF].parsed_pdv_items = pdv_list

        log.info(f"Sending P-DATA-TF ({len(pdv_list)} PDV(s))")
        # The build process will call P_DATA_TF.build_payload(),
        # then DICOM.post_build() will calculate the overall PDU length.
        try:
            # Use send() for P-DATA as we don't necessarily expect an immediate layer 7 response
            # sr1 might work but send is more appropriate for data transfer phases
            sent_len = self.stream.send(p_data_tf)
            # Optional: Log the raw bytes sent for debugging
            final_bytes = bytes(p_data_tf)
            log.debug(f"Final Bytes Sent ({len(final_bytes)} bytes):")
            log.debug(final_bytes.hex('.')) # Use hex with separator for readability
            return sent_len > 0
        except Exception as e:
            log.error(f"Error sending P-DATA-TF: {e}", exc_info=True)
            self.assoc_established = False # Assume connection broken
            self.close()
            return False

    def release(self):
        """Sends A-RELEASE-RQ and waits for A-RELEASE-RP."""
        if not self.assoc_established or not self.stream:
            log.info("Cannot release: Association not established or already closed.")
            return True # Consider it released if not established

        log.info("Sending A-RELEASE-RQ...")
        release_rq = DICOM()/A_RELEASE_RQ()
        response = self.stream.sr1(release_rq, timeout=self.read_timeout, verbose=False)

        if not response:
            log.warning("No response received for A-RELEASE-RQ (timeout). Closing connection.")
            self.assoc_established = False
            self.close()
            return False

        if response.haslayer(A_RELEASE_RP):
            log.info("Association released successfully (A-RELEASE-RP received).")
            self.assoc_established = False
            self.close() # Close connection after successful release
            return True
        else:
            log.warning(f"Unexpected response received for A-RELEASE-RQ: {response.summary()}")
            # Should we abort here? Or just close? Closing is safer.
            self.assoc_established = False
            self.close()
            return False

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