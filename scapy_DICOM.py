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

from scapy.all import Packet, bind_layers, PacketListField, conf
from scapy.fields import (
    ByteEnumField, ByteField, ShortField, IntField, FieldLenField,
    StrFixedLenField, StrLenField, ShortEnumField, Field, BitField
)
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket

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
    """Encode UID string to bytes, handling potential trailing null byte."""
    b_uid = uid.encode('ascii')
    # DICOM UIDs may be padded with a single NULL byte (0x00) if their length is odd
    if len(b_uid) % 2 != 0:
        b_uid += b'\x00'
    return b_uid

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

class A_ASSOCIATE_AC(Packet):
    """A-ASSOCIATE-AC PDU (PS3.8 Section 9.3.3)"""
    # Structure identical to RQ up to reserved2 field
    name = "A-ASSOCIATE-AC"
    fields_desc = [
        ShortField("protocol_version", 0x0001),
        ShortField("reserved1", 0),
        StrFixedLenField("called_ae_title", b"DefaultCalled ".ljust(16), 16), # Usually mirrors RQ
        StrFixedLenField("calling_ae_title", b"DefaultCalling".ljust(16), 16), # Usually mirrors RQ
        StrFixedLenField("reserved2", b"\x00"*32, 32),
        # Variable Items (Application Context, Presentation Context(s) AC, User Information)
        PacketListField("variable_items", [], DICOMVariableItem, length_from=lambda pkt: pkt.underlayer.length - 68)
    ]

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

# --- Data Transfer Service PDU ---
class PresentationDataValueItem(Packet):
    """
    Presentation Data Value (PDV) Item within a P-DATA-TF PDU
    PS3.8 Section 9.3.5.1 & Figure 9-18
    """
    name = "PDV Item"
    fields_desc = [
        # PDV Length: Length of the *following* fields (Context ID + Msg Hdr + Data)
        IntField("length", None),
        # --- Start of PDV Value (length bytes) ---
        ByteField("context_id", 0), # Presentation Context ID this data relates to
        # Message Control Header (1 byte containing flags)
        ByteField("message_control_header", 0),
        # The actual DIMSE message fragment (Command or Data Set)
        # Length is PDV length - 1 (context_id) - 1 (msg_ctrl_hdr)
        StrLenField("data", b"", length_from=lambda x: x.length - 2),
    ]

    # Define properties to access flags within message_control_header
    @property
    def is_last(self):
        # Bit 1 (0-indexed) from the right = Last Fragment flag
        return (self.message_control_header >> 1) & 0x01

    @is_last.setter
    def is_last(self, value):
        if value:
            self.message_control_header |= 0x02 # Set bit 1
        else:
            self.message_control_header &= ~0x02 # Clear bit 1

    @property
    def is_command(self):
        # Bit 0 (0-indexed) from the right = Command/Data flag
        return self.message_control_header & 0x01

    @is_command.setter
    def is_command(self, value):
        if value:
            self.message_control_header |= 0x01 # Set bit 0
        else:
            self.message_control_header &= ~0x01 # Clear bit 0

    def post_build(self, p, pay):
        # Calculate PDV length if not provided
        # Length = length of context_id(1) + msg_ctrl_hdr(1) + data
        if self.length is None:
            length = 1 + 1 + len(self.data)
            p = struct.pack("!I", length) + p[4:]

        # Ensure the message_control_header byte is correctly placed
        # Scapy should handle placing self.context_id and self.message_control_header
        # based on fields_desc before StrLenField.
        # If StrLenField misbehaves, manual packing might be needed here.
        # Assuming Scapy places the ByteFields correctly:
        p = p[:4] + bytes([self.context_id]) + bytes([self.message_control_header]) + self.data

        # Append any potential payload (should normally be empty for PDV)
        return p + pay

    # Add a summary for better display
    def summary(self):
        cmd_data = "Command" if self.is_command else "Data"
        last = "Last" if self.is_last else "More"
        return f"PDV Item (Context: {self.context_id}, {cmd_data}, {last}, Len: {self.length}, DataLen: {len(self.data)})"
class P_DATA_TF(Packet):
    """
    P-DATA-TF PDU (PS3.8 Section 9.3.5)
    Carries one or more Presentation Data Value (PDV) items.
    """
    name = "P-DATA-TF"
    fields_desc = [
        # The payload of this PDU consists of one or more concatenated PDV Items
        PacketListField("pdv_items", [], PresentationDataValueItem,
                        length_from=lambda pkt: pkt.underlayer.length)
    ]

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
        """Build PresentationContextRQItems from a dict."""
        pc_items = []
        current_context_id = self.next_context_id
        for abstract_syntax, transfer_syntaxes in requested_contexts.items():
            if not isinstance(transfer_syntaxes, list):
                transfer_syntaxes = [transfer_syntaxes]

            abs_syntax_item = AbstractSyntaxSubItem(abstract_syntax_uid=abstract_syntax)
            trn_syntax_items = [TransferSyntaxSubItem(transfer_syntax_uid=ts) for ts in transfer_syntaxes]

            # Pack sub-items into the data field manually for PresentationContextRQItem
            sub_items_bytes = bytes(abs_syntax_item) + b"".join(bytes(ts) for ts in trn_syntax_items)
            data_len = 4 + len(sub_items_bytes)

            pc_item_bytes = struct.pack("!BBH", 0x20, 0, data_len) # Type, Res, Len
            pc_item_bytes += struct.pack("!BBBB", current_context_id, 0, 0, 0) # CtxID, Res, Res, Res
            pc_item_bytes += sub_items_bytes

            # Create the packet object by parsing bytes (simpler than complex post_build)
            # We use the generic DICOMVariableItem for this construction method
            pc_item = DICOMVariableItem(pc_item_bytes)
            pc_items.append(pc_item)

            # Increment context ID (must be odd)
            current_context_id += 2
        self.next_context_id = current_context_id # Update for next potential use
        return pc_items


    def _build_user_information(self, role_selection=None):
        """Build the UserInformationItem with standard sub-items."""
        sub_items = [
            MaxLengthSubItem(max_length_received=self.max_pdu_length),
            ImplementationClassUIDSubItem(implementation_class_uid=self.implementation_class_uid),
            ImplementationVersionNameSubItem(implementation_version_name=self.implementation_version_name)
        ]

        # Add Async Operations Window (optional, often included)
        sub_items.append(AsyncOperationsWindowSubItem())

        # Add Role Selection if provided
        if role_selection:
            # Ensure role_selection is a list of SCUSCPRoleSelectionSubItem objects or tuples
            if not isinstance(role_selection, list):
                 role_selection = [role_selection] # Allow single item

            for role in role_selection:
                if isinstance(role, tuple) and len(role) >= 3:
                    # Assume tuple is (sop_class_uid, scu_role, scp_role)
                    sub_items.append(SCUSCPRoleSelectionSubItem(
                        sop_class_uid=role[0],
                        scu_role=role[1],
                        scp_role=role[2]
                    ))
                elif isinstance(role, SCUSCPRoleSelectionSubItem):
                     sub_items.append(role)
                else:
                     log.warning(f"Invalid role selection format: {role}. Skipping.")


        # Pack sub-items into the data field manually for UserInformationItem
        user_data_bytes = b"".join(bytes(item) for item in sub_items)
        user_info_bytes = struct.pack("!BBH", 0x50, 0, len(user_data_bytes)) + user_data_bytes

        # Create the packet object by parsing bytes
        user_info_item = DICOMVariableItem(user_info_bytes)
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
        """Parse the A-ASSOCIATE-AC PDU to store negotiated parameters."""
        self.accepted_contexts = {}
        self.peer_max_pdu_length = None # Reset

        for item in ac_pdu.variable_items:
            if item.item_type == 0x21: # Presentation Context AC
                # Need to parse the 'data' field of the PresentationContextACItem manually
                if len(item.data) >= 4:
                    context_id, _, result_reason, _ = struct.unpack("!BBBB", item.data[:4])
                    if result_reason == 0: # Acceptance
                        # Find the Transfer Syntax Sub-item within the remaining data
                        sub_item_data = item.data[4:]
                        if len(sub_item_data) >= 4 and sub_item_data[0] == 0x40: # Transfer Syntax type
                            ts_len = struct.unpack("!H", sub_item_data[2:4])[0]
                            if len(sub_item_data) >= 4 + ts_len:
                                trn_syntax_uid = UIDField("dummy", "").m2i(None, sub_item_data[4:4+ts_len])
                                # Need original abstract syntax - requires matching RQ context ID,
                                # which we don't store directly here. Assume matching for now.
                                # TODO: Improve context matching if needed later
                                log.info(f"Presentation Context ID {context_id} accepted (Transfer Syntax: {trn_syntax_uid})")
                                # Store context_id -> transfer_syntax mapping (abstract syntax unknown here)
                                self.accepted_contexts[context_id] = ("Unknown Abstract Syntax", trn_syntax_uid)
                            else:
                                log.warning(f"Malformed Transfer Syntax sub-item in AC context {context_id}")
                        else:
                             log.warning(f"No valid Transfer Syntax found in accepted AC context {context_id}")
                    else:
                         log.info(f"Presentation Context ID {context_id} rejected/failed (Reason: {result_reason})")

            elif item.item_type == 0x50: # User Information
                 # Parse User Info sub-items within the 'data' field
                 user_data = item.data
                 offset = 0
                 while offset < len(user_data):
                     if offset + 4 > len(user_data): break # Need type, res, len
                     sub_type, _, sub_len = struct.unpack("!BBH", user_data[offset:offset+4])
                     if offset + 4 + sub_len > len(user_data):
                         log.warning("Malformed User Information sub-item structure in AC.")
                         break
                     sub_item_payload = user_data[offset+4 : offset+4+sub_len]

                     if sub_type == 0x51: # Max Length
                         if sub_len == 4:
                             self.peer_max_pdu_length = struct.unpack("!I", sub_item_payload)[0]
                             log.info(f"Peer maximum PDU length: {self.peer_max_pdu_length}")
                         else:
                              log.warning("Invalid length for Max Length sub-item in AC.")
                     # Could parse other items like Impl Class UID if needed

                     offset += (4 + sub_len)


    def send_p_data(self, pdv_list):
        """
        Sends one or more PDVs in a P-DATA-TF PDU.

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

        p_data_tf_pdu = P_DATA_TF(pdv_items=pdv_list)
        dicom_pkt = DICOM(pdu_type=0x04) / p_data_tf_pdu

        # Check PDU size against peer's max length if known
        total_len = len(bytes(dicom_pkt))
        if self.peer_max_pdu_length and total_len > self.peer_max_pdu_length:
            log.error(f"PDU size ({total_len} bytes) exceeds peer maximum ({self.peer_max_pdu_length} bytes). Cannot send.")
            # In a real application, you would fragment the data across multiple P-DATA-TFs
            return False

        log.info(f"Sending P-DATA-TF ({len(pdv_list)} PDV(s))")
        log.debug(f"P-DATA-TF Details:\n{dicom_pkt.show(dump=True)}")

        try:
            self.stream.send(dicom_pkt)
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


# --- Example Usage (Optional) ---
if __name__ == '__main__':
    # Configure logging for Scapy and this script
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    # Uncomment to see detailed Scapy layer info:
    # logging.getLogger("scapy.runtime").setLevel(logging.DEBUG)
    # logging.getLogger("scapy.contrib.dicom").setLevel(logging.DEBUG)


    # --- Example 1: Build and Show an A-ASSOCIATE-RQ ---
    print("\n--- Example 1: Building A-ASSOCIATE-RQ ---")
    # Presentation Context: Verification SOP Class, Implicit VR LE Transfer Syntax
    abs_syn = AbstractSyntaxSubItem(abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID)
    trn_syn = TransferSyntaxSubItem(transfer_syntax_uid=DEFAULT_TRANSFER_SYNTAX_UID)
    pc_data = struct.pack("!BBBB", 1, 0, 0, 0) + bytes(abs_syn) + bytes(trn_syn) # CtxID=1, Res, Res, Res + Items
    pc_item = DICOMVariableItem(item_type=0x20, data=pc_data)

    # User Info: Max Length, Impl Class UID, Impl Version Name
    max_len_item = MaxLengthSubItem(max_length_received=32768)
    impl_uid_item = ImplementationClassUIDSubItem()
    impl_ver_item = ImplementationVersionNameSubItem()
    user_data = bytes(max_len_item) + bytes(impl_uid_item) + bytes(impl_ver_item)
    user_info_item = DICOMVariableItem(item_type=0x50, data=user_data)

    # Application Context
    app_context_item = DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID))

    # A-ASSOCIATE-RQ Packet
    assoc_rq = A_ASSOCIATE_RQ(
        calling_ae_title=_pad_ae_title("MY_SCU"),
        called_ae_title=_pad_ae_title("ORTHANC_SCP"),
        variable_items=[app_context_item, pc_item, user_info_item]
    )
    dicom_rq = DICOM() / assoc_rq # Length calculated automatically
    dicom_rq.show()
    print("Raw bytes:")
    # hexdump(dicom_rq) # Uncomment for byte dump

    # --- Example 2: Dissect Raw A-ASSOCIATE-AC Bytes (Simulated) ---
    print("\n--- Example 2: Dissecting A-ASSOCIATE-AC ---")
    # Construct sample AC bytes (simplified)
    # Variable items: App Ctx, Pres Ctx AC (ID=1, Accept, Default TS), User Info (Max Len)
    ac_app_ctx = bytes(DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID)))
    ac_trn_syn = bytes(TransferSyntaxSubItem(transfer_syntax_uid=DEFAULT_TRANSFER_SYNTAX_UID))
    ac_pc_data = struct.pack("!BBBB", 1, 0, 0, 0) + ac_trn_syn # CtxID=1, Res, Result=Accept, Res + TS Item
    ac_pc_item = bytes(DICOMVariableItem(item_type=0x21, data=ac_pc_data))
    ac_max_len = bytes(MaxLengthSubItem(max_length_received=16384))
    ac_user_info_data = ac_max_len
    ac_user_info = bytes(DICOMVariableItem(item_type=0x50, data=ac_user_info_data))
    ac_var_items = ac_app_ctx + ac_pc_item + ac_user_info

    ac_header = struct.pack("!HH", 1, 0) # Protocol Ver, Res
    ac_aes = _pad_ae_title("ORTHANC_SCP") + _pad_ae_title("MY_SCU") # Called, Calling
    ac_res = b'\x00' * 32

    ac_payload = ac_header + ac_aes + ac_res + ac_var_items
    ac_pdu = struct.pack("!BB", 0x02, 0) + struct.pack("!I", len(ac_payload)) + ac_payload
    # ac_pdu = b'\x02\x00\x00\x00\x00\xc2\x00\x01\x00\x00ORTHANC_SCP     MY_SCU          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x1a1.2.840.10008.3.1.1.1\x00!\x00\x00\x18\x01\x00\x00\x00@\x00\x00\x121.2.840.10008.1.2\x00P\x00\x00\x08Q\x00\x00\x04\x00\x00@\x00'

    print("Raw AC bytes (simulated):")
    # hexdump(ac_pdu) # Uncomment for byte dump
    dissected_ac = DICOM(ac_pdu)
    dissected_ac.show()

    # --- Example 3: Basic C-ECHO using DICOMSession (Requires a DICOM SCP) ---
    # print("\n--- Example 3: C-ECHO Test (Requires running SCP) ---")
    # scp_ip = "127.0.0.1" # Replace with your SCP's IP
    # scp_port = 11112      # Replace with your SCP's port
    # scp_ae = "ANY_SCP"    # Replace with your SCP's AE Title

    # session = DICOMSession(dst_ip=scp_ip, dst_port=scp_port, dst_ae=scp_ae, src_ae="SCAPY_ECHO")

    # # Define context for Verification SOP Class
    # verification_context = {
    #     VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
    # }

    # if session.associate(requested_contexts=verification_context):
    #     print("Association established!")

    #     # Construct a C-ECHO-RQ DIMSE message (very simplified example)
    #     # A real implementation needs a full DIMSE layer
    #     # Tag (0000,0002) Affected SOP Class UID
    #     # Tag (0000,0100) Command Field (C-ECHO-RQ = 0x0030)
    #     # Tag (0000,0110) Message ID
    #     # Tag (0000,0900) Command Data Set Type (0x0101 = No dataset)
    #     # All Implicit VR Little Endian for this example
    #     # Group Length (0000,0000) UL value=??
    #     # Note: Calculating Group 0 length requires knowing the full command structure
    #     # We will omit group length for this basic example, which might not be strictly compliant

    #     # Simplistic C-ECHO RQ payload (missing Group 0 Length, may fail on strict SCPs)
    #     # Using Implicit VR Little Endian encoding manually
    #     cmd_sop_class = b'\x00\x00\x02\x00' + b'UI' + struct.pack("<H", len(_uid_to_bytes(VERIFICATION_SOP_CLASS_UID))) + _uid_to_bytes(VERIFICATION_SOP_CLASS_UID)
    #     cmd_field = b'\x00\x00\x00\x01' + b'US' + struct.pack("<H", 2) + struct.pack("<H", 0x0030) # Command Field C-ECHO-RQ
    #     cmd_msg_id = b'\x00\x00\x10\x01' + b'US' + struct.pack("<H", 2) + struct.pack("<H", 1) # Message ID 1
    #     cmd_dataset_type = b'\x00\x00\x00\x08' + b'US' + struct.pack("<H", 2) + struct.pack("<H", 0x0101) # No Dataset
    #     # Calculate Group Length (0000,0000)
    #     group0_payload = cmd_sop_class + cmd_field + cmd_msg_id + cmd_dataset_type
    #     group0_len_field = b'\x00\x00\x00\x00' + b'UL' + struct.pack("<H", 4) + struct.pack("<I", len(group0_payload))
    #     c_echo_rq_bytes = group0_len_field + group0_payload

    #     # Find accepted context ID for Verification
    #     echo_ctx_id = None
    #     for ctx_id, (abs_syntax, _) in session.accepted_contexts.items():
    #         # Need a way to match the Abstract Syntax UID used in the RQ
    #         # For now, assume context ID 1 was accepted for Verification
    #         # A real system would store the original requested Abstract Syntax per context ID
    #         if ctx_id == 1: # HACK: Assume ctx 1 is Verification
    #              echo_ctx_id = 1
    #              break

    #     if echo_ctx_id:
    #         pdv = PresentationDataValueItem(
    #             context_id=echo_ctx_id,
    #             is_command=1, # This is a command
    #             is_last=1,    # This is the only fragment
    #             data=c_echo_rq_bytes
    #         )
    #         if session.send_p_data([pdv]):
    #             print("C-ECHO-RQ sent via P-DATA-TF.")
    #             # In a real C-ECHO, you would wait for a P-DATA-TF response containing C-ECHO-RSP
    #             print("Waiting for response (not implemented in this example)...")
    #             # Add recv logic here if needed
    #             try:
    #                 response_pdata = session.stream.recv()
    #                 if response_pdata and response_pdata.haslayer(P_DATA_TF):
    #                     print("Received P-DATA-TF response (likely C-ECHO-RSP)")
    #                     response_pdata.show()
    #                     # Further parsing of the PDV data (DIMSE layer) needed here
    #                 elif response_pdata:
    #                     print(f"Received unexpected response: {response_pdata.summary()}")
    #                 else:
    #                     print("No response data received.")
    #             except socket.timeout:
    #                 print("Timeout waiting for C-ECHO response.")
    #             except Exception as e_recv:
    #                 print(f"Error receiving C-ECHO response: {e_recv}")

    #     else:
    #         print("Could not find an accepted Presentation Context for Verification SOP Class.")

    #     session.release()
    # else:
    #     print("Association failed.")