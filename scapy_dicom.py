# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Tyler M

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
from io import BytesIO

from scapy.packet import Packet, NoPayload, bind_layers
from scapy.fields import (
    ByteEnumField,
    ByteField,
    IntField,
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
    # Packet classes
    "DICOM",
    "DICOMVariableItem",
    "A_ASSOCIATE_RQ",
    "A_ASSOCIATE_AC",
    "A_ASSOCIATE_RJ",
    "P_DATA_TF",
    "PresentationDataValueItem",
    "A_RELEASE_RQ",
    "A_RELEASE_RP",
    "A_ABORT",
    "P_DATA_TF",
    "PresentationDataValueItem",
    # Session helper
    "DICOMSession",
    # DIMSE builders
    "build_c_echo_rq_dimse",
    "build_c_store_rq_dimse",
    "parse_dimse_status",
    # Utility functions
    "_pad_ae_title",
    "_uid_to_bytes",
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


# --- Helper Functions ---

def _pad_ae_title(title):
    """Pad an Application Entity title to 16 bytes with spaces."""
    if isinstance(title, bytes):
        return title.ljust(16, b" ")
    return title.ljust(16).encode("ascii")


def _uid_to_bytes(uid):
    """Convert a UID string to bytes, padding to even length if needed."""
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


# --- DIMSE Message Builders ---

def build_c_echo_rq_dimse(message_id=1):
    """
    Build a C-ECHO-RQ DIMSE command message.

    :param message_id: Message ID for the request (default: 1)
    :return: Bytes containing the encoded DIMSE command
    """
    elements = [
        (0x0000, 0x0002, _uid_to_bytes(VERIFICATION_SOP_CLASS_UID)),  # Affected SOP Class
        (0x0000, 0x0100, struct.pack("<H", 0x0030)),  # Command Field: C-ECHO-RQ
        (0x0000, 0x0110, struct.pack("<H", message_id)),  # Message ID
        (0x0000, 0x0800, struct.pack("<H", 0x0101)),  # Data Set Type: No dataset
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


def build_c_store_rq_dimse(sop_class_uid, sop_instance_uid, message_id=1):
    """
    Build a C-STORE-RQ DIMSE command message.

    :param sop_class_uid: SOP Class UID of the object to store
    :param sop_instance_uid: SOP Instance UID of the object to store
    :param message_id: Message ID for the request (default: 1)
    :return: Bytes containing the encoded DIMSE command
    """
    elements = [
        (0x0000, 0x0002, _uid_to_bytes(sop_class_uid)),  # Affected SOP Class
        (0x0000, 0x0100, struct.pack("<H", 0x0001)),  # Command Field: C-STORE-RQ
        (0x0000, 0x0110, struct.pack("<H", message_id)),  # Message ID
        (0x0000, 0x0700, struct.pack("<H", 0x0002)),  # Priority: MEDIUM
        (0x0000, 0x0800, struct.pack("<H", 0x0000)),  # Data Set Type: Dataset present
        (0x0000, 0x1000, _uid_to_bytes(sop_instance_uid)),  # Affected SOP Instance
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
    """
    Parse the Status field from a DIMSE response message.

    :param dimse_bytes: Raw bytes of the DIMSE message
    :return: Status code (int) or None if parsing fails
    """
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


# --- Scapy Packet Definitions ---

class DICOM(Packet):
    """
    DICOM Upper Layer PDU header.

    This is the main PDU wrapper containing type, reserved byte, and length.
    """
    name = "DICOM UL"
    fields_desc = [
        ByteEnumField("pdu_type", 0x01, PDU_TYPES),
        ByteField("reserved1", 0),
        IntField("length", None),
    ]

    def post_build(self, pkt, pay):
        if self.length is None:
            length = len(pay)
            pkt = pkt[:2] + struct.pack("!I", length) + pkt[6:]
        return pkt + pay


class DICOMVariableItem(Packet):
    """
    DICOM Variable Item used in A-ASSOCIATE PDUs.

    Used for Application Context, Presentation Context, and User Information items.
    """
    name = "DICOM Variable Item"
    fields_desc = [
        ByteField("item_type", 0x10),
        ByteField("reserved", 0),
        ShortField("length", None),
        StrLenField("data", b"", length_from=lambda pkt: pkt.length),
    ]

    def post_build(self, pkt, pay):
        if self.length is None:
            length = len(self.data) if self.data else 0
            pkt = pkt[:2] + struct.pack("!H", length) + pkt[4:]
        return pkt + pay


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
        StrLenField(
            "variable_items_payload",
            b"",
            length_from=lambda pkt: pkt.underlayer.length - 68 if pkt.underlayer else 0,
        ),
    ]

    def __init__(self, *args, variable_items=None, **kwargs):
        super().__init__(*args, **kwargs)
        if variable_items is not None:
            self.variable_items = variable_items

    @property
    def variable_items(self):
        """Parse variable_items_payload into a list of DICOMVariableItem packets."""
        items = []
        data = self.variable_items_payload
        if isinstance(data, str):
            data = data.encode("latin-1")
        stream = BytesIO(data)
        while stream.tell() < len(data):
            try:
                header = stream.read(4)
                if len(header) < 4:
                    break
                _, _, item_length = struct.unpack("!BBH", header)
                item_data = stream.read(item_length)
                if len(item_data) < item_length:
                    break
                items.append(DICOMVariableItem(header + item_data))
            except Exception:
                break
        return items

    @variable_items.setter
    def variable_items(self, items_list):
        """Serialize a list of DICOMVariableItem packets to variable_items_payload."""
        self.variable_items_payload = b"".join(bytes(item) for item in items_list)


class A_ASSOCIATE_AC(A_ASSOCIATE_RQ):
    """
    A-ASSOCIATE-AC PDU for accepting an association.

    Has the same structure as A-ASSOCIATE-RQ.
    """
    name = "A-ASSOCIATE-AC"


class A_ASSOCIATE_RJ(Packet):
    """
    A-ASSOCIATE-RJ PDU for rejecting an association.

    Contains result, source, and reason/diagnostic fields.
    """
    name = "A-ASSOCIATE-RJ"
    fields_desc = [
        ByteField("reserved1", 0),
        ByteField("result", 1),
        ByteField("source", 1),
        ByteField("reason_diag", 1),
    ]


class PresentationDataValueItem(Packet):
    """
    Presentation Data Value Item within a P-DATA-TF PDU.

    Contains context ID, message control header, and the actual DIMSE data.
    """
    name = "PresentationDataValueItem"
    fields_desc = [
        IntField("length", None),
        ByteField("context_id", 1),
        ByteField("message_control_header", 0),
        StrLenField(
            "data",
            b"",
            length_from=lambda pkt: pkt.length - 2 if pkt.length is not None else 0,
        ),
    ]

    def __init__(self, *args, is_command=None, is_last=None, **kwargs):
        super().__init__(*args, **kwargs)
        if is_command is not None:
            self.is_command = is_command
        if is_last is not None:
            self.is_last = is_last

    def post_build(self, pkt, pay):
        if self.length is None:
            data = self.data
            if isinstance(data, str):
                data = data.encode("latin-1")
            length = 2 + len(data)
            pkt = struct.pack("!I", length) + pkt[4:]
        return pkt + pay

    def guess_payload_class(self, payload):
        return NoPayload

    @property
    def is_command(self):
        """True if this PDV contains a command message (bit 0)."""
        return (self.message_control_header & 0x01) == 1

    @is_command.setter
    def is_command(self, value):
        if value:
            self.message_control_header |= 0x01
        else:
            self.message_control_header &= ~0x01

    @property
    def is_last(self):
        """True if this is the last fragment of the message (bit 1)."""
        return (self.message_control_header & 0x02) == 0x02

    @is_last.setter
    def is_last(self, value):
        if value:
            self.message_control_header |= 0x02
        else:
            self.message_control_header &= ~0x02


class P_DATA_TF(Packet):
    """
    P-DATA-TF PDU for transferring presentation data.

    Contains one or more Presentation Data Value Items.
    """
    name = "P-DATA-TF"
    fields_desc = [
        StrLenField(
            "pdv_items_payload",
            b"",
            length_from=lambda pkt: pkt.underlayer.length if pkt.underlayer else 0,
        ),
    ]

    def __init__(self, *args, pdv_items=None, **kwargs):
        super().__init__(*args, **kwargs)
        if pdv_items is not None:
            self.pdv_items = pdv_items

    @property
    def pdv_items(self):
        """Parse pdv_items_payload into a list of PresentationDataValueItem packets."""
        items = []
        data = self.pdv_items_payload
        if isinstance(data, str):
            data = data.encode("latin-1")
        while data:
            item = PresentationDataValueItem(data)
            items.append(item)
            if item.length is None or item.length <= 0:
                break
            item_total_size = 4 + item.length
            if item_total_size > len(data):
                break
            data = data[item_total_size:]
        return items

    @pdv_items.setter
    def pdv_items(self, items_list):
        """Serialize a list of PresentationDataValueItem packets to pdv_items_payload."""
        self.pdv_items_payload = b"".join(bytes(item) for item in items_list)


class A_RELEASE_RQ(Packet):
    """A-RELEASE-RQ PDU for requesting association release."""
    name = "A-RELEASE-RQ"
    fields_desc = [IntField("reserved1", 0)]


class A_RELEASE_RP(Packet):
    """A-RELEASE-RP PDU for confirming association release."""
    name = "A-RELEASE-RP"
    fields_desc = [IntField("reserved1", 0)]


class A_ABORT(Packet):
    """A-ABORT PDU for aborting an association."""
    name = "A-ABORT"
    fields_desc = [
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteField("source", 0),
        ByteField("reason_diag", 0),
    ]


# --- Layer Bindings ---
bind_layers(TCP, DICOM, dport=DICOM_PORT)
bind_layers(TCP, DICOM, sport=DICOM_PORT)
bind_layers(DICOM, A_ASSOCIATE_RQ, pdu_type=0x01)
bind_layers(DICOM, A_ASSOCIATE_AC, pdu_type=0x02)
bind_layers(DICOM, A_ASSOCIATE_RJ, pdu_type=0x03)
bind_layers(DICOM, P_DATA_TF, pdu_type=0x04)
bind_layers(DICOM, A_RELEASE_RQ, pdu_type=0x05)
bind_layers(DICOM, A_RELEASE_RP, pdu_type=0x06)
bind_layers(DICOM, A_ABORT, pdu_type=0x07)


# --- DICOM Session Helper Class ---

class DICOMSession:
    """
    High-level helper class for DICOM network operations.

    Provides methods for association establishment, C-ECHO, C-STORE,
    and graceful release.

    Example usage::

        session = DICOMSession("192.168.1.100", 104, "TARGET_AE")
        if session.associate():
            status = session.c_echo()
            print(f"C-ECHO status: {status}")
            session.release()
    """

    def __init__(self, dst_ip, dst_port, dst_ae, src_ae="SCAPY_SCU", read_timeout=10):
        """
        Initialize a DICOM session.

        :param dst_ip: Destination IP address
        :param dst_port: Destination port (typically 104 or 11112)
        :param dst_ae: Destination Application Entity title
        :param src_ae: Source Application Entity title (default: "SCAPY_SCU")
        :param read_timeout: Socket read timeout in seconds (default: 10)
        :param max_pdu_length: Maximum PDU length to propose (default: 16384)
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
        self.max_pdu_length = 16384  # Will be updated during association

    def connect(self):
        """
        Establish TCP connection to the DICOM server.

        :return: True if connection successful, False otherwise
        """
        try:
            self.sock = socket.create_connection(
                (self.dst_ip, self.dst_port),
                timeout=self.read_timeout,
            )
            self.stream = StreamSocket(self.sock, basecls=DICOM)
            return True
        except Exception as e:
            log.error("Connection failed: %s", e)
            return False

    def _recv_pdu(self):
        """
        Receive a complete DICOM PDU from the socket.

        Reads the 6-byte PDU header first to get the length,
        then reads the complete PDU payload.

        :return: Complete PDU bytes or None on error/timeout
        """
        try:
            # Read PDU header (6 bytes: type, reserved, length)
            header = b""
            while len(header) < 6:
                chunk = self.sock.recv(6 - len(header))
                if not chunk:
                    return None
                header += chunk

            # Parse length from header (bytes 2-6, big-endian)
            pdu_length = struct.unpack("!I", header[2:6])[0]

            # Read PDU payload
            payload = b""
            while len(payload) < pdu_length:
                chunk = self.sock.recv(pdu_length - len(payload))
                if not chunk:
                    return None
                payload += chunk

            return header + payload
        except socket.timeout:
            return None
        except Exception as e:
            log.error("Error receiving PDU: %s", e)
            return None

    def _send_pdu(self, pkt):
        """Send a DICOM PDU packet."""
        self.sock.sendall(bytes(pkt))

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

        # Build variable items
        variable_items = [
            DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID))
        ]

        # Build presentation contexts
        ctx_id = 1
        for abs_syntax, trn_syntaxes in requested_contexts.items():
            sub_items_data = bytes(
                DICOMVariableItem(item_type=0x30, data=_uid_to_bytes(abs_syntax))
            )
            for ts in trn_syntaxes:
                sub_items_data += bytes(
                    DICOMVariableItem(item_type=0x40, data=_uid_to_bytes(ts))
                )
            variable_items.append(
                DICOMVariableItem(
                    item_type=0x20,
                    data=struct.pack("!BBBB", ctx_id, 0, 0, 0) + sub_items_data,
                )
            )
            ctx_id += 2

        # User information item with max PDU length
        user_info_data = bytes(
            DICOMVariableItem(item_type=0x51, data=struct.pack("!I", 16384))
        )
        variable_items.append(DICOMVariableItem(item_type=0x50, data=user_info_data))

        # Build and send A-ASSOCIATE-RQ
        assoc_rq = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.dst_ae,
            calling_ae_title=self.src_ae,
            variable_items=variable_items,
        )

        self._send_pdu(assoc_rq)
        response_data = self._recv_pdu()

        if response_data:
            response = DICOM(response_data)
            if response.haslayer(A_ASSOCIATE_AC):
                self.assoc_established = True
                self._parse_accepted_contexts(response, requested_contexts)
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
                # User Information item (0x50)
                if item.item_type == 0x50:
                    user_data = item.data
                    if isinstance(user_data, str):
                        user_data = user_data.encode("latin-1")
                    # Parse sub-items within User Information
                    offset = 0
                    while offset < len(user_data) - 4:
                        sub_type = user_data[offset]
                        sub_len = struct.unpack("!H", user_data[offset + 2:offset + 4])[0]
                        # Max PDU Length sub-item (0x51)
                        if sub_type == 0x51 and sub_len == 4:
                            server_max = struct.unpack(
                                "!I", user_data[offset + 4:offset + 8]
                            )[0]
                            # Use minimum of what we proposed and server accepts
                            self.max_pdu_length = min(self._proposed_max_pdu, server_max)
                            log.debug("Negotiated max PDU length: %d", self.max_pdu_length)
                            return
                        offset += 4 + sub_len
        except Exception as e:
            log.debug("Could not parse max PDU length: %s", e)
        # Keep default if parsing fails
        self.max_pdu_length = self._proposed_max_pdu

    def _parse_accepted_contexts(self, response, requested_contexts):
        """Parse accepted presentation contexts from A-ASSOCIATE-AC."""
        for item in response[A_ASSOCIATE_AC].variable_items:
            # Presentation Context Accept item (0x21)
            if item.item_type == 0x21:
                item_data = item.data
                if isinstance(item_data, str):
                    item_data = item_data.encode("latin-1")
                if len(item_data) < 4:
                    continue
                ctx_id = item_data[0]
                result = item_data[2]
                if result != 0:  # Not accepted
                    continue
                # Find corresponding abstract syntax
                abs_syntax_key_list = list(requested_contexts.keys())
                key_index = (ctx_id - 1) // 2
                if key_index >= len(abs_syntax_key_list):
                    continue
                abs_syntax = abs_syntax_key_list[key_index]
                # Parse transfer syntax from sub-item
                ts_item_data = item_data[4:]
                if len(ts_item_data) > 4:
                    ts_item = DICOMVariableItem(ts_item_data)
                    ts_data = ts_item.data
                    if isinstance(ts_data, str):
                        ts_data = ts_data.encode("latin-1")
                    ts_uid = ts_data.rstrip(b"\x00").decode("ascii")
                    self.accepted_contexts[ctx_id] = (abs_syntax, ts_uid)

    def _get_next_message_id(self):
        """Get the next message ID for DIMSE commands."""
        self._current_message_id_counter += 1
        return self._current_message_id_counter & 0xFFFF

    def _find_accepted_context_id(self, sop_class_uid, transfer_syntax_uid=None):
        """
        Find an accepted presentation context ID for the given SOP Class.

        :param sop_class_uid: SOP Class UID to find
        :param transfer_syntax_uid: Optional specific Transfer Syntax UID
        :return: Context ID if found, None otherwise
        """
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
        dimse_rq = build_c_echo_rq_dimse(msg_id)
        pdv_rq = PresentationDataValueItem(
            context_id=echo_ctx_id,
            data=dimse_rq,
            is_command=True,
            is_last=True,
        )
        pdata_rq = DICOM() / P_DATA_TF(pdv_items=[pdv_rq])

        self._send_pdu(pdata_rq)
        response_data = self._recv_pdu()

        if response_data:
            response = DICOM(response_data)
            if response.haslayer(P_DATA_TF):
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
        dimse_rq = build_c_store_rq_dimse(sop_class_uid, sop_instance_uid, msg_id)

        # Command PDV (is_last=True means last fragment of command)
        cmd_pdv = PresentationDataValueItem(
            context_id=store_ctx_id,
            data=dimse_rq,
            is_command=True,
            is_last=True,
        )
        pdata_cmd = DICOM() / P_DATA_TF(pdv_items=[cmd_pdv])
        self._send_pdu(pdata_cmd)

        # Fragment data if it exceeds max PDV size
        # Max PDV data = max_pdu_length - 6 (PDV item header: 4 len + 1 ctx + 1 flags)
        # Use conservative margin for safety
        max_pdv_data = self.max_pdu_length - 12  # Extra margin for safety

        if len(dataset_bytes) <= max_pdv_data:
            # Data fits in single PDU
            data_pdv = PresentationDataValueItem(
                context_id=store_ctx_id,
                data=dataset_bytes,
                is_command=False,
                is_last=True,
            )
            pdata_data = DICOM() / P_DATA_TF(pdv_items=[data_pdv])
            self._send_pdu(pdata_data)
        else:
            # Fragment data across multiple PDUs
            offset = 0
            while offset < len(dataset_bytes):
                chunk = dataset_bytes[offset:offset + max_pdv_data]
                is_last = (offset + len(chunk) >= len(dataset_bytes))
                data_pdv = PresentationDataValueItem(
                    context_id=store_ctx_id,
                    data=chunk,
                    is_command=False,
                    is_last=is_last,
                )
                pdata_data = DICOM() / P_DATA_TF(pdv_items=[data_pdv])
                self._send_pdu(pdata_data)
                offset += len(chunk)
            log.debug(
                "Fragmented %d bytes into %d PDUs",
                len(dataset_bytes),
                (len(dataset_bytes) + max_pdv_data - 1) // max_pdv_data,
            )

        response_data = self._recv_pdu()

        if response_data:
            response = DICOM(response_data)
            if response.haslayer(P_DATA_TF):
                pdv_items = response[P_DATA_TF].pdv_items
                if pdv_items:
                    pdv_rsp = pdv_items[0]
                    data = pdv_rsp.data
                    if isinstance(data, str):
                        data = data.encode("latin-1")
                    return parse_dimse_status(data)
        return None

    def release(self):
        """
        Request graceful release of the association.

        :return: True if release confirmed, False otherwise
        """
        if not self.assoc_established:
            return True

        release_rq = DICOM() / A_RELEASE_RQ()
        self._send_pdu(release_rq)
        response_data = self._recv_pdu()
        self.close()

        if response_data:
            response = DICOM(response_data)
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


if __name__ == "__main__":
    # Simple test/example
    import sys

    if len(sys.argv) < 3:
        print("Usage: python dicom.py <ip> <ae_title> [port]")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_ae = sys.argv[2]
    target_port = int(sys.argv[3]) if len(sys.argv) > 3 else DICOM_PORT

    print(f"Testing DICOM connection to {target_ip}:{target_port} (AE: {target_ae})")

    session = DICOMSession(target_ip, target_port, target_ae)
    if session.associate():
        print("Association established successfully")
        status = session.c_echo()
        if status == 0:
            print("C-ECHO successful (status=0)")
        else:
            print(f"C-ECHO returned status: {status}")
        session.release()
        print("Association released")
    else:
        print("Association failed")        