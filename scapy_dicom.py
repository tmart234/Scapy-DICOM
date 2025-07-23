# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
# pylint: disable=attribute-defined-outside-init

import struct
import time
import socket
import logging
from io import BytesIO

from scapy.all import Packet, bind_layers, PacketListField
from scapy.fields import (
    ByteEnumField, ByteField, ShortField, IntField, FieldLenField,
    StrFixedLenField, StrLenField
)
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket
from scapy.packet import NoPayload, Raw

log = logging.getLogger("scapy.contrib.dicom")
if not log.handlers:
    logging.basicConfig(level=logging.INFO)

# --- Constants & Helpers ---
DICOM_PORT = 104
APP_CONTEXT_UID = "1.2.840.10008.3.1.1.1"
DEFAULT_TRANSFER_SYNTAX_UID = "1.2.840.10008.1.2"
VERIFICATION_SOP_CLASS_UID = "1.2.840.10008.1.1"
CT_IMAGE_STORAGE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.2"

def _pad_ae_title(title):
    if isinstance(title, bytes): return title.ljust(16, b' ')
    return title.ljust(16).encode('ascii')

def _uid_to_bytes(uid):
    if isinstance(uid, bytes): b_uid = uid
    elif isinstance(uid, str): b_uid = uid.encode('ascii')
    else: return b''
    if len(b_uid) % 2 != 0: b_uid += b'\x00'
    return b_uid

# --- DIMSE Builders ---
def build_c_echo_rq_dimse(message_id=1):
    elements = [
        (0x0000, 0x0002, _uid_to_bytes(VERIFICATION_SOP_CLASS_UID)),
        (0x0000, 0x0100, struct.pack('<H', 0x0030)),
        (0x0000, 0x0110, struct.pack('<H', message_id)),
        (0x0000, 0x0800, struct.pack('<H', 0x0101)),
    ]
    payload = b"".join(struct.pack('<HH', g, e) + struct.pack('<I', len(v)) + v for g, e, v in elements)
    group_len = len(payload)
    return struct.pack('<HHI', 0x0000, 0x0000, 4) + struct.pack('<I', group_len) + payload

def build_c_store_rq_dimse(sop_class_uid, sop_instance_uid, message_id=1):
    elements = [
        (0x0000, 0x0002, _uid_to_bytes(sop_class_uid)),
        (0x0000, 0x0100, struct.pack('<H', 0x0001)),
        (0x0000, 0x0110, struct.pack('<H', message_id)),
        (0x0000, 0x0700, struct.pack('<H', 0x0002)), # Priority MEDIUM
        (0x0000, 0x0800, struct.pack('<H', 0x0101)), # Dataset type: No dataset in command
        (0x0000, 0x1000, _uid_to_bytes(sop_instance_uid)),
    ]
    payload = b"".join(struct.pack('<HH', g, e) + struct.pack('<I', len(v)) + v for g, e, v in elements)
    group_len = len(payload)
    return struct.pack('<HHI', 0x0000, 0x0000, 4) + struct.pack('<I', group_len) + payload

def parse_dimse_status(dimse_bytes):
    try:
        if len(dimse_bytes) < 12: return None
        cmd_group_len = struct.unpack("<I", dimse_bytes[8:12])[0]
        offset = 12
        group_end_offset = offset + cmd_group_len
        while offset < group_end_offset and offset + 8 <= len(dimse_bytes):
            tag_group, tag_elem = struct.unpack("<HH", dimse_bytes[offset:offset+4])
            value_len = struct.unpack("<I", dimse_bytes[offset+4:offset+8])[0]
            if tag_group == 0x0000 and tag_elem == 0x0900 and value_len == 2:
                return struct.unpack("<H", dimse_bytes[offset+8:offset+10])[0]
            offset += 8 + value_len
    except Exception: return None
    return None

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

# FIX: Restored manual dissect/build methods for this complex packet.
class A_ASSOCIATE_RQ(Packet):
    name = "A-ASSOCIATE-RQ"
    fields_desc = [
        ShortField("protocol_version", 1), ShortField("reserved1", 0),
        StrFixedLenField("called_ae_title", b"", 16),
        StrFixedLenField("calling_ae_title", b"", 16),
        StrFixedLenField("reserved2", b"\x00"*32, 32),
    ]
    def __init__(self, *args, **kwargs):
        self.variable_items = kwargs.pop('variable_items', [])
        super(A_ASSOCIATE_RQ, self).__init__(*args, **kwargs)

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
        if remaining_bytes: self.payload = Raw(remaining_bytes)

    def do_build_payload(self):
        return b"".join(bytes(item) for item in self.variable_items)

class A_ASSOCIATE_AC(A_ASSOCIATE_RQ):
    name = "A-ASSOCIATE-AC"

class A_ASSOCIATE_RJ(Packet): name = "A-ASSOCIATE-RJ"; fields_desc = [ByteField("reserved1", 0), ByteField("result", 1), ByteField("source", 1), ByteField("reason_diag", 1)]

# FIX: Redefined PresentationDataValueItem as a proper Scapy Packet with real fields.
class PresentationDataValueItem(Packet):
    name = "PresentationDataValueItem"
    fields_desc = [
        FieldLenField("length", None, length_of="data", fmt="!I", adjust=lambda pkt, x: x + 2),
        ByteField("context_id", 1),
        ByteField("message_control_header", 0x03),
        StrLenField("data", "", length_from=lambda pkt: pkt.length - 2)
    ]
    def __init__(self, *args, **kwargs):
        is_command_kw = kwargs.pop('is_command', None)
        is_last_kw = kwargs.pop('is_last', None)
        super(PresentationDataValueItem, self).__init__(*args, **kwargs)
        if is_command_kw is not None: self.is_command = is_command_kw
        if is_last_kw is not None: self.is_last = is_last_kw
    is_command = property(
        lambda self: (self.message_control_header & 0x01) == 1,
        lambda self, v: setattr(self, 'message_control_header', (self.message_control_header & ~0x01) | (0x01 if v else 0x00))
    )
    is_last = property(
        lambda self: (self.message_control_header >> 1 & 0x01) == 1,
        lambda self, v: setattr(self, 'message_control_header', (self.message_control_header & ~0x02) | (0x02 if v else 0x00))
    )

class P_DATA_TF(Packet):
    name = "P-DATA-TF"
    fields_desc = [
        PacketListField("pdv_items", [], PresentationDataValueItem,
                        length_from=lambda pkt: pkt.underlayer.length)
    ]

class A_RELEASE_RQ(Packet): name = "A-RELEASE-RQ"; fields_desc = [IntField("reserved1", 0)]
class A_RELEASE_RP(Packet): name = "A-RELEASE-RP"; fields_desc = [IntField("reserved1", 0)]
class A_ABORT(Packet): name = "A-ABORT"; fields_desc = [ByteField("reserved1", 0), ByteField("reserved2", 0), ByteField("source", 0), ByteField("reason_diag", 0)]

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
    def __init__(self, dst_ip, dst_port, dst_ae, src_ae="SCAPY_SCU", read_timeout=10):
        self.dst_ip, self.dst_port = dst_ip, dst_port
        self.dst_ae, self.src_ae = _pad_ae_title(dst_ae), _pad_ae_title(src_ae)
        self.sock, self.stream, self.assoc_established = None, None, False
        self.accepted_contexts = {}
        self.read_timeout = read_timeout
        self._current_message_id_counter = int(time.time()) % 50000
    def connect(self):
        try:
            self.sock = socket.create_connection((self.dst_ip, self.dst_port), timeout=self.read_timeout)
            self.stream = StreamSocket(self.sock, basecls=DICOM)
            return True
        except Exception:
            return False

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
        
        assoc_rq_payload = A_ASSOCIATE_RQ(called_ae_title=self.dst_ae, calling_ae_title=self.src_ae)
        assoc_rq_payload.variable_items = variable_items
        assoc_rq = DICOM() / assoc_rq_payload
        
        response = self.stream.sr1(assoc_rq, timeout=self.read_timeout, verbose=0)

        if response and response.haslayer(A_ASSOCIATE_AC):
            self.assoc_established = True
            for item in response[A_ASSOCIATE_AC].variable_items:
                if item.item_type == 0x21 and item.data[2] == 0:
                    ctx_id = item.data[0]
                    abs_syntax_key_list = list(requested_contexts.keys())
                    key_index = (ctx_id - 1) // 2
                    if key_index < len(abs_syntax_key_list):
                        abs_syntax = abs_syntax_key_list[key_index]
                        ts_item_data = item.data[4:]
                        if len(ts_item_data) > 4:
                            ts_uid = DICOMVariableItem(ts_item_data).data.rstrip(b'\x00').decode()
                            self.accepted_contexts[ctx_id] = (abs_syntax, ts_uid)
            return True
        log.error(f"Association failed. Response: {response.summary() if response else 'None'}")
        return False

    def _get_next_message_id(self):
        self._current_message_id_counter += 1
        return self._current_message_id_counter & 0xFFFF
        
    def _find_accepted_context_id(self, sop_class_uid, transfer_syntax_uid=None):
        for ctx_id, (abs_syntax, ts_syntax) in self.accepted_contexts.items():
            if abs_syntax == sop_class_uid:
                if transfer_syntax_uid is None or transfer_syntax_uid == ts_syntax:
                    return ctx_id
        return None
        
    def c_echo(self):
        if not self.assoc_established: return None
        echo_ctx_id = self._find_accepted_context_id(VERIFICATION_SOP_CLASS_UID)
        if echo_ctx_id is None: return None
        
        msg_id = self._get_next_message_id()
        dimse_rq = build_c_echo_rq_dimse(msg_id)
        pdv_rq = PresentationDataValueItem(context_id=echo_ctx_id, data=dimse_rq, is_command=True, is_last=True)
        pdata_rq = DICOM() / P_DATA_TF(pdv_items=[pdv_rq])
        
        response = self.stream.sr1(pdata_rq, timeout=self.read_timeout, verbose=0)
        
        if response and response.haslayer(P_DATA_TF) and response[P_DATA_TF].pdv_items:
            pdv_rsp = response[P_DATA_TF].pdv_items[0]
            status = parse_dimse_status(pdv_rsp.data)
            return status
        return None

    def c_store(self, dataset_bytes, sop_class_uid, sop_instance_uid, transfer_syntax_uid):
        if not self.assoc_established: return None
        store_ctx_id = self._find_accepted_context_id(sop_class_uid, transfer_syntax_uid)
        if store_ctx_id is None: return None

        msg_id = self._get_next_message_id()
        dimse_rq = build_c_store_rq_dimse(sop_class_uid, sop_instance_uid, msg_id)
        
        cmd_pdv = PresentationDataValueItem(context_id=store_ctx_id, data=dimse_rq, is_command=True, is_last=False)
        data_pdv = PresentationDataValueItem(context_id=store_ctx_id, data=dataset_bytes, is_command=False, is_last=True)
        pdata_rq = DICOM() / P_DATA_TF(pdv_items=[cmd_pdv, data_pdv])

        response = self.stream.sr1(pdata_rq, timeout=self.read_timeout, verbose=0)

        if response and response.haslayer(P_DATA_TF) and response[P_DATA_TF].pdv_items:
            pdv_rsp = response[P_DATA_TF].pdv_items[0]
            status = parse_dimse_status(pdv_rsp.data)
            return status
        return None
    
    def release(self):
        if not self.assoc_established: return True
        response = self.stream.sr1(DICOM()/A_RELEASE_RQ(), timeout=self.read_timeout, verbose=0)
        self.close()
        return response and response.haslayer(A_RELEASE_RP)

    def close(self):
        if self.stream: self.stream.close()
        self.sock, self.stream, self.assoc_established = None, None, False
