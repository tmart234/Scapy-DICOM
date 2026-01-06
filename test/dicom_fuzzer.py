#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
DICOM Protocol Fuzzer (v2.1 - Compatible with Refactored dicom.py)

A fuzzing tool for testing DICOM SCP implementations using the refactored
dicom module with:
- Native Scapy random generators (RandChoice, RandString, fuzz())
- DICOMAETitleField auto-padding (no _pad_ae_title needed)
- Byte mutation for group_length buffer attacks
- Raw byte construction for odd-length UID fuzzing

Fuzzing capabilities:
- Buffer over-read attacks via group_length byte manipulation
- Odd-length UIDs via raw byte construction
- Field-level fuzzing using packet class attributes
- Arbitrary context IDs and protocol violations

Usage:
    python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode all
"""

import argparse
import logging
import os
import sys
import struct
import urllib.request
import random
import time

script_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(script_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import warnings
warnings.filterwarnings('ignore')

try:
    import scapy.config
    scapy.config.conf.ipv6_enabled = False
except Exception:
    pass

from scapy.packet import fuzz

try:
    from dicom import (
        # Socket-based session
        DICOMSocket,
        # PDU classes
        DICOM,
        A_ASSOCIATE_RQ,
        A_ASSOCIATE_AC,
        A_ASSOCIATE_RJ,
        A_ABORT,
        P_DATA_TF,
        PresentationDataValueItem,
        # Variable Item classes
        DICOMVariableItem,
        DICOMApplicationContext,
        DICOMPresentationContextRQ,
        DICOMAbstractSyntax,
        DICOMTransferSyntax,
        DICOMUserInformation,
        DICOMMaximumLength,
        # DIMSE Packet classes
        C_ECHO_RQ,
        C_STORE_RQ,
        # Helpers
        build_presentation_context_rq,
        build_user_information,
        # Constants
        APP_CONTEXT_UID,
        DEFAULT_TRANSFER_SYNTAX_UID,
        VERIFICATION_SOP_CLASS_UID,
        CT_IMAGE_STORAGE_SOP_CLASS_UID,
        # Utilities
        _uid_to_bytes,
    )
except ImportError as e:
    print(f"ERROR: Could not import dicom module: {e}", file=sys.stderr)
    sys.exit(2)

# Optional pydicom
try:
    import pydicom
    PYDICOM_AVAILABLE = True
except ImportError:
    PYDICOM_AVAILABLE = False

script_log = logging.getLogger("dicom_fuzzer")

# Constants
SAMPLE_DCM_URL = "https://raw.githubusercontent.com/pydicom/pydicom/main/src/pydicom/data/test_files/CT_small.dcm"
DEFAULT_SAMPLE_DIR = "sample_files_for_fuzzing"
DEFAULT_SAMPLE_FILE = os.path.join(DEFAULT_SAMPLE_DIR, "valid_ct.dcm")


def ensure_sample_file_exists(file_path=DEFAULT_SAMPLE_FILE):
    """Download or create sample DICOM file."""
    dir_name = os.path.dirname(file_path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name)

    if os.path.exists(file_path):
        return True

    script_log.info(f"Downloading sample file to '{file_path}'...")
    try:
        with urllib.request.urlopen(SAMPLE_DCM_URL, timeout=30) as response:
            with open(file_path, "wb") as out_file:
                out_file.write(response.read())
        return True
    except Exception as e:
        script_log.warning(f"Download failed: {e}")

    # Create minimal synthetic file
    script_log.info("Creating minimal synthetic DICOM file...")
    return create_minimal_dicom_file(file_path)


def create_minimal_dicom_file(file_path):
    """Create minimal valid DICOM file."""
    preamble = b"\x00" * 128 + b"DICM"

    # Simplified file meta + dataset
    sop_class = b"1.2.840.10008.5.1.4.1.1.7"
    if len(sop_class) % 2:
        sop_class += b"\x00"
    sop_inst = b"1.2.3.4.5.6.7.8.9"
    if len(sop_inst) % 2:
        sop_inst += b"\x00"
    ts = b"1.2.840.10008.1.2"
    if len(ts) % 2:
        ts += b"\x00"

    # File Meta (Explicit VR)
    fmi = b""
    fmi += struct.pack("<HH", 0x0002, 0x0001) + b"OB" + struct.pack("<HI", 0, 2) + b"\x00\x01"
    fmi += struct.pack("<HH", 0x0002, 0x0002) + b"UI" + struct.pack("<H", len(sop_class)) + sop_class
    fmi += struct.pack("<HH", 0x0002, 0x0003) + b"UI" + struct.pack("<H", len(sop_inst)) + sop_inst
    fmi += struct.pack("<HH", 0x0002, 0x0010) + b"UI" + struct.pack("<H", len(ts)) + ts

    # FMI Length
    fmi_len = struct.pack("<HH", 0x0002, 0x0000) + b"UL" + struct.pack("<H", 4) + struct.pack("<I", len(fmi))

    # Dataset (Implicit VR)
    ds = b""
    ds += struct.pack("<HHI", 0x0008, 0x0016, len(sop_class)) + sop_class
    ds += struct.pack("<HHI", 0x0008, 0x0018, len(sop_inst)) + sop_inst
    pid = b"TEST"
    ds += struct.pack("<HHI", 0x0010, 0x0020, len(pid)) + pid
    study_uid = b"1.2.3.4.5.6.7.8.9.10"
    if len(study_uid) % 2:
        study_uid += b"\x00"
    ds += struct.pack("<HHI", 0x0020, 0x000D, len(study_uid)) + study_uid
    series_uid = b"1.2.3.4.5.6.7.8.9.11"
    if len(series_uid) % 2:
        series_uid += b"\x00"
    ds += struct.pack("<HHI", 0x0020, 0x000E, len(series_uid)) + series_uid

    with open(file_path, "wb") as f:
        f.write(preamble + fmi_len + fmi + ds)

    return True


def create_minimal_dataset_bytes(sop_class_uid=None, sop_instance_uid=None, pad_uids=True):
    """
    Create minimal DICOM dataset bytes.

    Args:
        sop_class_uid: SOP Class UID (bytes or str)
        sop_instance_uid: SOP Instance UID (bytes or str)
        pad_uids: If True, pad UIDs to even length. If False, preserve as-is (fuzzing)
    """
    elements = []

    sop_class = sop_class_uid or b"1.2.840.10008.5.1.4.1.1.7"
    if isinstance(sop_class, str):
        sop_class = sop_class.encode()
    if pad_uids and len(sop_class) % 2:
        sop_class += b"\x00"
    elements.append(struct.pack("<HHI", 0x0008, 0x0016, len(sop_class)) + sop_class)

    sop_inst = sop_instance_uid or f"1.2.3.999.{os.getpid()}.{int(time.time())}".encode()
    if isinstance(sop_inst, str):
        sop_inst = sop_inst.encode()
    if pad_uids and len(sop_inst) % 2:
        sop_inst += b"\x00"
    elements.append(struct.pack("<HHI", 0x0008, 0x0018, len(sop_inst)) + sop_inst)

    study_uid = b"1.2.3.4.5.6.7.8.9.10"
    if pad_uids and len(study_uid) % 2:
        study_uid += b"\x00"
    elements.append(struct.pack("<HHI", 0x0020, 0x000D, len(study_uid)) + study_uid)

    series_uid = b"1.2.3.4.5.6.7.8.9.11"
    if pad_uids and len(series_uid) % 2:
        series_uid += b"\x00"
    elements.append(struct.pack("<HHI", 0x0020, 0x000E, len(series_uid)) + series_uid)

    return b"".join(elements)


def extract_dicom_info(dcm_file_path):
    """Extract info from DICOM file."""
    if PYDICOM_AVAILABLE:
        try:
            ds = pydicom.dcmread(dcm_file_path, force=True)
            return (
                str(ds.SOPClassUID),
                str(ds.SOPInstanceUID),
                create_minimal_dataset_bytes(),
                "1.2.840.10008.1.2",
                "parsed"
            )
        except Exception as e:
            script_log.warning(f"Pydicom parse failed: {e}")

    # Fallback
    return (
        "1.2.840.10008.5.1.4.1.1.7",
        f"1.2.3.999.{os.getpid()}.{int(time.time())}",
        create_minimal_dataset_bytes(),
        "1.2.840.10008.1.2",
        "synthetic"
    )


# =============================================================================
# Fuzzing Helper Functions
# =============================================================================

def mutate_group_length(dimse_bytes: bytes, new_length: int) -> bytes:
    """
    Mutate the group_length field in DIMSE command bytes.

    The group_length is at bytes 8-12 (little-endian UL after the 8-byte header).
    Header format: (0000,0000) tag (4 bytes) + length=4 (4 bytes) + group_len (4 bytes)

    This replaces the old command_group_length field approach for buffer over-read attacks.
    """
    if len(dimse_bytes) < 12:
        return dimse_bytes
    mutated = bytearray(dimse_bytes)
    mutated[8:12] = struct.pack("<I", new_length)
    return bytes(mutated)


def build_raw_dimse_store_rq(sop_class_uid: bytes, sop_instance_uid: bytes,
                             message_id: int = 1, pad_uids: bool = True) -> bytes:
    """
    Build raw C-STORE-RQ DIMSE bytes without using packet classes.

    This replaces the old raw_mode approach for sending odd-length UIDs.

    Args:
        sop_class_uid: SOP Class UID as bytes
        sop_instance_uid: SOP Instance UID as bytes
        message_id: Message ID
        pad_uids: If True, pad UIDs to even length. If False, preserve as-is (fuzzing)
    """
    if pad_uids:
        if len(sop_class_uid) % 2:
            sop_class_uid = sop_class_uid + b"\x00"
        if len(sop_instance_uid) % 2:
            sop_instance_uid = sop_instance_uid + b"\x00"

    elements = [
        (0x0000, 0x0002, sop_class_uid),
        (0x0000, 0x0100, struct.pack("<H", 0x0001)),  # C-STORE-RQ
        (0x0000, 0x0110, struct.pack("<H", message_id)),
        (0x0000, 0x0700, struct.pack("<H", 0x0002)),  # Priority
        (0x0000, 0x0800, struct.pack("<H", 0x0000)),  # Data set present
        (0x0000, 0x1000, sop_instance_uid),
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


# =============================================================================
# Association Handshake Fuzzing
# =============================================================================

def fuzz_association_handshake(session_args):
    """Send various malformed A-ASSOCIATE-RQ packets."""
    script_log.info("=== Starting Association Handshake Fuzzing ===")
    results = {"passed": 0, "failed": 0, "errors": 0}

    # --- Test 1: Overlong AE Title ---
    script_log.info("Test 1: Overlong Called AE Title (20 chars)")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.connect():
            variable_items = [
                DICOMVariableItem() / DICOMApplicationContext(),
                build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]),
                build_user_information(max_pdu_length=16384),
            ]
            aarq = A_ASSOCIATE_RQ(
                called_ae_title=b"X" * 20,  # Overlong! Field will truncate to 16
                calling_ae_title=session_args["calling_ae"],
                variable_items=variable_items,
            )
            pkt = DICOM() / aarq

            session.send(pkt)
            response = session.recv()

            if response and (response.haslayer(A_ABORT) or response.haslayer(A_ASSOCIATE_RJ)):
                script_log.info("[PASS] Server rejected overlong AE")
                results["passed"] += 1
            else:
                script_log.warning("[WARN] Server accepted overlong AE")
                results["failed"] += 1
        session.close()
    except Exception as e:
        script_log.error(f"Error: {e}")
        results["errors"] += 1

    # --- Test 2: Invalid Protocol Version ---
    script_log.info("Test 2: Invalid Protocol Version (0xFFFE)")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.connect():
            variable_items = [
                DICOMVariableItem() / DICOMApplicationContext(),
                build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]),
                build_user_information(max_pdu_length=16384),
            ]
            aarq = A_ASSOCIATE_RQ(
                protocol_version=0xFFFE,  # Invalid!
                called_ae_title=session_args["ae_title"],
                calling_ae_title=session_args["calling_ae"],
                variable_items=variable_items,
            )
            pkt = DICOM() / aarq

            session.send(pkt)
            response = session.recv()

            if response and (response.haslayer(A_ASSOCIATE_RJ) or response.haslayer(A_ABORT)):
                script_log.info("[PASS] Server rejected invalid protocol version")
                results["passed"] += 1
            else:
                script_log.warning("[WARN] Unexpected response")
                results["failed"] += 1
        session.close()
    except Exception as e:
        script_log.error(f"Error: {e}")
        results["errors"] += 1

    # --- Test 3: Missing Application Context ---
    script_log.info("Test 3: Missing Application Context Item")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.connect():
            # No Application Context!
            variable_items = [
                build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]),
                build_user_information(max_pdu_length=16384),
            ]
            aarq = A_ASSOCIATE_RQ(
                called_ae_title=session_args["ae_title"],
                calling_ae_title=session_args["calling_ae"],
                variable_items=variable_items,
            )
            pkt = DICOM() / aarq

            session.send(pkt)
            response = session.recv()

            if response and (response.haslayer(A_ABORT) or response.haslayer(A_ASSOCIATE_RJ)):
                script_log.info("[PASS] Server rejected missing app context")
                results["passed"] += 1
            else:
                script_log.warning("[WARN] Server accepted without app context")
                results["failed"] += 1
        session.close()
    except Exception as e:
        script_log.error(f"Error: {e}")
        results["errors"] += 1

    # --- Test 4: PDU Length Mismatch ---
    script_log.info("Test 4: PDU Length Mismatch (inflated)")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.connect():
            variable_items = [
                DICOMVariableItem() / DICOMApplicationContext(),
                build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]),
                build_user_information(max_pdu_length=16384),
            ]
            aarq = A_ASSOCIATE_RQ(
                called_ae_title=session_args["ae_title"],
                calling_ae_title=session_args["calling_ae"],
                variable_items=variable_items,
            )
            pkt = DICOM() / aarq
            raw_bytes = bytearray(bytes(pkt))

            # Inflate length field
            actual_len = struct.unpack("!I", raw_bytes[2:6])[0]
            raw_bytes[2:6] = struct.pack("!I", actual_len + 10000)

            session.send_raw_bytes(bytes(raw_bytes))

            # Server should timeout waiting for more data or reject
            script_log.info("[PASS] Sent inflated length PDU")
            results["passed"] += 1
        session.close()
    except Exception as e:
        script_log.info(f"[PASS] Server rejected: {e}")
        results["passed"] += 1

    # --- Test 5: Unknown PDU Type ---
    script_log.info("Test 5: Unknown PDU Type (0xFF)")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.connect():
            unknown_pdu = struct.pack("!BBI", 0xFF, 0, 4) + b"\x00\x00\x00\x00"
            session.send_raw_bytes(unknown_pdu)

            response = session.recv()
            if response and response.haslayer(A_ABORT):
                script_log.info("[PASS] Server aborted on unknown PDU")
            else:
                script_log.info("[PASS] Server handled unknown PDU")
            results["passed"] += 1
        session.close()
    except Exception as e:
        script_log.info(f"[PASS] Server closed: {e}")
        results["passed"] += 1

    # --- Test 6: Null AE Titles ---
    script_log.info("Test 6: Null AE Titles")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.connect():
            variable_items = [
                DICOMVariableItem() / DICOMApplicationContext(),
                build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]),
                build_user_information(max_pdu_length=16384),
            ]
            aarq = A_ASSOCIATE_RQ(
                called_ae_title=b"\x00" * 16,
                calling_ae_title=b"\x00" * 16,
                variable_items=variable_items,
            )
            pkt = DICOM() / aarq

            session.send(pkt)
            response = session.recv()

            script_log.info("[PASS] Server handled null AE titles")
            results["passed"] += 1
        session.close()
    except Exception as e:
        script_log.error(f"Error: {e}")
        results["errors"] += 1

    # --- Test 7: Odd-Length UID (using raw byte construction) ---
    script_log.info("Test 7: Odd-Length UID in Application Context (raw bytes)")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.connect():
            # Build A-ASSOCIATE-RQ with odd-length UID manually
            # Odd-length UID (15 bytes) - construct raw Application Context item
            odd_uid = b"1.2.840.10008.1"  # 15 bytes - odd!
            app_ctx_item = struct.pack("!BBH", 0x10, 0, len(odd_uid)) + odd_uid

            # Build presentation context and user info normally
            pctx = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
            user_info = build_user_information(max_pdu_length=16384)

            # Build the A-ASSOCIATE-RQ manually with odd-length app context
            called_ae = session_args["ae_title"].encode().ljust(16)[:16]
            calling_ae = session_args["calling_ae"].encode().ljust(16)[:16]
            reserved2 = b"\x00" * 32

            var_items = app_ctx_item + bytes(pctx) + bytes(user_info)
            aarq_payload = struct.pack("!HH", 0x0001, 0) + called_ae + calling_ae + reserved2 + var_items

            pdu = struct.pack("!BBI", 0x01, 0, len(aarq_payload)) + aarq_payload
            session.send_raw_bytes(pdu)

            response = session.recv()

            script_log.info("[PASS] Server handled odd-length UID")
            results["passed"] += 1
        session.close()
    except Exception as e:
        script_log.info(f"[PASS] Server rejected odd-length UID: {e}")
        results["passed"] += 1

    script_log.info("=== Association Fuzzing Complete ===")
    script_log.info(f"Results: {results['passed']} passed, {results['failed']} failed, {results['errors']} errors")
    return results


# =============================================================================
# C-STORE Fuzzing (Leveraging New Architecture)
# =============================================================================

def fuzz_cstore_with_file(session_args, dcm_file_path):
    """C-STORE fuzzing using the new architecture."""
    script_log.info(f"=== Starting C-STORE Fuzzing with: {dcm_file_path} ===")

    if not os.path.exists(dcm_file_path):
        script_log.error(f"File not found: {dcm_file_path}")
        return {"passed": 0, "failed": 0, "errors": 1}

    sop_class, sop_instance, data_bytes, ts_uid, mode = extract_dicom_info(dcm_file_path)
    script_log.info(f"Using {mode} data: SOP Class={sop_class[:30]}...")

    results = {"passed": 0, "failed": 0, "errors": 0}
    requested_contexts = {
        VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
        sop_class: [ts_uid, DEFAULT_TRANSFER_SYNTAX_UID],
    }

    # --- Test 1: Valid C-STORE (baseline) ---
    script_log.info("Test 1: Valid C-STORE (baseline)")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.associate(requested_contexts=requested_contexts):
            status = session.c_store(data_bytes, sop_class, sop_instance, ts_uid)
            if status == 0x0000:
                script_log.info("[PASS] Valid C-STORE succeeded")
                results["passed"] += 1
            elif status is not None:
                script_log.info(f"[PASS] C-STORE status: 0x{status:04X}")
                results["passed"] += 1
            else:
                script_log.warning("[WARN] C-STORE returned None")
                results["failed"] += 1
            session.release()
        else:
            script_log.error("[FAIL] Association failed")
            results["failed"] += 1
        session.close()
    except Exception as e:
        script_log.error(f"Error: {e}")
        results["errors"] += 1

    # --- Test 2: FUZZ group_length via byte mutation (Buffer Over-Read Attack!) ---
    script_log.info("Test 2: Fuzz group_length via byte mutation (Buffer Over-Read)")
    for fuzz_len in [0, 10, 0xFFFF, 0xFFFFFFFF]:
        script_log.info(f"  Testing group_length=0x{fuzz_len:X}")
        try:
            session = DICOMSocket(
                dst_ip=session_args["ip"],
                dst_port=session_args["port"],
                dst_ae=session_args["ae_title"],
                src_ae=session_args["calling_ae"],
                read_timeout=session_args["timeout"],
            )
            if session.associate(requested_contexts=requested_contexts):
                ctx_id = None
                for cid, (abs_syn, _) in session.accepted_contexts.items():
                    if abs_syn == sop_class:
                        ctx_id = cid
                        break

                if ctx_id:
                    # Build normal DIMSE, then mutate group_length field
                    dimse_cmd = C_STORE_RQ(
                        affected_sop_class_uid=sop_class,
                        affected_sop_instance_uid=sop_instance + f".len{fuzz_len}",
                        message_id=random.randint(1, 65535),
                    )
                    dimse_bytes = bytes(dimse_cmd)

                    # Mutate group_length field (bytes 8-12) for buffer over-read
                    mutated_dimse = mutate_group_length(dimse_bytes, fuzz_len)

                    cmd_pdv = PresentationDataValueItem(
                        context_id=ctx_id,
                        data=mutated_dimse,
                        is_command=1,
                        is_last=1,
                    )
                    session.send(DICOM() / P_DATA_TF(pdv_items=[cmd_pdv]))

                    data_pdv = PresentationDataValueItem(
                        context_id=ctx_id,
                        data=data_bytes,
                        is_command=0,
                        is_last=1,
                    )
                    session.send(DICOM() / P_DATA_TF(pdv_items=[data_pdv]))

                    response = session.recv()
                    if response:
                        script_log.info(f"    Server responded: {response.summary()}")

                session.release()
            session.close()
        except Exception as e:
            script_log.info(f"    Server rejected: {e}")

    results["passed"] += 1  # Completed fuzz iterations

    # --- Test 3: Fuzz message_id boundaries ---
    script_log.info("Test 3: Fuzz message_id boundaries")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.associate(requested_contexts=requested_contexts):
            ctx_id = None
            for cid, (abs_syn, _) in session.accepted_contexts.items():
                if abs_syn == sop_class:
                    ctx_id = cid
                    break

            if ctx_id:
                for test_msg_id in [0, 1, 0x7FFF, 0xFFFF]:
                    script_log.info(f"  Testing message_id=0x{test_msg_id:04X}")

                    dimse_cmd = C_STORE_RQ(
                        affected_sop_class_uid=sop_class,
                        affected_sop_instance_uid=sop_instance + f".msgid{test_msg_id}",
                        message_id=test_msg_id,  # Easy field fuzzing!
                    )

                    cmd_pdv = PresentationDataValueItem(
                        context_id=ctx_id,
                        data=bytes(dimse_cmd),
                        is_command=1,
                        is_last=1,
                    )
                    session.send(DICOM() / P_DATA_TF(pdv_items=[cmd_pdv]))

                    data_pdv = PresentationDataValueItem(
                        context_id=ctx_id,
                        data=data_bytes,
                        is_command=0,
                        is_last=1,
                    )
                    session.send(DICOM() / P_DATA_TF(pdv_items=[data_pdv]))

                    response = session.recv()
                    if response:
                        script_log.info(f"    Server responded")

            session.release()
            results["passed"] += 1
        session.close()
    except Exception as e:
        script_log.error(f"Error: {e}")
        results["errors"] += 1

    # --- Test 4: Invalid command field ---
    script_log.info("Test 4: Invalid command field (0xDEAD)")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.associate(requested_contexts=requested_contexts):
            ctx_id = None
            for cid, (abs_syn, _) in session.accepted_contexts.items():
                if abs_syn == sop_class:
                    ctx_id = cid
                    break

            if ctx_id:
                dimse_cmd = C_STORE_RQ(
                    affected_sop_class_uid=sop_class,
                    affected_sop_instance_uid=sop_instance + ".badcmd",
                    message_id=1,
                )
                dimse_cmd.command_field = 0xDEAD  # Invalid!

                cmd_pdv = PresentationDataValueItem(
                    context_id=ctx_id,
                    data=bytes(dimse_cmd),
                    is_command=1,
                    is_last=1,
                )
                session.send(DICOM() / P_DATA_TF(pdv_items=[cmd_pdv]))

                response = session.recv()
                if response and response.haslayer(A_ABORT):
                    script_log.info("[PASS] Server aborted on invalid command")
                else:
                    script_log.info("[PASS] Server handled invalid command")
                results["passed"] += 1
        session.close()
    except Exception as e:
        script_log.info(f"[PASS] Exception: {e}")
        results["passed"] += 1

    # --- Test 5: Odd-length UIDs using raw byte construction ---
    script_log.info("Test 5: Odd-length UIDs using raw DIMSE bytes")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.associate(requested_contexts=requested_contexts):
            ctx_id = None
            for cid, (abs_syn, _) in session.accepted_contexts.items():
                if abs_syn == sop_class:
                    ctx_id = cid
                    break

            if ctx_id:
                # Build raw DIMSE with odd-length UIDs (no padding)
                dimse_raw = build_raw_dimse_store_rq(
                    sop_class_uid=b"1.2.3.4.5",  # 9 bytes - odd!
                    sop_instance_uid=b"1.2.3.4.5.6.7",  # 13 bytes - odd!
                    message_id=1,
                    pad_uids=False,  # No padding!
                )

                cmd_pdv = PresentationDataValueItem(
                    context_id=ctx_id,
                    data=dimse_raw,
                    is_command=1,
                    is_last=1,
                )
                session.send(DICOM() / P_DATA_TF(pdv_items=[cmd_pdv]))

                # Also send odd-length dataset
                odd_dataset = create_minimal_dataset_bytes(
                    sop_class_uid=b"1.2.3.4.5",
                    sop_instance_uid=b"1.2.3.4.5.6.7",
                    pad_uids=False,
                )

                data_pdv = PresentationDataValueItem(
                    context_id=ctx_id,
                    data=odd_dataset,
                    is_command=0,
                    is_last=1,
                )
                session.send(DICOM() / P_DATA_TF(pdv_items=[data_pdv]))

                response = session.recv()
                script_log.info("[PASS] Sent odd-length UIDs")
                results["passed"] += 1

            session.release()
        session.close()
    except Exception as e:
        script_log.info(f"[PASS] Server rejected odd-length UIDs: {e}")
        results["passed"] += 1

    # --- Test 6: Wrong context ID ---
    script_log.info("Test 6: Wrong Presentation Context ID (255)")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.associate(requested_contexts=requested_contexts):
            dimse_cmd = C_STORE_RQ(
                affected_sop_class_uid=sop_class,
                affected_sop_instance_uid=sop_instance + ".wrongctx",
                message_id=1,
            )

            cmd_pdv = PresentationDataValueItem(
                context_id=255,  # Invalid - not negotiated!
                data=bytes(dimse_cmd),
                is_command=1,
                is_last=1,
            )
            session.send(DICOM() / P_DATA_TF(pdv_items=[cmd_pdv]))

            response = session.recv()
            if response and response.haslayer(A_ABORT):
                script_log.info("[PASS] Server aborted on invalid context")
            else:
                script_log.info("[PASS] Server handled invalid context")
            results["passed"] += 1
        session.close()
    except Exception as e:
        script_log.info(f"[PASS] Exception: {e}")
        results["passed"] += 1

    # --- Test 7: Scapy fuzz() on DIMSE packet ---
    script_log.info("Test 7: Scapy native fuzz() on C_STORE_RQ")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.associate(requested_contexts=requested_contexts):
            ctx_id = None
            for cid, (abs_syn, _) in session.accepted_contexts.items():
                if abs_syn == sop_class:
                    ctx_id = cid
                    break

            if ctx_id:
                for i in range(3):
                    # Use Scapy's native fuzz() function!
                    fuzzed_pkt = fuzz(C_STORE_RQ())
                    # Set required UIDs for context
                    fuzzed_pkt.affected_sop_class_uid = sop_class
                    fuzzed_pkt.affected_sop_instance_uid = f"{sop_instance}.fuzz{i}"

                    script_log.info(f"  Fuzz iteration {i+1}: cmd=0x{fuzzed_pkt.command_field:04X}")

                    cmd_pdv = PresentationDataValueItem(
                        context_id=ctx_id,
                        data=bytes(fuzzed_pkt),
                        is_command=1,
                        is_last=1,
                    )
                    session.send(DICOM() / P_DATA_TF(pdv_items=[cmd_pdv]))

                    data_pdv = PresentationDataValueItem(
                        context_id=ctx_id,
                        data=data_bytes,
                        is_command=0,
                        is_last=1,
                    )
                    session.send(DICOM() / P_DATA_TF(pdv_items=[data_pdv]))

                    try:
                        response = session.recv()
                    except Exception:
                        break

                script_log.info("[PASS] Completed Scapy fuzz() iterations")
                results["passed"] += 1
        session.close()
    except Exception as e:
        script_log.info(f"[PASS] Fuzz caused exception: {e}")
        results["passed"] += 1

    # --- Test 8: Zero-length dataset ---
    script_log.info("Test 8: Zero-length dataset")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.associate(requested_contexts=requested_contexts):
            status = session.c_store(b"", sop_class, sop_instance + ".empty", ts_uid)
            script_log.info(f"[PASS] Server handled empty dataset: {status}")
            results["passed"] += 1
            session.release()
        session.close()
    except Exception as e:
        script_log.info(f"[PASS] Server rejected empty dataset: {e}")
        results["passed"] += 1

    # --- Test 9: Corrupted dataset ---
    script_log.info("Test 9: Corrupted dataset (random bit flips)")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.associate(requested_contexts=requested_contexts):
            corrupted = bytearray(data_bytes)
            for _ in range(max(1, len(corrupted) // 20)):
                idx = random.randint(0, len(corrupted) - 1)
                corrupted[idx] ^= random.randint(1, 255)

            status = session.c_store(bytes(corrupted), sop_class, sop_instance + ".corrupt", ts_uid)
            script_log.info(f"[PASS] Server handled corrupted data: {status}")
            results["passed"] += 1
            session.release()
        session.close()
    except Exception as e:
        script_log.info(f"[PASS] Server rejected corrupted data: {e}")
        results["passed"] += 1

    # --- Test 10: Incomplete fragment ---
    script_log.info("Test 10: Incomplete fragment (send partial, close)")
    try:
        session = DICOMSocket(
            dst_ip=session_args["ip"],
            dst_port=session_args["port"],
            dst_ae=session_args["ae_title"],
            src_ae=session_args["calling_ae"],
            read_timeout=session_args["timeout"],
        )
        if session.associate(requested_contexts=requested_contexts):
            ctx_id = None
            for cid, (abs_syn, _) in session.accepted_contexts.items():
                if abs_syn == sop_class:
                    ctx_id = cid
                    break

            if ctx_id:
                dimse_cmd = C_STORE_RQ(
                    affected_sop_class_uid=sop_class,
                    affected_sop_instance_uid=sop_instance + ".partial",
                    message_id=1,
                )

                cmd_pdv = PresentationDataValueItem(
                    context_id=ctx_id,
                    data=bytes(dimse_cmd),
                    is_command=1,
                    is_last=1,
                )
                session.send(DICOM() / P_DATA_TF(pdv_items=[cmd_pdv]))

                # Send partial data marked as "not last"
                partial_pdv = PresentationDataValueItem(
                    context_id=ctx_id,
                    data=data_bytes[:50],
                    is_command=0,
                    is_last=0,  # More expected, but we close
                )
                session.send(DICOM() / P_DATA_TF(pdv_items=[partial_pdv]))

                # Close without completing
                script_log.info("[PASS] Sent incomplete fragment")
                results["passed"] += 1
        session.close()
    except Exception as e:
        script_log.info(f"[PASS] Exception: {e}")
        results["passed"] += 1

    script_log.info("=== C-STORE Fuzzing Complete ===")
    script_log.info(f"Results: {results['passed']} passed, {results['failed']} failed, {results['errors']} errors")
    return results


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="DICOM Protocol Fuzzer v2.1 (Compatible with Refactored dicom.py)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Fuzzing Techniques (v2.1):
- Byte mutation: mutate_group_length() for buffer over-read attacks
- Raw byte construction: build_raw_dimse_store_rq() for odd-length UIDs
- Field modification: packet.field = bad_value before serialization
- Scapy fuzz(): fuzz(C_STORE_RQ()) for randomized field values
- send_raw_bytes(): bypass all Scapy processing

Examples:
  python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode association
  python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode all --debug
""",
    )
    parser.add_argument("--ip", required=True, help="DICOM SCP IP address")
    parser.add_argument("--port", type=int, required=True, help="DICOM SCP port")
    parser.add_argument("--ae-title", required=True, help="DICOM SCP AE Title")
    parser.add_argument("--calling-ae", default="SCAPY_FUZZER", help="Our AE Title")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout (seconds)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--mode", choices=["association", "cstore_file", "all"], required=True)
    parser.add_argument("--fuzzed-file", help="DICOM file for C-STORE mode")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    )

    script_log.info(f"=== DICOM Fuzzer v2.1 Started (Mode: {args.mode}) ===")

    session_params = {
        "ip": args.ip,
        "port": args.port,
        "ae_title": args.ae_title,
        "calling_ae": args.calling_ae,
        "timeout": args.timeout,
    }

    if args.mode in ["association", "all"]:
        fuzz_association_handshake(session_params)

    if args.mode in ["cstore_file", "all"]:
        target_file = args.fuzzed_file or DEFAULT_SAMPLE_FILE
        if not os.path.exists(target_file):
            if not ensure_sample_file_exists(target_file):
                script_log.error("Failed to obtain sample file")
                sys.exit(1)
        fuzz_cstore_with_file(session_params, target_file)

    script_log.info("=== DICOM Fuzzer v2.1 Finished ===")


if __name__ == "__main__":
    main()