#!/usr/bin/env python3
import argparse
from io import BytesIO
import logging
import os
import sys
import time
import random
import struct # For manual byte packing if needed
import urllib.request # Added for downloading sample file

# Ensure scapy_dicom is accessible
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

try:
    from scapy_dicom import (
        DICOMSession, DICOM, A_ASSOCIATE_RQ, A_ASSOCIATE_RJ, A_ABORT, P_DATA_TF,
        PresentationDataValueItem, APP_CONTEXT_UID, DEFAULT_TRANSFER_SYNTAX_UID,
        VERIFICATION_SOP_CLASS_UID, DICOMVariableItem, PresentationContextRQItem,
        UserInformationItem, MaxLengthSubItem, ImplementationClassUIDSubItem,
        ImplementationVersionNameSubItem, AbstractSyntaxSubItem, TransferSyntaxSubItem,
        _pad_ae_title, _uid_to_bytes, build_c_store_rq_dimse
    )
    from scapy.all import Raw
except ImportError as e:
    print(f"ERROR: Could not import required modules. Ensure scapy_dicom.py is present. Details: {e}", file=sys.stderr)
    sys.exit(2)

import pydicom
from pydicom.errors import InvalidDicomError
from pydicom.uid import generate_uid, ImplicitVRLittleEndian, ExplicitVRLittleEndian

# Global logger
script_log = logging.getLogger("unified_dicom_fuzzer")

# --- Constants for Sample File Download ---
SAMPLE_DCM_URL = "https://github.com/pydicom/pydicom/raw/main/pydicom/data/test_files/CT_small.dcm"
DEFAULT_SAMPLE_DIR = "sample_files_for_fuzzing"
DEFAULT_SAMPLE_FILE = os.path.join(DEFAULT_SAMPLE_DIR, "valid_ct.dcm")

# --- Fallback UIDs ---
FALLBACK_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.7"  # Secondary Capture
FALLBACK_TRANSFER_SYNTAX_UID = ImplicitVRLittleEndian._uid

# --- Helper Functions ---
def ensure_sample_file_exists(file_path=DEFAULT_SAMPLE_FILE):
    """Checks if a sample DICOM file exists, and downloads it if not."""
    dir_name = os.path.dirname(file_path)
    if not os.path.exists(dir_name):
        script_log.info(f"Creating sample file directory: {dir_name}")
        os.makedirs(dir_name)
    
    if not os.path.exists(file_path):
        script_log.info(f"Sample file not found at '{file_path}'. Downloading...")
        try:
            with urllib.request.urlopen(SAMPLE_DCM_URL) as response, open(file_path, 'wb') as out_file:
                data = response.read()
                out_file.write(data)
            script_log.info(f"Successfully downloaded and saved sample file to '{file_path}'.")
            return True
        except Exception as e:
            script_log.error(f"Failed to download sample file: {e}")
            return False
    else:
        script_log.debug(f"Sample file already exists at '{file_path}'.")
        return True

# --- Fuzzing Functions ---

def fuzz_association_handshake(session_args, fuzz_params):
    """
    Sends various malformed A-ASSOCIATE-RQ packets to a live target.
    This function tests requirements that need a live connection to observe a response.
    """
    script_log.info("--- Starting Association Handshake Fuzzing ---")
    
    # Test Case 1: Overlong Called AE Title (REQ-002)
    # The pytest script confirms we can BUILD this; the fuzzer CONFIRMS how a server reacts.
    script_log.info("Test Case: Overlong Called AE Title")
    session = DICOMSession(
        dst_ip=session_args['ip'], dst_port=session_args['port'], dst_ae=session_args['ae_title'],
        src_ae=session_args['calling_ae'], read_timeout=session_args['timeout']
    )
    if session.connect():
        try:
            malformed_aarq_pkt = DICOM() / A_ASSOCIATE_RQ(
                calling_ae_title=_pad_ae_title(session_args['calling_ae']),
                variable_items=[
                    DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID)),
                    DICOMVariableItem(item_type=0x20, data=(
                        struct.pack("!BBBB", 1, 0, 0, 0) +
                        bytes(AbstractSyntaxSubItem(abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID)) +
                        bytes(TransferSyntaxSubItem(transfer_syntax_uid=DEFAULT_TRANSFER_SYNTAX_UID))
                    )),
                    DICOMVariableItem(item_type=0x50, data=bytes(MaxLengthSubItem()))
                ]
            )
            # Manually override the field to be longer than the spec allows
            malformed_aarq_pkt[A_ASSOCIATE_RQ].called_ae_title = b"X"*20
            
            script_log.debug("Sending malformed AARQ (overlong Called AE)")
            response = session.stream.sr1(malformed_aarq_pkt, timeout=session.read_timeout, verbose=0)
            
            if response:
                script_log.info(f"Received response: {response.summary()}")
                if response.haslayer(A_ABORT) or response.haslayer(A_ASSOCIATE_RJ):
                    script_log.info("[PASS] Server correctly rejected or aborted the connection.")
                else:
                    script_log.warning("[FAIL?] Server accepted a malformed AARQ.")
            else:
                script_log.warning("No response received (timeout or connection closed). This may indicate a crash.")
        except Exception as e:
            script_log.error(f"Error during overlong AE fuzz: {e}", exc_info=session_args['debug'])
        finally:
            session.close()

    # Test Case 2: Invalid Protocol Version (REQ-L01 related)
    script_log.info("Test Case: Invalid Protocol Version in AARQ")
    session = DICOMSession(
        dst_ip=session_args['ip'], dst_port=session_args['port'], dst_ae=session_args['ae_title'],
        src_ae=session_args['calling_ae'], read_timeout=session_args['timeout']
    )
    if session.connect():
        try:
            invalid_ver_aarq_pkt = DICOM() / A_ASSOCIATE_RQ(
                protocol_version=0xFFFE, # Invalid version
                called_ae_title=_pad_ae_title(session_args['ae_title']),
                calling_ae_title=_pad_ae_title(session_args['calling_ae']),
                variable_items=[
                    DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID)),
                    DICOMVariableItem(item_type=0x20, data=(
                        struct.pack("!BBBB", 1, 0, 0, 0) +
                        bytes(AbstractSyntaxSubItem(abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID)) +
                        bytes(TransferSyntaxSubItem(transfer_syntax_uid=DEFAULT_TRANSFER_SYNTAX_UID))
                    )),
                    DICOMVariableItem(item_type=0x50, data=bytes(MaxLengthSubItem()))
                ]
            )
            script_log.debug("Sending malformed AARQ (invalid protocol version)")
            response = session.stream.sr1(invalid_ver_aarq_pkt, timeout=session.read_timeout, verbose=0)
            if response:
                script_log.info(f"Received response: {response.summary()}")
                if response.haslayer(A_ASSOCIATE_RJ) and response[A_ASSOCIATE_RJ].reason_diag == 2:
                    script_log.info("[PASS] Server correctly rejected due to unsupported protocol version.")
                else:
                    script_log.warning(f"[FAIL?] Server responded unexpectedly: {response.summary()}")
            else:
                script_log.warning("No response received. Possible crash?")
        except Exception as e:
            script_log.error(f"Error during invalid protocol version fuzz: {e}", exc_info=session_args['debug'])
        finally:
            session.close()

    # NOTE: This is where a fuzzer would implement live tests for requirements like:
    # - REQ-L11 (State Confusion): e.g., session.stream.send(P_DATA_TF(...)) before associating.
    # - REQ-L12 (Resource Exhaustion): e.g., session.stream.send(b'\x04\x00\x10\x00\x00\x00\x01\x02')
    # - REQ-L13 (Interleaving): Send multiple P-DATA-TF packets in a specific order.
    script_log.info("--- Finished Association Handshake Fuzzing ---")
    return True

def extract_info_or_fallback(dcm_file_path):
    try:
        ds = pydicom.dcmread(dcm_file_path, force=True)
        sop_class_uid = str(ds.SOPClassUID)
        sop_instance_uid = str(ds.SOPInstanceUID)
        original_ts_uid = str(ds.file_meta.TransferSyntaxUID)
        
        dataset_buffer = BytesIO()
        pydicom.filewriter.write_dataset(dataset_buffer, ds)
        dataset_bytes = dataset_buffer.getvalue()
        
        return sop_class_uid, sop_instance_uid, dataset_bytes, original_ts_uid, "parsed"
    except Exception:
        script_log.warning(f"Failed to parse '{dcm_file_path}'. Using raw fallback.")
        try:
            with open(dcm_file_path, 'rb') as f:
                dataset_bytes = f.read()
            sop_instance_uid = generate_uid(prefix="1.2.3.999.fuzz.")
            return FALLBACK_SOP_CLASS_UID, sop_instance_uid, dataset_bytes, FALLBACK_TRANSFER_SYNTAX_UID, "fallback_raw"
        except Exception as e_fallback:
            script_log.error(f"Fallback raw read also failed for '{dcm_file_path}': {e_fallback}")
            return None, None, None, None, "failed"

def fuzz_cstore_with_file(session_args, dcm_file_path, fuzz_params):
    """
    Uses the C-STORE mechanism with a (potentially fuzzed) DCM file.
    """
    script_log.info(f"--- Starting C-STORE Fuzzing with File: {dcm_file_path} ---")
    if not os.path.exists(dcm_file_path):
        script_log.error(f"Fuzzed file not found: {dcm_file_path}")
        return False

    sop_class, sop_instance, data_bytes, original_ts_uid, parse_mode = extract_info_or_fallback(dcm_file_path)

    if parse_mode == "failed" or data_bytes is None:
        script_log.error(f"Could not extract data from {dcm_file_path}. Aborting.")
        return False
    
    session = DICOMSession(
        dst_ip=session_args['ip'], dst_port=session_args['port'], dst_ae=session_args['ae_title'],
        src_ae=session_args['calling_ae'], read_timeout=session_args['timeout']
    )

    requested_contexts = {
        VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
        sop_class: [original_ts_uid, DEFAULT_TRANSFER_SYNTAX_UID]
    }

    try:
        if session.associate(requested_contexts=requested_contexts):
            script_log.info("C-STORE Fuzz: Association successful.")
            store_status = session.c_store(
                dataset_bytes=data_bytes,
                sop_class_uid=sop_class,
                sop_instance_uid=sop_instance,
                original_dataset_transfer_syntax_uid=original_ts_uid
            )
            if store_status is not None:
                script_log.info(f"C-STORE completed. SCP Status: 0x{store_status:04X}")
            else:
                script_log.error("C-STORE did not complete at protocol level.")
        else:
            script_log.error("C-STORE Fuzz: Association failed.")
    except Exception as e:
        script_log.exception(f"Exception during C-STORE operation: {e}")
    finally:
        if session and session.stream:
            session.close()
    
    script_log.info("--- Finished C-STORE Fuzzing with File ---")
    return True


def main():
    parser = argparse.ArgumentParser(description="Unified DICOM Fuzzer")
    parser.add_argument("--ip", required=True, help="IP of DICOM SCP")
    parser.add_argument("--port", type=int, required=True, help="Port of DICOM SCP")
    parser.add_argument("--ae-title", required=True, help="AE Title of DICOM SCP")
    parser.add_argument("--calling-ae", default="SCAPY_FUZZER", help="Our AE Title")
    parser.add_argument("--timeout", type=int, default=10, help="Network timeout")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--mode", choices=['association', 'cstore_file', 'all'], required=True, help="Fuzzing mode.")
    parser.add_argument("--fuzzed-file", help="Path to a DICOM file for C-STORE. If omitted, a sample file is downloaded.")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    logging.getLogger("scapy.contrib.dicom").setLevel(log_level)

    script_log.info(f"=== DICOM Fuzzer Started (Mode: {args.mode}) ===")
    
    session_params = {
        'ip': args.ip, 'port': args.port, 'ae_title': args.ae_title,
        'calling_ae': args.calling_ae, 'timeout': args.timeout, 'debug': args.debug
    }

    if args.mode in ['association', 'all']:
        fuzz_association_handshake(session_params, {})

    if args.mode in ['cstore_file', 'all']:
        target_file = args.fuzzed_file
        if not target_file:
            script_log.info("No --fuzzed-file provided. Using default sample file.")
            target_file = DEFAULT_SAMPLE_FILE
            if not ensure_sample_file_exists(target_file):
                script_log.error("Failed to obtain a sample file. Aborting C-STORE mode.")
                sys.exit(1)
        
        fuzz_cstore_with_file(session_params, target_file, {})

    script_log.info("=== DICOM Fuzzer Finished ===")
    sys.exit(0)

if __name__ == "__main__":
    main()
