#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import time
import random
import struct # For manual byte packing if needed

# Ensure scapy_DICOM is accessible
try:
    from scapy_DICOM import (
        DICOMSession, DICOM, A_ASSOCIATE_RQ, A_ABORT, P_DATA_TF, PresentationDataValueItem,
        APP_CONTEXT_UID, DEFAULT_TRANSFER_SYNTAX_UID, VERIFICATION_SOP_CLASS_UID,
        # Import PDU component classes if needed for direct construction
        DICOMVariableItem, ApplicationContextItem, PresentationContextRQItem, UserInformationItem,
        MaxLengthSubItem, ImplementationClassUIDSubItem, ImplementationVersionNameSubItem,
        AbstractSyntaxSubItem, TransferSyntaxSubItem,
        _pad_ae_title, _uid_to_bytes, build_c_store_rq_dimse # Make sure build_c_store_rq_dimse is in scapy_DICOM
    )
    from scapy.all import Raw # For sending raw bytes
except ImportError:
    sys.path.append(os.path.join(os.path.dirname(__file__), '.')) # Assume in same folder for GHA
    try:
        from scapy_DICOM import (
            DICOMSession, DICOM, A_ASSOCIATE_RQ, A_ABORT, P_DATA_TF, PresentationDataValueItem,
            APP_CONTEXT_UID, DEFAULT_TRANSFER_SYNTAX_UID, VERIFICATION_SOP_CLASS_UID,
            DICOMVariableItem, ApplicationContextItem, PresentationContextRQItem, UserInformationItem,
            MaxLengthSubItem, ImplementationClassUIDSubItem, ImplementationVersionNameSubItem,
            AbstractSyntaxSubItem, TransferSyntaxSubItem,
            _pad_ae_title, _uid_to_bytes, build_c_store_rq_dimse
        )
        from scapy.all import Raw
    except ImportError as e_imp:
        print(f"ERROR: Could not import from scapy_DICOM.py: {e_imp}", file=sys.stderr)
        sys.exit(2)

import pydicom
from pydicom.errors import InvalidDicomError
from pydicom.uid import generate_uid, ImplicitVRLittleEndian, ExplicitVRLittleEndian

# Global logger
script_log = logging.getLogger("unified_dicom_fuzzer")

# --- Fallback UIDs (same as in fuzz_cstore.py) ---
FALLBACK_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.7"  # Secondary Capture
FALLBACK_TRANSFER_SYNTAX_UID = ImplicitVRLittleEndian._uid # Get the string UID

# --- Fuzzing Functions ---

def fuzz_association_handshake(session_args, fuzz_params):
    """
    Sends various malformed A-ASSOCIATE-RQ packets.
    fuzz_params could control mutation type, specific fields to target, etc.
    """
    script_log.info("--- Starting Association Handshake Fuzzing ---")
    session = DICOMSession(
        dst_ip=session_args['ip'], dst_port=session_args['port'], dst_ae=session_args['ae_title'],
        src_ae=session_args['calling_ae'], read_timeout=session_args['timeout']
    )

    # Test Case 1: Overlong Called AE Title
    script_log.info("Test Case: Overlong Called AE Title")
    if session.connect():
        try:
            # Craft AARQ with Scapy layers
            malformed_aarq_pkt = DICOM() / A_ASSOCIATE_RQ(
                called_ae_title=_pad_ae_title("THIS_AE_TITLE_IS_WAY_TOO_LONG_AND_SHOULD_BE_TRUNCATED_OR_REJECTED"), # Will be 16 bytes
                calling_ae_title=_pad_ae_title(session_args['calling_ae']),
                # Minimal variable items for a basic association attempt
                variable_items=[
                    DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID)), # Application Context
                    # Basic Presentation Context for Verification
                    DICOMVariableItem(item_type=0x20, data= (
                        struct.pack("!BBBB", 1, 0, 0, 0) + # Context ID 1
                        bytes(AbstractSyntaxSubItem(abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID)) +
                        bytes(TransferSyntaxSubItem(transfer_syntax_uid=DEFAULT_TRANSFER_SYNTAX_UID))
                    )),
                    DICOMVariableItem(item_type=0x50, data=bytes(MaxLengthSubItem(max_length_received=16384))) # User Info
                ]
            )
            # Override the called_ae_title field after Scapy's initial padding
            malformed_aarq_pkt[A_ASSOCIATE_RQ].called_ae_title = b"X"*20 # 20 bytes, exceeds 16
            
            script_log.debug(f"Sending malformed AARQ (overlong Called AE):\n{malformed_aarq_pkt.show(dump=True, indent=1)}")
            response = session.stream.sr1(malformed_aarq_pkt, timeout=session.read_timeout, verbose=0)
            if response:
                script_log.info(f"Received response to malformed AARQ: {response.summary()}")
                response.show()
                if response.haslayer(A_ABORT) or response.haslayer(A_ASSOCIATE_RJ):
                    script_log.info("Server correctly rejected or aborted.")
            else:
                script_log.warning("No response to malformed AARQ (timeout or closed). Possible issue?")
        except Exception as e:
            script_log.error(f"Error during overlong AE fuzz: {e}", exc_info=args.debug)
        finally:
            session.close() # Ensure connection is closed for next test

    # Test Case 2: Invalid Protocol Version
    script_log.info("Test Case: Invalid Protocol Version in AARQ")
    if session.connect():
        try:
            invalid_ver_aarq_pkt = DICOM() / A_ASSOCIATE_RQ(
                protocol_version=0xFFFE, # Invalid version
                called_ae_title=_pad_ae_title(session_args['ae_title']),
                calling_ae_title=_pad_ae_title(session_args['calling_ae']),
                variable_items=[
                    DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID)),
                    DICOMVariableItem(item_type=0x20, data= (
                        struct.pack("!BBBB", 1, 0, 0, 0) +
                        bytes(AbstractSyntaxSubItem(abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID)) +
                        bytes(TransferSyntaxSubItem(transfer_syntax_uid=DEFAULT_TRANSFER_SYNTAX_UID))
                    )),
                    DICOMVariableItem(item_type=0x50, data=bytes(MaxLengthSubItem(max_length_received=16384)))
                ]
            )
            script_log.debug(f"Sending malformed AARQ (invalid protocol version):\n{invalid_ver_aarq_pkt.show(dump=True, indent=1)}")
            response = session.stream.sr1(invalid_ver_aarq_pkt, timeout=session.read_timeout, verbose=0)
            if response:
                script_log.info(f"Received response: {response.summary()}")
                if response.haslayer(A_ASSOCIATE_RJ) and response[A_ASSOCIATE_RJ].reason_diag == 2: # Protocol version not supported
                     script_log.info("Server correctly rejected due to protocol version.")
            else:
                script_log.warning("No response to invalid protocol version AARQ.")
        except Exception as e:
            script_log.error(f"Error during invalid protocol version fuzz: {e}", exc_info=args.debug)
        finally:
            session.close()

    # Add more AARQ fuzz cases:
    # - Malformed presentation context (e.g., item length incorrect for content)
    # - Malformed user info item (e.g., MaxLength PDU with length field != 4)
    # - Sending an A-ABORT PDU immediately after TCP connect
    # - Sending an A-ASSOCIATE-AC PDU (acting as SCP)
    script_log.info("--- Finished Association Handshake Fuzzing ---")
    return True # Indicates completion of this fuzz mode

def fuzz_cstore_with_file(session_args, dcm_file_path, fuzz_params):
    """
    Uses the C-STORE mechanism with a (potentially fuzzed) DCM file.
    """
    script_log.info(f"--- Starting C-STORE Fuzzing with File: {dcm_file_path} ---")
    if not os.path.exists(dcm_file_path):
        script_log.error(f"Fuzzed file for C-STORE not found: {dcm_file_path}")
        return False

    sop_class, sop_instance, data_bytes, original_ts_uid, parse_mode = \
        extract_info_or_fallback(dcm_file_path) # Defined below

    if parse_mode == "failed" or data_bytes is None:
        script_log.error(f"Could not extract any data from {dcm_file_path}. Aborting C-STORE fuzz for this file.")
        return False
    
    script_log.info(f"C-STORE Data mode: {parse_mode}. Dataset size: {len(data_bytes)} bytes. "
                    f"SOP Class: {sop_class}, SOP Instance: {sop_instance}, Declared TS: {original_ts_uid}")

    session = DICOMSession(
        dst_ip=session_args['ip'], dst_port=session_args['port'], dst_ae=session_args['ae_title'],
        src_ae=session_args['calling_ae'], read_timeout=session_args['timeout']
    )

    requested_contexts = {
        VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
        sop_class: [original_ts_uid]
    }
    # For more robust fuzzing, ensure common TS are also proposed if original_ts_uid is exotic or fuzzed
    if original_ts_uid != DEFAULT_TRANSFER_SYNTAX_UID:
         if sop_class in requested_contexts and DEFAULT_TRANSFER_SYNTAX_UID not in requested_contexts[sop_class]:
            requested_contexts[sop_class].append(DEFAULT_TRANSFER_SYNTAX_UID)
         elif sop_class not in requested_contexts: # Should not happen if sop_class is valid
            requested_contexts[sop_class] = [DEFAULT_TRANSFER_SYNTAX_UID]

    if ExplicitVRLittleEndian._uid != original_ts_uid and ExplicitVRLittleEndian._uid != DEFAULT_TRANSFER_SYNTAX_UID :
        if sop_class in requested_contexts and ExplicitVRLittleEndian._uid not in requested_contexts[sop_class]:
            requested_contexts[sop_class].append(ExplicitVRLittleEndian._uid)
        elif sop_class not in requested_contexts:
             requested_contexts[sop_class] = [ExplicitVRLittleEndian._uid]


    cstore_attempted = False
    try:
        if session.associate(requested_contexts=requested_contexts):
            script_log.info("C-STORE Fuzz: Association successful.")
            
            store_status = session.c_store(
                dataset_bytes=data_bytes,
                sop_class_uid=sop_class,
                sop_instance_uid=sop_instance,
                original_dataset_transfer_syntax_uid=original_ts_uid
            )
            cstore_attempted = True

            if store_status is not None:
                script_log.info(f"C-STORE for fuzzed file completed. SCP Response Status: 0x{store_status:04X}")
            else:
                script_log.error("C-STORE for fuzzed file did NOT complete at protocol level (check server logs).")
        else:
            script_log.error("C-STORE Fuzz: Association failed.")
    except Exception as e:
        script_log.exception(f"Exception during C-STORE fuzzed file operation: {e}")
    finally:
        if session and (session.assoc_established or session.stream):
            if session.assoc_established: # Only release if association was fully up
                session.release()
            else:
                session.close() # Close socket if association failed mid-way or connect only
    
    script_log.info("--- Finished C-STORE Fuzzing with File ---")
    return cstore_attempted # True if the C-STORE was at least attempted after association


def extract_info_or_fallback(dcm_file_path): # Same as in previous fuzz_cstore.py
    """
    Attempts to parse a DCM file. If successful, returns extracted UIDs, dataset, and TS.
    If parsing fails, returns fallback UIDs, the raw file content as dataset, and a fallback TS.
    Returns: (sop_class_uid, sop_instance_uid, dataset_bytes, transfer_syntax_uid, parse_mode)
    parse_mode can be "parsed", "fallback_raw", "failed"
    """
    try:
        ds = pydicom.dcmread(dcm_file_path, force=True)
        script_log.debug(f"Successfully parsed (or partially parsed) '{dcm_file_path}' with pydicom.")

        sop_class_uid = str(ds.SOPClassUID)
        sop_instance_uid = str(ds.SOPInstanceUID)
        
        original_ts_uid = FALLBACK_TRANSFER_SYNTAX_UID 
        if hasattr(ds, 'file_meta') and hasattr(ds.file_meta, 'TransferSyntaxUID') and ds.file_meta.TransferSyntaxUID:
             original_ts_uid = str(ds.file_meta.TransferSyntaxUID)
        else:
            script_log.warning(f"File '{dcm_file_path}' parsed but missing FMI or TransferSyntaxUID. Using fallback TS '{FALLBACK_TRANSFER_SYNTAX_UID}'.")
            # Attempt to guess from dataset's encoding if FMI is missing
            if hasattr(ds, 'is_implicit_VR') and hasattr(ds, 'is_little_endian'):
                if ds.is_implicit_VR and ds.is_little_endian: original_ts_uid = ImplicitVRLittleEndian._uid
                elif not ds.is_implicit_VR and ds.is_little_endian: original_ts_uid = ExplicitVRLittleEndian._uid
                # Not handling big endian or explicit big endian here for brevity

        # Extract dataset bytes (excluding file meta information)
        dataset_buffer = BytesIO()
        temp_ds_for_bytes = pydicom.Dataset()
        # Preserve original encoding characteristics for writing
        temp_ds_for_bytes.is_little_endian = ds.is_little_endian
        temp_ds_for_bytes.is_implicit_VR = ds.is_implicit_VR
        
        for elem in ds: # Copy elements from the read dataset, excluding file meta
            if elem.tag.group != 0x0002:
                temp_ds_for_bytes.add(elem)
        
        pydicom.filewriter.write_dataset(dataset_buffer, temp_ds_for_bytes)
        dataset_bytes = dataset_buffer.getvalue()
        
        script_log.info(f"Extracted from parsed file: SOPClass={sop_class_uid}, SOPInstance={sop_instance_uid}, "
                        f"OrigTS={original_ts_uid}, DataSize={len(dataset_bytes)}")
        return sop_class_uid, sop_instance_uid, dataset_bytes, original_ts_uid, "parsed"

    except Exception as e: # Broad exception for any parsing issue
        script_log.warning(f"Failed to parse '{dcm_file_path}' with pydicom (Error: {e}). Using raw fallback.")
        try:
            with open(dcm_file_path, 'rb') as f:
                dataset_bytes = f.read() # Entire raw file content as "dataset"
            
            sop_instance_uid = generate_uid(prefix="1.2.3.999.fuzz.")
            
            script_log.info(f"Fallback: SOPClass={FALLBACK_SOP_CLASS_UID}, SOPInstance={sop_instance_uid} (generated), "
                        f"TS={FALLBACK_TRANSFER_SYNTAX_UID}, DataSize={len(dataset_bytes)} (raw file content)")
            return FALLBACK_SOP_CLASS_UID, sop_instance_uid, dataset_bytes, FALLBACK_TRANSFER_SYNTAX_UID, "fallback_raw"
        except Exception as e_fallback:
            script_log.error(f"Fallback raw read also failed for '{dcm_file_path}': {e_fallback}")
            return None, None, None, None, "failed"

def main():
    parser = argparse.ArgumentParser(description="Unified DICOM Fuzzer (Scapy Packets & C-STORE File)")
    parser.add_argument("--ip", required=True, help="IP of DICOM SCP")
    parser.add_argument("--port", type=int, required=True, help="Port of DICOM SCP")
    parser.add_argument("--ae-title", required=True, help="AE Title of DICOM SCP")
    parser.add_argument("--calling-ae", default="UNIFIED_FUZZER", help="Our AE Title")
    parser.add_argument("--timeout", type=int, default=20, help="Network timeout")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    # Mode selection
    parser.add_argument("--mode", choices=['association', 'cstore_file', 'all'], required=True,
                        help="Fuzzing mode to run.")
    parser.add_argument("--fuzzed-file", help="Path to fuzzed DCM file (required for 'cstore_file' mode)")

    # Fuzzing parameters (example)
    # parser.add_argument("--iterations", type=int, default=10, help="Number of fuzz iterations for some modes")

    global args # Make args globally accessible for logging in helper functions if needed.
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(name)s - %(threadName)s - %(message)s')
        logging.getLogger("scapy.contrib.dicom").setLevel(logging.DEBUG)
        logging.getLogger("pydicom").setLevel(logging.DEBUG) # Pydicom can be verbose
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
        logging.getLogger("scapy.contrib.dicom").setLevel(logging.INFO)
        logging.getLogger("pydicom").setLevel(logging.INFO)

    script_log.info(f"=== Unified DICOM Fuzzer Started ===")
    script_log.info(f"Target: {args.ae_title} at {args.ip}:{args.port}")
    script_log.info(f"Mode: {args.mode}")

    session_params = {
        'ip': args.ip, 'port': args.port, 'ae_title': args.ae_title,
        'calling_ae': args.calling_ae, 'timeout': args.timeout
    }
    fuzz_run_overall_status = True # True if all selected modes ran without script error

    if args.mode == 'association' or args.mode == 'all':
        if not fuzz_association_handshake(session_params, {}):
            fuzz_run_overall_status = False
            script_log.error("Association fuzzing mode reported an issue.")


    if args.mode == 'cstore_file' or args.mode == 'all':
        if not args.fuzzed_file:
            script_log.error("--fuzzed-file is required for 'cstore_file' or 'all' modes.")
            sys.exit(1)
        if not fuzz_cstore_with_file(session_params, args.fuzzed_file, {}):
            fuzz_run_overall_status = False # If the C-STORE attempt itself failed badly
            script_log.error("C-STORE file fuzzing mode reported an issue.")

    # Add other modes like fuzz_pdata_pdvs etc.
    # if args.mode == 'pdata' or args.mode == 'all':
    #   fuzz_pdata_contents(...)

    script_log.info(f"=== Unified DICOM Fuzzer Finished ===")
    if fuzz_run_overall_status:
        sys.exit(0) # All selected modes completed their attempts
    else:
        sys.exit(1) # One or more modes had issues with the attempt itself

if __name__ == "__main__":
    main()