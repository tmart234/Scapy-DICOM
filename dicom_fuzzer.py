#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
DICOM Protocol Fuzzer

A fuzzing tool for testing DICOM SCP implementations using the scapy_dicom module.
Supports association handshake fuzzing and C-STORE operations with malformed data.

Usage:
    python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode all
"""

import argparse
from io import BytesIO
import logging
import os
import sys
import struct
import urllib.request

# Ensure scapy_dicom is accessible
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

try:
    from scapy_dicom import (
        DICOMSession,
        DICOM,
        A_ASSOCIATE_RQ,
        A_ASSOCIATE_RJ,
        A_ABORT,
        DICOMVariableItem,
        APP_CONTEXT_UID,
        DEFAULT_TRANSFER_SYNTAX_UID,
        VERIFICATION_SOP_CLASS_UID,
        _pad_ae_title,
        _uid_to_bytes,
    )
except ImportError as e:
    print(
        f"ERROR: Could not import scapy_dicom. "
        f"Ensure scapy_dicom.py is present. Details: {e}",
        file=sys.stderr,
    )
    sys.exit(2)

# Optional pydicom for parsing real DICOM files
try:
    import pydicom
    PYDICOM_AVAILABLE = True
except ImportError:
    PYDICOM_AVAILABLE = False

# Global logger
script_log = logging.getLogger("dicom_fuzzer")

# --- Constants ---
SAMPLE_DCM_URL = (
    "https://github.com/pydicom/pydicom/raw/main/pydicom/data/test_files/CT_small.dcm"
)
DEFAULT_SAMPLE_DIR = "sample_files_for_fuzzing"
DEFAULT_SAMPLE_FILE = os.path.join(DEFAULT_SAMPLE_DIR, "valid_ct.dcm")

# Fallback UIDs when pydicom is not available
FALLBACK_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.7"  # Secondary Capture
FALLBACK_TRANSFER_SYNTAX_UID = "1.2.840.10008.1.2"  # Implicit VR Little Endian


def ensure_sample_file_exists(file_path=DEFAULT_SAMPLE_FILE):
    """Download sample DICOM file if not present."""
    dir_name = os.path.dirname(file_path)
    if dir_name and not os.path.exists(dir_name):
        script_log.info(f"Creating sample file directory: {dir_name}")
        os.makedirs(dir_name)

    if not os.path.exists(file_path):
        script_log.info(f"Downloading sample file to '{file_path}'...")
        try:
            with urllib.request.urlopen(SAMPLE_DCM_URL) as response:
                with open(file_path, "wb") as out_file:
                    out_file.write(response.read())
            script_log.info("Download successful.")
            return True
        except Exception as e:
            script_log.error(f"Failed to download sample file: {e}")
            return False
    return True


def build_presentation_context_item(ctx_id, abstract_syntax, transfer_syntaxes):
    """
    Build a Presentation Context Item (type 0x20) for A-ASSOCIATE-RQ.

    :param ctx_id: Presentation Context ID (odd number 1-255)
    :param abstract_syntax: Abstract Syntax UID (SOP Class)
    :param transfer_syntaxes: List of Transfer Syntax UIDs
    :return: DICOMVariableItem for the presentation context
    """
    # Build sub-items
    sub_items = bytes(
        DICOMVariableItem(item_type=0x30, data=_uid_to_bytes(abstract_syntax))
    )
    for ts in transfer_syntaxes:
        sub_items += bytes(
            DICOMVariableItem(item_type=0x40, data=_uid_to_bytes(ts))
        )

    # Presentation context header: ID, reserved, reserved, reserved
    pctx_data = struct.pack("!BBBB", ctx_id, 0, 0, 0) + sub_items
    return DICOMVariableItem(item_type=0x20, data=pctx_data)


def build_user_info_item(max_pdu_length=16384):
    """
    Build a User Information Item (type 0x50) for A-ASSOCIATE-RQ.

    :param max_pdu_length: Maximum PDU length to negotiate
    :return: DICOMVariableItem for user information
    """
    # Maximum Length Sub-Item (type 0x51)
    max_len_data = struct.pack("!I", max_pdu_length)
    max_len_item = DICOMVariableItem(item_type=0x51, data=max_len_data)
    return DICOMVariableItem(item_type=0x50, data=bytes(max_len_item))


def fuzz_association_handshake(session_args):
    """
    Send various malformed A-ASSOCIATE-RQ packets to test SCP robustness.
    """
    script_log.info("=== Starting Association Handshake Fuzzing ===")
    results = {"passed": 0, "failed": 0, "errors": 0}

    # --- Test Case 1: Overlong Called AE Title ---
    script_log.info("Test Case 1: Overlong Called AE Title (20 chars)")
    session = DICOMSession(
        dst_ip=session_args["ip"],
        dst_port=session_args["port"],
        dst_ae=session_args["ae_title"],
        src_ae=session_args["calling_ae"],
        read_timeout=session_args["timeout"],
    )
    if session.connect():
        try:
            # Build a valid AARQ structure first
            variable_items = [
                DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID)),
                build_presentation_context_item(
                    1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]
                ),
                build_user_info_item(),
            ]

            aarq = A_ASSOCIATE_RQ(
                called_ae_title=_pad_ae_title(session_args["ae_title"]),
                calling_ae_title=_pad_ae_title(session_args["calling_ae"]),
                variable_items=variable_items,
            )
            pkt = DICOM() / aarq

            # Inject overlong AE title (20 bytes instead of 16)
            pkt[A_ASSOCIATE_RQ].called_ae_title = b"X" * 20

            script_log.debug("Sending malformed AARQ (overlong Called AE)")
            session._send_pdu(pkt)
            response_data = session._recv_pdu()

            if response_data:
                response = DICOM(response_data)
                script_log.info(f"Received response: {response.summary()}")
                if response.haslayer(A_ABORT) or response.haslayer(A_ASSOCIATE_RJ):
                    script_log.info("[PASS] Server correctly rejected the connection.")
                    results["passed"] += 1
                else:
                    script_log.warning("[WARN] Server accepted malformed AARQ.")
                    results["failed"] += 1
            else:
                script_log.warning("[WARN] No response (timeout or connection closed).")
                results["failed"] += 1
        except Exception as e:
            script_log.error(f"Error: {e}")
            results["errors"] += 1
        finally:
            session.close()

    # --- Test Case 2: Invalid Protocol Version ---
    script_log.info("Test Case 2: Invalid Protocol Version (0xFFFE)")
    session = DICOMSession(
        dst_ip=session_args["ip"],
        dst_port=session_args["port"],
        dst_ae=session_args["ae_title"],
        src_ae=session_args["calling_ae"],
        read_timeout=session_args["timeout"],
    )
    if session.connect():
        try:
            variable_items = [
                DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID)),
                build_presentation_context_item(
                    1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]
                ),
                build_user_info_item(),
            ]

            aarq = A_ASSOCIATE_RQ(
                protocol_version=0xFFFE,  # Invalid version
                called_ae_title=_pad_ae_title(session_args["ae_title"]),
                calling_ae_title=_pad_ae_title(session_args["calling_ae"]),
                variable_items=variable_items,
            )
            pkt = DICOM() / aarq

            script_log.debug("Sending AARQ with invalid protocol version")
            session._send_pdu(pkt)
            response_data = session._recv_pdu()

            if response_data:
                response = DICOM(response_data)
                script_log.info(f"Received response: {response.summary()}")
                if response.haslayer(A_ASSOCIATE_RJ):
                    reason = response[A_ASSOCIATE_RJ].reason_diag
                    if reason == 2:  # Protocol version not supported
                        script_log.info(
                            "[PASS] Server rejected with correct reason (protocol version)."
                        )
                        results["passed"] += 1
                    else:
                        script_log.info(f"[PASS] Server rejected (reason={reason}).")
                        results["passed"] += 1
                elif response.haslayer(A_ABORT):
                    script_log.info("[PASS] Server aborted connection.")
                    results["passed"] += 1
                else:
                    script_log.warning("[WARN] Unexpected response.")
                    results["failed"] += 1
            else:
                script_log.warning("[WARN] No response received.")
                results["failed"] += 1
        except Exception as e:
            script_log.error(f"Error: {e}")
            results["errors"] += 1
        finally:
            session.close()

    # --- Test Case 3: Missing Application Context ---
    script_log.info("Test Case 3: Missing Application Context Item")
    session = DICOMSession(
        dst_ip=session_args["ip"],
        dst_port=session_args["port"],
        dst_ae=session_args["ae_title"],
        src_ae=session_args["calling_ae"],
        read_timeout=session_args["timeout"],
    )
    if session.connect():
        try:
            # No Application Context Item (type 0x10)
            variable_items = [
                build_presentation_context_item(
                    1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]
                ),
                build_user_info_item(),
            ]

            aarq = A_ASSOCIATE_RQ(
                called_ae_title=_pad_ae_title(session_args["ae_title"]),
                calling_ae_title=_pad_ae_title(session_args["calling_ae"]),
                variable_items=variable_items,
            )
            pkt = DICOM() / aarq

            script_log.debug("Sending AARQ without Application Context")
            session._send_pdu(pkt)
            response_data = session._recv_pdu()

            if response_data:
                response = DICOM(response_data)
                script_log.info(f"Received response: {response.summary()}")
                if response.haslayer(A_ABORT) or response.haslayer(A_ASSOCIATE_RJ):
                    script_log.info("[PASS] Server rejected missing app context.")
                    results["passed"] += 1
                else:
                    script_log.warning("[WARN] Server accepted without app context.")
                    results["failed"] += 1
            else:
                script_log.warning("[WARN] No response received.")
                results["failed"] += 1
        except Exception as e:
            script_log.error(f"Error: {e}")
            results["errors"] += 1
        finally:
            session.close()

    # --- Test Case 4: Excessive Presentation Contexts ---
    script_log.info("Test Case 4: Excessive Presentation Contexts (200)")
    session = DICOMSession(
        dst_ip=session_args["ip"],
        dst_port=session_args["port"],
        dst_ae=session_args["ae_title"],
        src_ae=session_args["calling_ae"],
        read_timeout=session_args["timeout"],
    )
    if session.connect():
        try:
            variable_items = [
                DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID)),
            ]
            # Add 200 presentation contexts (DICOM allows max 128)
            for i in range(200):
                ctx_id = (i * 2 + 1) % 256  # Odd numbers, wrap around
                variable_items.append(
                    build_presentation_context_item(
                        ctx_id, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]
                    )
                )
            variable_items.append(build_user_info_item())

            aarq = A_ASSOCIATE_RQ(
                called_ae_title=_pad_ae_title(session_args["ae_title"]),
                calling_ae_title=_pad_ae_title(session_args["calling_ae"]),
                variable_items=variable_items,
            )
            pkt = DICOM() / aarq

            script_log.debug("Sending AARQ with 200 presentation contexts")
            session._send_pdu(pkt)
            response_data = session._recv_pdu()

            if response_data:
                response = DICOM(response_data)
                script_log.info(f"Received response: {response.summary()}")
                # Any response is acceptable - server didn't crash
                script_log.info("[PASS] Server handled excessive contexts.")
                results["passed"] += 1
            else:
                script_log.warning("[WARN] No response (possible crash?).")
                results["failed"] += 1
        except Exception as e:
            script_log.error(f"Error: {e}")
            results["errors"] += 1
        finally:
            session.close()

    script_log.info("=== Association Fuzzing Complete ===")
    script_log.info(
        f"Results: {results['passed']} passed, "
        f"{results['failed']} failed, {results['errors']} errors"
    )
    return results


def extract_dicom_info(dcm_file_path):
    """
    Extract SOP Class UID, SOP Instance UID, and dataset bytes from a DICOM file.
    Falls back to raw bytes if pydicom is not available or parsing fails.
    """
    if PYDICOM_AVAILABLE:
        try:
            ds = pydicom.dcmread(dcm_file_path, force=True)
            sop_class_uid = str(ds.SOPClassUID)
            sop_instance_uid = str(ds.SOPInstanceUID)
            ts_uid = str(ds.file_meta.TransferSyntaxUID)

            # Write dataset (without file meta) to bytes
            buffer = BytesIO()
            pydicom.filewriter.write_dataset(buffer, ds)
            dataset_bytes = buffer.getvalue()

            return sop_class_uid, sop_instance_uid, dataset_bytes, ts_uid, "parsed"
        except Exception as e:
            script_log.warning(f"Failed to parse DICOM file: {e}")

    # Fallback: raw bytes
    script_log.info("Using raw fallback for DICOM file.")
    try:
        with open(dcm_file_path, "rb") as f:
            dataset_bytes = f.read()
        # Generate a unique SOP Instance UID
        sop_instance_uid = f"1.2.3.999.{os.getpid()}.{int(__import__('time').time())}"
        return (
            FALLBACK_SOP_CLASS_UID,
            sop_instance_uid,
            dataset_bytes,
            FALLBACK_TRANSFER_SYNTAX_UID,
            "fallback",
        )
    except Exception as e:
        script_log.error(f"Failed to read file: {e}")
        return None, None, None, None, "failed"


def fuzz_cstore_with_file(session_args, dcm_file_path):
    """
    Attempt C-STORE with a (potentially malformed) DICOM file.
    """
    script_log.info(f"=== Starting C-STORE Fuzzing with: {dcm_file_path} ===")

    if not os.path.exists(dcm_file_path):
        script_log.error(f"File not found: {dcm_file_path}")
        return False

    sop_class, sop_instance, data_bytes, ts_uid, mode = extract_dicom_info(
        dcm_file_path
    )

    if mode == "failed" or data_bytes is None:
        script_log.error("Could not extract data from file. Aborting.")
        return False

    script_log.info(f"Extracted info (mode={mode}):")
    script_log.info(f"  SOP Class UID: {sop_class}")
    script_log.info(f"  SOP Instance UID: {sop_instance}")
    script_log.info(f"  Transfer Syntax: {ts_uid}")
    script_log.info(f"  Dataset size: {len(data_bytes)} bytes")

    session = DICOMSession(
        dst_ip=session_args["ip"],
        dst_port=session_args["port"],
        dst_ae=session_args["ae_title"],
        src_ae=session_args["calling_ae"],
        read_timeout=session_args["timeout"],
    )

    # Request contexts for both Verification and the SOP Class
    requested_contexts = {
        VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
        sop_class: [ts_uid, DEFAULT_TRANSFER_SYNTAX_UID],
    }

    try:
        if session.associate(requested_contexts=requested_contexts):
            script_log.info("Association successful.")

            # Perform C-STORE
            store_status = session.c_store(
                dataset_bytes=data_bytes,
                sop_class_uid=sop_class,
                sop_instance_uid=sop_instance,
                transfer_syntax_uid=ts_uid,
            )

            if store_status is not None:
                script_log.info(f"C-STORE completed. Status: 0x{store_status:04X}")
                if store_status == 0x0000:
                    script_log.info("[PASS] C-STORE succeeded.")
                else:
                    script_log.warning("[INFO] C-STORE returned non-success status.")
            else:
                script_log.error("[FAIL] C-STORE returned None (protocol error).")

            session.release()
        else:
            script_log.error("Association failed.")
            return False
    except Exception as e:
        script_log.exception(f"Exception during C-STORE: {e}")
        return False
    finally:
        session.close()

    script_log.info("=== C-STORE Fuzzing Complete ===")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="DICOM Protocol Fuzzer using scapy_dicom",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fuzz association handshake
  python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode association

  # Fuzz with a specific DICOM file
  python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode cstore_file --fuzzed-file test.dcm

  # Run all fuzzing modes
  python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode all --debug
""",
    )
    parser.add_argument("--ip", required=True, help="IP address of DICOM SCP")
    parser.add_argument("--port", type=int, required=True, help="Port of DICOM SCP")
    parser.add_argument("--ae-title", required=True, help="AE Title of DICOM SCP")
    parser.add_argument(
        "--calling-ae", default="SCAPY_FUZZER", help="Our AE Title (default: SCAPY_FUZZER)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10, help="Network timeout in seconds (default: 10)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--mode",
        choices=["association", "cstore_file", "all"],
        required=True,
        help="Fuzzing mode",
    )
    parser.add_argument(
        "--fuzzed-file",
        help="Path to DICOM file for C-STORE mode (downloads sample if omitted)",
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    )
    logging.getLogger("scapy.contrib.dicom").setLevel(log_level)

    script_log.info(f"=== DICOM Fuzzer Started (Mode: {args.mode}) ===")

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
        target_file = args.fuzzed_file
        if not target_file:
            script_log.info("No --fuzzed-file provided. Using default sample.")
            target_file = DEFAULT_SAMPLE_FILE
            if not ensure_sample_file_exists(target_file):
                script_log.error("Failed to obtain sample file. Aborting C-STORE mode.")
                sys.exit(1)

        fuzz_cstore_with_file(session_params, target_file)

    script_log.info("=== DICOM Fuzzer Finished ===")
    sys.exit(0)


if __name__ == "__main__":
    main()