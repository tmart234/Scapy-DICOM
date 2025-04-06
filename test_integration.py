# test_integration.py
import sys
import argparse
import logging
import socket
import struct
import time

# Assuming scapy_DICOM.py is in the same directory or installable
try:
    from scapy_DICOM import (
        DICOMSession,
        VERIFICATION_SOP_CLASS_UID,
        DEFAULT_TRANSFER_SYNTAX_UID,
        P_DATA_TF,
        A_ABORT,
    )
    from scapy_DICOM import _uid_to_bytes # Import helper if needed
except ImportError:
    print("ERROR: Could not import DICOMSession from scapy_DICOM.py.")
    print("Ensure scapy_DICOM.py is in the same directory or PYTHONPATH.")
    sys.exit(2)

# Configure logging for the test script
log_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)
log = logging.getLogger("dicom_test")

# --- Minimal DIMSE C-ECHO-RQ Builder ---
# Creates C-ECHO RQ bytes using Implicit VR Little Endian
def build_c_echo_rq_dimse(message_id=1):
    """Builds raw bytes for a C-ECHO-RQ DIMSE command message."""
    log.debug(f"Building C-ECHO-RQ DIMSE (Message ID: {message_id})")
    dimse_command_set = b''
    affected_sop_uid_bytes = _uid_to_bytes(VERIFICATION_SOP_CLASS_UID)

    # (0000,0002) Affected SOP Class UID - Tag, VR, Len, Value
    # Need explicit VR 'UI' for DIMSE command elements, even in Implicit TS negotiation! (PS3.7 6.3.1)
    dimse_command_set += struct.pack("<HH", 0x0000, 0x0002) + b'UI' + struct.pack("<H", len(affected_sop_uid_bytes)) + affected_sop_uid_bytes

    # (0000,0100) Command Field (C-ECHO-RQ = 0x0030) - Tag, VR, Len, Value
    dimse_command_set += struct.pack("<HH", 0x0000, 0x0100) + b'US' + struct.pack("<HH", 2, 0x0030)

    # (0000,0110) Message ID - Tag, VR, Len, Value
    dimse_command_set += struct.pack("<HH", 0x0000, 0x0110) + b'US' + struct.pack("<HH", 2, message_id)

    # (0000,0800) Command Data Set Type (0x0101 = No dataset) - Tag, VR, Len, Value
    dimse_command_set += struct.pack("<HH", 0x0000, 0x0800) + b'US' + struct.pack("<HH", 2, 0x0101)

    # (0000,0000) Command Group Length - Tag, VR, Len, Value
    cmd_group_len = len(dimse_command_set) # Length of elements *after* this one
    dimse_command_set = struct.pack("<HH", 0x0000, 0x0000) + b'UL' + struct.pack("<HI", 4, cmd_group_len) + dimse_command_set

    log.debug(f"Built DIMSE Command Set (len={len(dimse_command_set)}): {dimse_command_set.hex()}")
    return dimse_command_set

# --- Minimal DIMSE C-ECHO-RSP Parser ---
def check_c_echo_rsp(dimse_bytes):
    """Very basic check for Success status in a C-ECHO-RSP."""
    try:
        offset = 0
        # Look for Command Group Length (0000,0000) UL 4 bytes_len
        tag_group, tag_elem = struct.unpack("<HH", dimse_bytes[offset:offset+4])
        vr = dimse_bytes[offset+4:offset+6]
        length_format = "<H" if vr in [b'OB', b'OW', b'OF', b'SQ', b'UT', b'UN'] else "<H" # Adjust based on VR if needed, assume short for now
        value_len = struct.unpack(length_format, dimse_bytes[offset+6:offset+8])[0]
        offset += 8 # Move past tag, vr, len
        # command_group_length = struct.unpack("<I", dimse_bytes[offset:offset+4])[0]
        offset += value_len # Skip group length value

        status_found = False
        while offset < len(dimse_bytes):
             # Read Tag (Group, Element)
            tag_group, tag_elem = struct.unpack("<HH", dimse_bytes[offset:offset+4])
            vr = dimse_bytes[offset+4:offset+6]
            value_len = struct.unpack(length_format, dimse_bytes[offset+6:offset+8])[0] # Assuming short length format
            offset += 8

            if tag_group == 0x0000 and tag_elem == 0x0900: # Status tag
                if vr == b'US' and value_len == 2:
                    status = struct.unpack("<H", dimse_bytes[offset:offset+value_len])[0]
                    log.info(f"Found Status (0000,0900): 0x{status:04X}")
                    return status == 0x0000 # Success
                else:
                    log.warning(f"Status tag (0000,0900) found but VR/Len mismatch (VR:{vr}, Len:{value_len})")
                    return False
            # Move to next element
            offset += value_len
            # Add alignment padding if VR requires it (not handled in this simple parser)

        log.warning("Status tag (0000,0900) not found in response DIMSE.")
        return False
    except Exception as e:
        log.error(f"Error parsing DIMSE response: {e}")
        log.error(f"DIMSE Data: {dimse_bytes.hex()}")
        return False


def main():
    parser = argparse.ArgumentParser(description="DICOM C-ECHO Integration Test using Scapy")
    parser.add_argument("--ip", required=True, help="IP address of the DICOM SCP")
    parser.add_argument("--port", type=int, required=True, help="Port number of the DICOM SCP")
    parser.add_argument("--ae-title", required=True, help="AE Title of the DICOM SCP (Called AE Title)")
    parser.add_argument("--calling-ae", default="SCAPY_TEST_SCU", help="Calling AE Title for this SCU")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("scapy.contrib.dicom").setLevel(logging.DEBUG) # Enable debug for the layer too

    log.info(f"Starting C-ECHO test against {args.ae_title} at {args.ip}:{args.port}")

    # --- Test Parameters ---
    scp_ip = args.ip
    scp_port = args.port
    scp_ae = args.ae_title
    my_ae = args.calling_ae
    message_id = int(time.time()) % 10000 # Semi-unique message ID

    # --- Initialize Session ---
    session = DICOMSession(
        dst_ip=scp_ip,
        dst_port=scp_port,
        dst_ae=scp_ae,
        src_ae=my_ae,
        read_timeout=15 # Reasonably short timeout for CI
    )

    # --- Define Context for Verification SOP Class ---
    verification_context = {
        VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
    }

    test_success = False
    try:
        # 1. Associate
        log.info("Attempting association...")
        if not session.associate(requested_contexts=verification_context):
            log.error("Association failed.")
            sys.exit(1)
        log.info("Association established!")

        # 2. Prepare C-ECHO-RQ DIMSE Message
        dimse_command_bytes = build_c_echo_rq_dimse(message_id)

        # 3. Find accepted context ID for Verification
        echo_ctx_id = None
        for ctx_id, (abs_syntax, trn_syntax) in session.accepted_contexts.items():
            if abs_syntax == VERIFICATION_SOP_CLASS_UID:
                 log.info(f"Found accepted context {ctx_id} for Verification ({trn_syntax})")
                 echo_ctx_id = ctx_id
                 break

        if not echo_ctx_id:
            log.error("SCP did not accept the Presentation Context for Verification SOP Class.")
            sys.exit(1)

        # 4. Send C-ECHO-RQ via P-DATA-TF
        log.info(f"Sending C-ECHO-RQ (Message ID: {message_id}) on context {echo_ctx_id}...")
        if not session.send_p_data(context_id=echo_ctx_id, data=dimse_command_bytes, is_command=True, is_last=True):
            log.error("Failed to send C-ECHO-RQ P-DATA.")
            sys.exit(1)
        log.info("C-ECHO-RQ sent successfully via P-DATA-TF.")

        # 5. Wait for C-ECHO-RSP via P-DATA-TF
        log.info("Waiting for C-ECHO response...")
        response_pdata = session.stream.recv() # Use the stream associated with the session

        if not response_pdata:
            log.error("No response received from SCP after sending C-ECHO-RQ.")
            sys.exit(1)

        log.debug(f"Received response packet:\n{response_pdata.show(dump=True, show_indent=False)}")

        if response_pdata.haslayer(P_DATA_TF):
            log.info("Received P-DATA-TF response (expected C-ECHO-RSP)")
            # Basic validation: Check if it contains a PDV for the correct context
            rsp_pdv = None
            for pdv in response_pdata[P_DATA_TF].pdv_items:
                log.info(f"  PDV Context: {pdv.context_id}, Command: {pdv.is_command}, Last: {pdv.is_last}, Data Len: {len(pdv.data)}")
                if pdv.context_id == echo_ctx_id and pdv.is_command and pdv.is_last:
                    rsp_pdv = pdv
                    break # Found the likely response PDV

            if rsp_pdv:
                log.info("Found relevant PDV in response.")
                # Validate the DIMSE status
                if check_c_echo_rsp(rsp_pdv.data):
                    log.info("C-ECHO Response indicates SUCCESS!")
                    test_success = True
                else:
                    log.error("C-ECHO Response DIMSE status check failed (Status != Success or parse error).")
            else:
                 log.error("Did not find a suitable PDV (Command, Last, matching Context ID) in the P-DATA-TF response.")

        elif response_pdata.haslayer(A_ABORT):
             log.error(f"Received A-ABORT from peer instead of P-DATA response:\n{response_pdata.show(dump=True, show_indent=False)}")
        else:
            log.error(f"Received unexpected PDU type response: {response_pdata.summary()}")

    except (socket.timeout):
         log.error("Socket timeout during C-ECHO test.")
         sys.exit(1)
    except (socket.error, ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as sock_err:
        log.error(f"Socket error during test: {sock_err}")
        sys.exit(1)
    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}") # Log stack trace
        sys.exit(1)
    finally:
        # 6. Release Association (or Abort if needed)
        if session.assoc_established:
            log.info("Releasing association...")
            if not session.release():
                 log.warning("Association release failed or timed out. Aborting.")
                 session.abort() # Attempt abort if release fails cleanly
        elif session.stream: # If connection exists but not associated
             log.info("Aborting connection (was not associated or release failed).")
             session.abort()
        else:
             log.info("No active association or connection to release/abort.")

    # --- Final Verdict ---
    if test_success:
        log.info("C-ECHO test completed successfully!")
        sys.exit(0)
    else:
        log.error("C-ECHO test failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()