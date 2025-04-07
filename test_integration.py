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
        PresentationDataValueItem, 
        parse_dimse_status
    )
    from scapy_DICOM import _uid_to_bytes
    from scapy.packet import NoPayload, Raw
except ImportError:
    print("ERROR: Could not import from scapy_DICOM.py.")
    sys.exit(2)

# Configure logging for the test script
log_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)
log = logging.getLogger("dicom_test")

# --- Minimal DIMSE C-ECHO-RQ Builder ---
# Creates C-ECHO RQ bytes using Implicit VR Little Endian
def build_c_echo_rq_dimse(message_id=1):
    """Builds raw bytes for a C-ECHO-RQ DIMSE command message using Implicit VR LE encoding."""
    log.debug(f"Building C-ECHO-RQ DIMSE (Implicit VR LE) (Message ID: {message_id})")
    # Build elements *before* calculating group length
    elements_payload = b''
    affected_sop_uid_bytes = _uid_to_bytes(VERIFICATION_SOP_CLASS_UID)

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
        read_timeout=20 #
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
            # Abort/Close is handled in 'finally' block
            sys.exit(1)
        log.info("Association established!")

        # 2. Prepare C-ECHO-RQ DIMSE Message
        dimse_command_bytes = build_c_echo_rq_dimse(message_id)

        # 3. Find accepted context ID for Verification
        echo_ctx_id = None
        accepted_ts = None
        for ctx_id, (abs_syntax, trn_syntax) in session.accepted_contexts.items():
            if abs_syntax == VERIFICATION_SOP_CLASS_UID:
                 log.info(f"Found accepted context {ctx_id} for Verification ({trn_syntax})")
                 echo_ctx_id = ctx_id
                 accepted_ts = trn_syntax # Store the accepted transfer syntax
                 break

        if not echo_ctx_id:
            log.error("SCP did not accept the Presentation Context for Verification SOP Class.")
            # Abort/Close handled in 'finally'
            sys.exit(1)

        # Optional: Check if the accepted transfer syntax is the one we wanted (Implicit VR LE)
        if accepted_ts != DEFAULT_TRANSFER_SYNTAX_UID:
            log.warning(f"Accepted Transfer Syntax ({accepted_ts}) differs from requested default ({DEFAULT_TRANSFER_SYNTAX_UID}). DIMSE parsing might fail if not Implicit VR LE.")
            # For this test, we assume the SCP accepts Implicit VR LE if it accepts the context.
            # A more robust test might try negotiating Explicit VR LE as well.

        # 4. Create the PresentationDataValueItem object for C-ECHO-RQ
        pdv_to_send = PresentationDataValueItem(
            context_id=echo_ctx_id,
            data=dimse_command_bytes
        )
        pdv_to_send.is_command = True # Mark as DIMSE command
        pdv_to_send.is_last = True    # Mark as last fragment

        # --- EXPLICITLY SET PDV LENGTH ---
        # The PDV length field value is the length of the subsequent fields:
        # context_id (1 byte) + message_control_header (1 byte) + data (N bytes)
        pdv_value_len = 1 + 1 + len(pdv_to_send.data)
        pdv_to_send.length = pdv_value_len
        log.debug(f"Explicitly setting PDV Item length field to: {pdv_to_send.length}")
        # --- END EXPLICIT SET ---

        # 5. Send the PDV Item via P-DATA-TF
        log.info(f"Sending C-ECHO-RQ (Message ID: {message_id}) on context {echo_ctx_id}...")
        # session.send_p_data expects a list of PDV items. We send just one here.
        if not session.send_p_data(pdv_list=[pdv_to_send]): # Pass the modified pdv_to_send
            log.error("Failed to send C-ECHO-RQ P-DATA.")
            # Exit if sending fails, finally block will handle cleanup
            sys.exit(1)
        log.info("C-ECHO-RQ sent successfully via P-DATA-TF.")

        # 6. Wait for response
        log.info("Waiting for C-ECHO response...")
        response_pdata = session.stream.recv() # DICOMSession stream uses DICOM class for dissection

        if not response_pdata:
            log.error("No response received from SCP after sending C-ECHO-RQ (timeout or connection closed).")
            sys.exit(1)

        log.debug(f"Received response packet type: {type(response_pdata)}")
        response_pdata.show() # Show summary
        # log.debug(f"Received response packet details:\n{response_pdata.show(dump=True)}") # More verbose

        # 7. Process the response using the library's dissection
        if response_pdata.haslayer(P_DATA_TF):
            log.info("Received P-DATA-TF response (expected C-ECHO-RSP)")
            pdata_layer = response_pdata[P_DATA_TF]

            # Check if the dissection populated pdv_items
            if not pdata_layer.pdv_items:
                log.error("P-DATA-TF received, but pdv_items list is empty after dissection.")
                # Check for raw payload as a fallback indicator of dissection failure
                if isinstance(pdata_layer.payload, Raw) and pdata_layer.payload.load:
                    log.warning(f"  P-DATA-TF payload contains raw bytes ({len(pdata_layer.payload.load)} bytes), indicating PDV dissection failed in the library.")
                    log.warning(f"  Raw Payload Hex: {pdata_layer.payload.load.hex()}")
                elif not isinstance(pdata_layer.payload, NoPayload):
                     log.warning(f"  P-DATA-TF has unexpected payload type: {type(pdata_layer.payload)}")
                sys.exit(1) # Fail the test if no PDVs were parsed

            # --- Process the dissected PDV items ---
            rsp_processed = False
            for pdv in pdata_layer.pdv_items:
                # Check if it's a properly dissected PDV item (not Raw from failure)
                if not isinstance(pdv, PresentationDataValueItem):
                    log.warning(f"Skipping non-PresentationDataValueItem found in pdv_items: {type(pdv)}")
                    if isinstance(pdv, Raw):
                        log.warning(f"  Raw Data Hex: {pdv.load.hex()}")
                    continue

                log.info(f"  Processing PDV: Context={pdv.context_id}, Cmd={pdv.is_command}, Last={pdv.is_last}, DataLen={len(pdv.data)}")

                # Check if this PDV matches our expectation for the C-ECHO-RSP
                # It should be on the same context, be a command, and be the last fragment
                if pdv.context_id == echo_ctx_id and pdv.is_command and pdv.is_last:
                    if pdv.data:
                        log.info("  Found relevant PDV. Parsing DIMSE status using library function...")
                        # Use the imported parse_dimse_status function
                        status = parse_dimse_status(pdv.data)

                        if status is not None:
                            log.info(f"  Parsed DIMSE Status: 0x{status:04X}")
                            if status == 0x0000:
                                log.info("  C-ECHO Response indicates SUCCESS!")
                                test_success = True
                            else:
                                # Log standard status codes if known, otherwise just hex
                                status_map = {
                                    0x0110: "Processing failure", 0x0112: "No such SOP Class",
                                    0xA700: "Refused: Out of Resources", 0xA900: "Error: Data Set does not match SOP Class",
                                    # Add more common C-ECHO statuses if needed
                                }
                                status_str = status_map.get(status, f"Unknown Status 0x{status:04X}")
                                log.error(f"  C-ECHO Response DIMSE status indicates failure: {status_str} (0x{status:04X})")
                        else:
                            log.error("  Failed to parse DIMSE status from response PDV data using library function.")
                            log.debug(f"  PDV DIMSE Data Hex: {pdv.data.hex()}")
                    else:
                        log.warning("  Found matching PDV, but its data field is empty.")

                    rsp_processed = True # Mark that we found and processed the expected PDV
                    break # Assume only one C-ECHO-RSP PDV is expected per P-DATA-TF

            if not rsp_processed:
                log.error("Did not find a suitable PDV (Command, Last, matching Context ID) in the P-DATA-TF response's items.")

        elif response_pdata.haslayer(A_ABORT):
             log.error(f"Received A-ABORT from peer instead of P-DATA response:")
             response_pdata.show()
             # A-ABORT details (source, reason) are useful
             abort_layer = response_pdata[A_ABORT]
             log.error(f"  Abort Source: {abort_layer.get_field('source').i2s[abort_layer.source]} ({abort_layer.source})")
             log.error(f"  Abort Reason: {abort_layer.get_field('reason_diag').i2s[abort_layer.reason_diag]} ({abort_layer.reason_diag})")
             session.assoc_established = False # Mark association as terminated
        else:
            log.error(f"Received unexpected PDU type response: {response_pdata.summary()}")
            response_pdata.show() # Show the unexpected packet

    except (socket.timeout) as timeout_err:
         log.error(f"Socket timeout during C-ECHO test (read_timeout={session.read_timeout}s): {timeout_err}")
         # Attempt abort, then exit in finally block
         if session and session.stream: session.abort()
         sys.exit(1)
    except (socket.error, ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as sock_err:
        log.error(f"Socket error during test: {sock_err}")
        # Abort/Close handled in 'finally'
        sys.exit(1)
    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}") # Log stack trace
        # Attempt abort, then exit in finally block
        if session and session.stream: session.abort()
        sys.exit(1)
    finally:
        # --- Reliable Cleanup ---
        log.debug("Entering finally block for cleanup...")
        if session:
            if session.assoc_established:
                log.info("Releasing association...")
                if not session.release():
                    log.warning("Association release failed or timed out. Aborting connection.")
                    # session.release() should call abort() on failure, but call again if needed
                    session.abort() # Ensures socket is closed even if release failed internally
            elif session.stream: # Connection exists but not associated
                 log.info("Aborting connection (association not established or release failed).")
                 session.abort()
            else:
                 log.info("No active association or connection to release/abort.")
        log.debug("Cleanup finished.")

    # --- Final Verdict ---
    if test_success:
        log.info("C-ECHO test completed successfully!")
        sys.exit(0)
    else:
        log.error("C-ECHO test failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()