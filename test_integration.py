# test_integration.py
import sys
import argparse
import logging
import socket
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
        build_c_echo_rq_dimse,
    )
    from scapy_DICOM import _uid_to_bytes, parse_dimse_status
    from scapy.packet import NoPayload, Raw
except ImportError:
    print("ERROR: Could not import from scapy_DICOM.py.")
    sys.exit(2)

# Configure logging for the test script
log_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)
log = logging.getLogger("dicom_test")


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
        status_map = {
            0x0000: "Success", # Add success for completeness if needed elsewhere
            0x0110: "Processing failure",
            0x0112: "No such SOP Class",
            0xA700: "Refused: Out of Resources",
            0xA900: "Error: Data Set does not match SOP Class",
            # Add more common C-ECHO statuses if needed
        }
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
            context_id=echo_ctx_id
            # message_control_header can be set via properties later
        )
        # Assign data and flags explicitly as attributes
        pdv_to_send.data = dimse_command_bytes # Assign data directly
        pdv_to_send.is_command = True # Mark as DIMSE command
        pdv_to_send.is_last = True    # Mark as last fragment


        # 5. Send the PDV Item via P-DATA-TF
        log.info(f"Sending C-ECHO-RQ (Message ID: {message_id}) on context {echo_ctx_id}...")
        # session.send_p_data expects a list of PDV items. We send just one here.
        # Pass the pdv_to_send object directly; its length will be calculated during serialization.
        if not session.send_p_data(pdv_list=[pdv_to_send]):
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

            # Check the new attribute where manually parsed items are stored
            if not hasattr(pdata_layer, 'parsed_pdv_items') or not pdata_layer.parsed_pdv_items:
                log.error("P-DATA-TF received, but parsed_pdv_items list is empty or missing after dissection.")
                # Check for raw payload on P_DATA_TF itself as fallback
                if isinstance(pdata_layer.payload, Raw) and pdata_layer.payload.load:
                     log.warning(f"  P-DATA-TF payload contains raw bytes ({len(pdata_layer.payload.load)} bytes), possibly indicating dissection error before PDV parsing.")
                     log.warning(f"  Raw Payload Hex: {pdata_layer.payload.load.hex()}")
                elif not isinstance(pdata_layer.payload, NoPayload):
                     log.warning(f"  P-DATA-TF has unexpected payload type: {type(pdata_layer.payload)}")
                sys.exit(1) # Fail the test if no PDVs were parsed

            # --- Process the manually parsed PDV items ---
            rsp_processed = False
            # Iterate through the new list
            for pdv in pdata_layer.parsed_pdv_items:
                # Check if it's a properly parsed PDV item (not Raw from failure within the loop)
                if not isinstance(pdv, PresentationDataValueItem):
                    log.warning(f"Skipping non-PresentationDataValueItem found in parsed_pdv_items: {type(pdv)}")
                    if isinstance(pdv, Raw):
                        log.warning(f"  Raw Data Hex: {pdv.load.hex()}")
                    continue

                log.info(f"  Processing PDV: Context={pdv.context_id}, Cmd={pdv.is_command}, Last={pdv.is_last}, DataLen={len(pdv.data)}")

                # Check if this PDV matches our expectation for the C-ECHO-RSP
                if pdv.context_id == echo_ctx_id and pdv.is_command and pdv.is_last:
                    if pdv.data:
                        log.info("  Found relevant PDV. Parsing DIMSE status using library function...")
                        status = parse_dimse_status(pdv.data) # Use the pdv.data attribute

                        if status is not None:
                            log.info(f"  Parsed DIMSE Status: 0x{status:04X}")
                            if status == 0x0000:
                                log.info("  C-ECHO Response indicates SUCCESS!")
                                test_success = True
                            else:
                                # ... (status code mapping remains the same) ...
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