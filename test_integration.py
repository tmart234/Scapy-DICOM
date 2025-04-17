# test_integration.py
import sys
import argparse
import logging

# Assuming scapy_DICOM.py is in the same directory or installable
try:
    from scapy_DICOM import (
        DICOMSession,
        VERIFICATION_SOP_CLASS_UID,
        DEFAULT_TRANSFER_SYNTAX_UID,
    )
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
    parser.add_argument("--timeout", type=int, default=20, help="Association and read timeout in seconds")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("scapy.contrib.dicom").setLevel(logging.DEBUG)

    log.info(f"Starting C-ECHO test against {args.ae_title} at {args.ip}:{args.port}")

    # --- Test Parameters ---
    scp_ip = args.ip
    scp_port = args.port
    scp_ae = args.ae_title
    my_ae = args.calling_ae

    # --- Initialize Session ---
    session = DICOMSession(
        dst_ip=scp_ip,
        dst_port=scp_port,
        dst_ae=scp_ae,
        src_ae=my_ae,
        read_timeout=args.timeout
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
            # Cleanup happens in finally block if needed, but exit here
            sys.exit(1)
        log.info("Association established!")

        # 2. Perform C-ECHO using the new session method
        log.info("Performing C-ECHO...")
        echo_status = session.c_echo() # Call the new method

        # 3. Check the result
        if echo_status == 0x0000:
            log.info("C-ECHO reported SUCCESS (Status 0x0000)")
            test_success = True
        elif echo_status is not None:
            # Map known status codes if desired (optional)
            status_map = {
                0x0110: "Processing failure", 0x0112: "No such SOP Class",
                0xA700: "Refused: Out of Resources", 0xA900: "Error: Data Set does not match SOP Class",
            }
            status_str = status_map.get(echo_status, f"Unknown Status")
            log.error(f"C-ECHO reported failure: {status_str} (Status 0x{echo_status:04X})")
            test_success = False # Explicitly false on non-zero status
        else:
            # c_echo returned None, indicating a lower-level error occurred (logged within c_echo)
            log.error("C-ECHO failed (error during operation, see previous logs).")
            test_success = False

    except Exception as e:
        # Catch unexpected errors during the overall process
        log.exception(f"An unexpected error occurred during the test: {e}")
        test_success = False
        # Attempt abort if connection might still be up
        if session and session.stream:
             session.abort()
    finally:
        # --- Reliable Cleanup ---
        # Ensure association is released or aborted if established
        log.debug("Entering finally block for cleanup...")
        if session:
            if session.assoc_established:
                log.info("Releasing association...")
                if not session.release():
                    log.warning("Association release failed or timed out post-test.")
                    # Abort is likely already called by release() on failure,
                    # but call close() for safety.
                    session.close()
            elif session.stream: # Connection exists but not associated (e.g., assoc failed but connect worked)
                 log.info("Closing connection (association not established).")
                 session.close() # Use close instead of abort if not associated
            else:
                 log.info("No active association or connection to release/close.")
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