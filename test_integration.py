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

# --- Minimal DIMSE C-ECHO-RSP Parser ---
def check_c_echo_rsp(dimse_bytes):
    """Checks for Success status (0x0000) in an Implicit VR LE DIMSE response."""
    try:
        offset = 0
        log.debug(f"Checking DIMSE RSP (Implicit VR LE) (Len={len(dimse_bytes)}): {dimse_bytes.hex()}")
        if len(dimse_bytes) < 8: # Need at least tag + len
            log.warning("DIMSE response too short for Tag+Length.")
            return False

        # --- Response structure ---
        # Command Group Length (0000,0000) UL 4 value=??
        # Affected SOP Class UID (0000,0002) UI ?? value=?? (Optional in RSP)
        # Command Field (0000,0100) US 2 value=0x8030 (RSP)
        # Message ID Being Responded To (0000,0120) US 2 value=??
        # Command Data Set Type (0000,0800) US 2 value=0x0101
        # Status (0000,0900) US 2 value=0x0000 (Success)
        # Optional fields (Error Comment, etc.)

        # Read Command Group Length element (Tag + 4-byte Length)
        tag_group, tag_elem = struct.unpack("<HH", dimse_bytes[offset:offset+4])
        value_len = struct.unpack("<I", dimse_bytes[offset+4:offset+8])[0]
        offset += 8 # Skip Tag and Len
        log.debug(f"  Tag: (0000,0000), Len: 4, Value (GroupLen): {value_len}")
        offset += value_len # Skip Group Length Value itself (we don't use it)

        status_found = False
        success_status = False
        while offset < len(dimse_bytes):
            if offset + 8 > len(dimse_bytes):
                 log.warning(f"Truncated element header at offset {offset}.")
                 break

            # Read Tag (4 bytes) + Length (4 bytes) for Implicit VR
            tag_group, tag_elem = struct.unpack("<HH", dimse_bytes[offset:offset+4])
            value_len = struct.unpack("<I", dimse_bytes[offset+4:offset+8])[0]
            data_offset = offset + 8
            next_element_offset = data_offset + value_len

            log.debug(f"  Tag: ({tag_group:04X},{tag_elem:04X}), Len: {value_len}, Data Offset: {data_offset}")

            if next_element_offset > len(dimse_bytes):
                log.warning(f"Element ({tag_group:04X},{tag_elem:04X}) length ({value_len}) exceeds available data ({len(dimse_bytes) - data_offset} left).")
                break

            if tag_group == 0x0000 and tag_elem == 0x0900: # Status tag
                status_found = True
                if value_len == 2: # Status is US (2 bytes)
                    status_bytes = dimse_bytes[data_offset:next_element_offset]
                    status = struct.unpack("<H", status_bytes)[0]
                    log.info(f"Parsed Status (0000,0900): 0x{status:04X}")
                    success_status = (status == 0x0000)
                    break # Found status, no need to parse further for this check
                else:
                    log.warning(f"Status tag (0000,0900) found but value length is {value_len}, expected 2.")
                    break # Treat unexpected length as failure

            # Move to next element
            offset = next_element_offset

        if not status_found:
            log.warning("Status tag (0000,0900) not found in response DIMSE.")

        return success_status # Return True only if Success status was found

    except struct.error as e:
        log.error(f"Struct unpack error parsing DIMSE response: {e}")
        log.error(f"DIMSE Data near offset {offset}: {dimse_bytes[max(0,offset-4):offset+12].hex()}")
        return False
    except Exception as e:
        log.exception(f"Unexpected error parsing DIMSE response: {e}")
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
            sys.exit(1) # Exit if association fails
        log.info("Association established!")

        # 2. Prepare C-ECHO-RQ DIMSE Message
        dimse_command_bytes = build_c_echo_rq_dimse(message_id)

        # 3. Find accepted context ID for Verification
        echo_ctx_id = None
        for ctx_id, (abs_syntax, trn_syntax) in session.accepted_contexts.items():
            if abs_syntax == VERIFICATION_SOP_CLASS_UID:
                 log.info(f"Found accepted context {ctx_id} for Verification ({trn_syntax})")
                 echo_ctx_id = ctx_id
                 break # Found the context, no need to check further

        if not echo_ctx_id:
            log.error("SCP did not accept the Presentation Context for Verification SOP Class.")
            # No point continuing if we don't have the context
            # The finally block will handle release/abort
            sys.exit(1)

        # 4. Create the PresentationDataValueItem object for C-ECHO-RQ
        # This object represents the data to be sent within a P-DATA-TF PDU.
        pdv_to_send = PresentationDataValueItem(
            context_id=echo_ctx_id,        # Which presentation context this data belongs to
            data=dimse_command_bytes       # The actual DIMSE command bytes
        )
        # Set the flags within the PDV's message control header
        pdv_to_send.is_command = True # Mark this data as a DIMSE command
        pdv_to_send.is_last = True    # Mark this as the last (and only) fragment for this command

        # 5. Send the PDV Item via P-DATA-TF using the session method
        log.info(f"Sending C-ECHO-RQ (Message ID: {message_id}) on context {echo_ctx_id}...")
        # session.send_p_data expects a list of PDV items. We send just one here.
        if not session.send_p_data(pdv_list=[pdv_to_send]):
            log.error("Failed to send C-ECHO-RQ P-DATA.")
            # Exit if sending fails, finally block will handle cleanup
            sys.exit(1)
        log.info("C-ECHO-RQ sent successfully via P-DATA-TF.")

        # 6. Wait for response
        log.info("Waiting for C-ECHO response...")
        response_pdata = session.stream.recv()

        if not response_pdata:
            log.error("No response received from SCP after sending C-ECHO-RQ (connection likely closed).")
            sys.exit(1)

        log.debug(f"Received response packet:\n{response_pdata.show(dump=True)}")

        # 7. Process the response
        if response_pdata.haslayer(P_DATA_TF):
            log.info("Received P-DATA-TF response (expected C-ECHO-RSP)")

            # +++ RESTORED MANUAL PARSING of PDV Items +++
            pdv_items_list = []
            pdata_payload_bytes = b''
            pdata_tf_layer = response_pdata[P_DATA_TF]

            # --- Revised Byte Extraction Logic ---
            # Check if pdv_items field contains a Raw layer list element
            if pdata_tf_layer.pdv_items and isinstance(pdata_tf_layer.pdv_items[0], Raw):
                log.debug("Extracting P-DATA payload from Raw layer inside pdv_items list.")
                # Assume all bytes are in the first Raw element if dissection failed this way
                pdata_payload_bytes = bytes(pdata_tf_layer.pdv_items[0].load)
            # Fallback: Check the generic payload attribute (might hold Raw)
            elif hasattr(pdata_tf_layer.payload, 'load') and isinstance(pdata_tf_layer.payload.load, (bytes, bytearray)):
                log.debug("Extracting P-DATA payload from Raw layer in generic payload.")
                pdata_payload_bytes = bytes(pdata_tf_layer.payload.load)
            # Fallback: Check if payload is bytes directly
            elif isinstance(pdata_tf_layer.payload, (bytes, bytearray)):
                log.debug("Extracting P-DATA payload from direct bytes payload.")
                pdata_payload_bytes = bytes(pdata_tf_layer.payload)
            elif not isinstance(pdata_tf_layer.payload, NoPayload):
                 try:
                     log.warning(f"Attempting byte conversion from unexpected P_DATA_TF payload type {type(pdata_tf_layer.payload)}.")
                     pdata_payload_bytes = bytes(pdata_tf_layer.payload)
                 except Exception:
                     log.warning(f"Could not get bytes from unexpected P_DATA_TF payload type {type(pdata_tf_layer.payload)}.")
            # --- End Revised Logic ---

            if not pdata_payload_bytes:
                 log.error("Failed to extract raw payload bytes for P-DATA-TF.")
            else:
                log.debug(f"Manually parsing {len(pdata_payload_bytes)} bytes of P-DATA payload.")
                offset = 0
                total_len = len(pdata_payload_bytes)
                while offset < total_len:
                    if offset + 4 > total_len: break
                    pdv_len = struct.unpack("!I", pdata_payload_bytes[offset:offset+4])[0]
                    pdv_item_start_offset = offset + 4
                    pdv_item_end_offset = pdv_item_start_offset + pdv_len
                    if pdv_item_end_offset > total_len: break

                    full_pdv_bytes_for_dissection = pdata_payload_bytes[offset:pdv_item_end_offset]
                    try:
                        parsed_pdv = PresentationDataValueItem(full_pdv_bytes_for_dissection)
                        log.debug(f"Successfully parsed PDV item: {parsed_pdv.summary()}")
                        pdv_items_list.append(parsed_pdv)
                    except Exception as e_pdv_parse:
                        log.error(f"Failed to parse extracted PDV item bytes: {e_pdv_parse}")
                    offset = pdv_item_end_offset
            # +++ END RESTORED MANUAL PARSING +++

            # Now iterate through the MANUALLY parsed list
            rsp_pdv = None
            for pdv in pdv_items_list: # Iterate parsed list
                try:
                    # Access fields directly on the parsed object
                    log.info(f"  PDV Context: {pdv.context_id}, Command: {pdv.is_command}, Last: {pdv.is_last}, Data Len: {len(pdv.data)}")
                    if pdv.context_id == echo_ctx_id and pdv.is_command and pdv.is_last:
                        if pdv.data:
                             rsp_pdv = pdv
                             break
                        else:
                             log.warning("  Found matching PDV, but its data field is empty after parsing.")
                except AttributeError as e:
                     log.error(f"  AttributeError accessing manually parsed PDV fields: {e}. PDV was: {pdv.summary() if hasattr(pdv, 'summary') else pdv}")

            if rsp_pdv:
                log.info("Found relevant PDV in response with data.")
                # Validate the DIMSE status using the CORRECTED Implicit VR parser
                if check_c_echo_rsp(rsp_pdv.data):
                    log.info("C-ECHO Response indicates SUCCESS!")
                    test_success = True
                else:
                    log.error("C-ECHO Response DIMSE status check failed (Status != Success or parse error).")
            else:
                 log.error("Did not find a suitable PDV (Command, Last, matching Context ID, with data) in the P-DATA-TF response.")

        elif response_pdata.haslayer(A_ABORT):
             log.error(f"Received A-ABORT from peer instead of P-DATA response:\n{response_pdata.show(dump=True)}")
             session.assoc_established = False
        else:
            log.error(f"Received unexpected PDU type response: {response_pdata.summary()}\n{response_pdata.show(dump=True)}")

    except (socket.timeout) as timeout_err:
         log.error(f"Socket timeout during C-ECHO test: {timeout_err}")
         sys.exit(1) # Exit, finally block handles cleanup
    except (socket.error, ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as sock_err:
        log.error(f"Socket error during test: {sock_err}")
        sys.exit(1) # Exit, finally block handles cleanup
    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}") # Log stack trace
        sys.exit(1) # Exit, finally block handles cleanup
    finally:
        # This block always runs, ensuring cleanup happens regardless of success or failure
        log.debug("Entering finally block for cleanup...")
        # 6. Release Association (or Abort if needed)
        if session and session.assoc_established:
            log.info("Releasing association...")
            if not session.release():
                 log.warning("Association release failed or timed out. Aborting instead.")
                 # session.release() calls abort() internally on failure/timeout
                 # but we call it again just to be sure connection is closed.
                 session.abort()
        elif session and session.stream: # If connection exists but not associated (e.g., associate failed, or release failed badly)
             log.info("Aborting connection (was not associated or release failed).")
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