# test_dicom_layer.py
import pytest
import struct
import logging
import time
import uuid
import sys
import os

# Mute Scapy's verbose warnings for this demonstration
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.contrib.dicom").setLevel(logging.DEBUG)

# Add project root to path to allow finding scapy_dicom in CI environments
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))
# Import all classes and functions from the custom DICOM layer
# This assumes the layer file is named 'scapy_dicom.py'
try:
    from scapy_dicom import *
except ImportError:
    print("[-] ERROR: Could not import the DICOM layer.")
    print("[-] Please ensure the DICOM layer script is saved as 'scapy_dicom.py' in the same directory.")
    exit(1)

# --- Group 1: Layer Unit & Validation Tests ---
# These tests validate the layer's ability to build and parse various PDUs.

class TestCoreLayerValidation:

    def test_req_001_and_006_parse_associate_rq_ac(self):
        """REQ-001/006: Validates parsing of A-ASSOCIATE-RQ/AC."""
        app_context = DICOMVariableItem(item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID))
        pres_context = PresentationContextRQItem(context_id=1, sub_item_data=bytes(AbstractSyntaxSubItem(abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID)) + bytes(TransferSyntaxSubItem(transfer_syntax_uid=DEFAULT_TRANSFER_SYNTAX_UID)))
        user_info = UserInformationItem(user_data_subitems=bytes(MaxLengthSubItem(max_length_received=16384)))
        
        pkt = DICOM() / A_ASSOCIATE_RQ(calling_ae_title=b'VALIDATOR', called_ae_title=b'TEST_SCP')
        pkt[A_ASSOCIATE_RQ].variable_items = [app_context, pres_context, user_info]

        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.pdu_type == 0x01
        assert reparsed_pkt.haslayer(A_ASSOCIATE_RQ)
        # A more detailed check could assert on the number of variable items parsed
        assert len(reparsed_pkt[A_ASSOCIATE_RQ].variable_items) == 3

    def test_req_009_parse_associate_rj(self):
        """REQ-009: Validates parsing of A-ASSOCIATE-RJ."""
        pkt = DICOM() / A_ASSOCIATE_RJ(result=1, source=2, reason_diag=2)
        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.pdu_type == 0x03
        assert reparsed_pkt.haslayer(A_ASSOCIATE_RJ)
        assert reparsed_pkt[A_ASSOCIATE_RJ].source == 2

    def test_req_011_parse_pdata_tf(self):
        """REQ-011: Validates parsing of P-DATA-TF with fragments."""
        pdv1 = PresentationDataValueItem(context_id=1, data=b'\xDE\xAD', is_command=True, is_last=False)
        pdv2 = PresentationDataValueItem(context_id=1, data=b'\xBE\xEF', is_command=False, is_last=True)
        pkt = DICOM() / P_DATA_TF()
        pkt.parsed_pdv_items = [pdv1, pdv2]

        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.pdu_type == 0x04
        assert reparsed_pkt.haslayer(P_DATA_TF)
        # The custom dissector should populate parsed_pdv_items
        assert len(reparsed_pkt[P_DATA_TF].parsed_pdv_items) == 2
        assert reparsed_pkt[P_DATA_TF].parsed_pdv_items[1].data == b'\xBE\xEF'

    @pytest.mark.parametrize("pdu_type, layer_class", [
        (0x05, A_RELEASE_RQ),
        (0x06, A_RELEASE_RP),
        (0x07, A_ABORT),
    ])
    def test_req_015_016_017_parse_simple_pdus(self, pdu_type, layer_class):
        """REQ-015/016/017: Validates parsing of simple PDUs."""
        pkt = DICOM(pdu_type=pdu_type) / layer_class()
        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.pdu_type == pdu_type
        assert reparsed_pkt.haslayer(layer_class)

    def test_req_023_construct_pdata_with_cecho(self):
        """REQ-023: Validates construction of a P-DATA-TF with a C-ECHO-RQ."""
        c_echo_dimse = build_c_echo_rq_dimse(message_id=123)
        pdv_echo = PresentationDataValueItem(context_id=1, data=c_echo_dimse, is_command=True, is_last=True)
        pkt = DICOM(pdu_type=0x04) / P_DATA_TF()
        pkt.parsed_pdv_items = [pdv_echo]
        
        raw_bytes = bytes(pkt)
        assert raw_bytes.startswith(b'\x04\x00') # P-DATA-TF type
        # Check that the DIMSE payload is present
        assert c_echo_dimse in raw_bytes

    def test_req_024_construct_pdata_with_cmd_and_data(self):
        """REQ-024: Validates construction of P-DATA-TF with separate Command and Data PDVs."""
        pdv_cmd = PresentationDataValueItem(context_id=3, data=b'\x01\x02', is_command=True, is_last=True)
        pdv_data = PresentationDataValueItem(context_id=3, data=b'\xAA\xBB', is_command=False, is_last=True)
        pkt = DICOM() / P_DATA_TF()
        pkt.parsed_pdv_items = [pdv_cmd, pdv_data]
        
        reparsed_pkt = DICOM(bytes(pkt))
        assert len(reparsed_pkt[P_DATA_TF].parsed_pdv_items) == 2


# --- Group 2: Basic Fuzzing & Manipulation Tests ---
# These tests validate the layer's flexibility for creating non-standard/malformed packets.

class TestBasicFuzzingCapabilities:

    def test_req_002_oversized_ae_title(self):
        """REQ-002: Can create a packet with an oversized AE Title."""
        oversized_title = b'A' * 25
        pkt = DICOM() / A_ASSOCIATE_RQ(called_ae_title=oversized_title)
        assert bytes(pkt)[10:35] == oversized_title

    def test_req_004_too_many_presentation_contexts(self):
        """REQ-004: Can create a packet with more than 128 presentation contexts."""
        contexts = [PresentationContextRQItem(context_id=(i*2)+1) for i in range(130)]
        pkt = DICOM() / A_ASSOCIATE_RQ()
        pkt[A_ASSOCIATE_RQ].variable_items = contexts
        
        reparsed_pkt = DICOM(bytes(pkt))
        assert len(reparsed_pkt[A_ASSOCIATE_RQ].variable_items) == 130

    def test_req_005_manipulate_user_info(self):
        """REQ-005: Can create a User Info item with an absurdly large Max PDU length."""
        user_info = UserInformationItem(user_data_subitems=bytes(MaxLengthSubItem(max_length_received=0x7FFFFFFF)))
        pkt = DICOM() / A_ASSOCIATE_RQ()
        pkt[A_ASSOCIATE_RQ].variable_items = [user_info]
        
        reparsed_pkt = DICOM(bytes(pkt))
        # This requires a deeper dissection of the variable items, which is complex.
        # For now, we assert that the packet can be built without error.
        assert b'\x51\x00\x00\x04\x7f\xff\xff\xff' in bytes(pkt) # Type, Res, Len, Value

    @pytest.mark.parametrize("pdu_class, field, value", [
        (A_ASSOCIATE_RJ, "reason_diag", 255),
        (A_ABORT, "source", 1), # 1 is a reserved/invalid value
    ])
    def test_req_010_018_invalid_enums(self, pdu_class, field, value):
        """REQ-010/018: Can create packets with invalid enum values."""
        pkt = DICOM() / pdu_class(**{field: value})
        reparsed_pkt = DICOM(bytes(pkt))
        assert getattr(reparsed_pkt[pdu_class], field) == value

    def test_req_013_illogical_fragmentation(self):
        """REQ-013: Can create a P-DATA-TF where the first fragment is not marked as last."""
        pdv = PresentationDataValueItem(context_id=1, data=b'first_and_only_fragment...or_is_it', is_last=False)
        pkt = DICOM() / P_DATA_TF()
        pkt.parsed_pdv_items = [pdv]

        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt[P_DATA_TF].parsed_pdv_items[0].is_last == 0

    def test_req_025_incorrect_command_group_length(self):
        """REQ-025: Can encapsulate a DIMSE message with an incorrect Command Group Length."""
        c_echo_dimse = build_c_echo_rq_dimse(message_id=456)
        corrupt_dimse = c_echo_dimse[:8] + struct.pack("<I", 1000) + c_echo_dimse[12:]
        pdv = PresentationDataValueItem(context_id=1, is_command=True, is_last=True, data=corrupt_dimse)
        pkt = DICOM() / P_DATA_TF()
        pkt.parsed_pdv_items = [pdv]

        assert corrupt_dimse in bytes(pkt)

    def test_req_l01_pdu_type_confusion(self):
        """REQ-L01: Can create a packet with a mismatched header type and payload layer."""
        pkt = DICOM(pdu_type=0x04) / A_ASSOCIATE_RQ() # Header says P-DATA-TF, payload is A-ASSOCIATE-RQ
        raw_bytes = bytes(pkt)
        assert raw_bytes[0] == 0x04
        assert raw_bytes[6:10] == b'\x00\x01\x00\x00' # Protocol version from A_ASSOCIATE_RQ

    def test_req_l02_integer_overflow_in_length(self):
        """REQ-L02: Can create a packet with a max value in the PDU length field."""
        pkt = DICOM(length=0xFFFFFFFF) / A_RELEASE_RQ()
        assert bytes(pkt)[2:6] == b'\xff\xff\xff\xff'

    def test_req_l05_null_byte_injection(self):
        """REQ-L05: Can create a packet with a NULL byte in an AE Title."""
        injected_title = b'SCAPY\x00FUZZER'.ljust(16)
        pkt = DICOM() / A_ASSOCIATE_RQ(calling_ae_title=injected_title)
        assert bytes(pkt)[26:42] == injected_title


# --- Group 3: Advanced Fuzzing & State Machine Tests ---
# NEW tests for more complex, stateful, and resource-based attacks.

class TestAdvancedFuzzingTechniques:

    def test_req_l11_state_confusion(self):
        """REQ-L11: Can build a P-DATA-TF PDU without a preceding association context."""
        # The test is that we CAN build this. Sending it out of order is the fuzzer's job.
        pdv = PresentationDataValueItem(context_id=1, data=b'some data')
        pkt = DICOM() / P_DATA_TF()
        pkt.parsed_pdv_items = [pdv]
        
        # The assertion is that the packet builds without error and has the correct type.
        assert pkt.pdu_type == 0x04
        assert b'some data' in bytes(pkt)

    def test_req_l12_resource_exhaustion_incomplete_pdu(self):
        """REQ-L12: Can build a PDU with a large declared length but a truncated payload."""
        # Create a PDU header with a large length
        pdu_header = DICOM(pdu_type=0x04, length=1024 * 1024) # Declare 1MB length
        # Provide a payload that is much smaller
        payload = b'\x01\x02\x03\x04'
        
        # Manually construct the raw bytes to simulate a truncated send
        raw_pkt = bytes(pdu_header)[:-4] + payload # Remove Scapy's auto-calculated length and add our own
        
        # The test is that we can construct the header as desired
        assert raw_pkt.startswith(b'\x04\x00')
        assert struct.unpack("!I", raw_pkt[2:6])[0] == 1024 * 1024
        assert len(raw_pkt) == 6 + len(payload) # 6 byte header + small payload

    def test_req_l13_advanced_fragmentation_interleaving(self):
        """REQ-L13: Demonstrates the layer can build interleaved fragments for different contexts."""
        # This test shows the *capability* to build the necessary list of PDVs.
        # The fuzzer would be responsible for sending them one by one.
        pdv_a1 = PresentationDataValueItem(context_id=1, data=b'context A part 1', is_last=False)
        pdv_b1 = PresentationDataValueItem(context_id=3, data=b'context B part 1', is_last=False)
        pdv_a2 = PresentationDataValueItem(context_id=1, data=b'context A part 2', is_last=True)
        pdv_b2 = PresentationDataValueItem(context_id=3, data=b'context B part 2', is_last=True)
        
        # A fuzzer could create a list of individual P-DATA-TF packets to send in order
        pkt_a1 = DICOM() / P_DATA_TF(); pkt_a1.parsed_pdv_items = [pdv_a1]
        pkt_b1 = DICOM() / P_DATA_TF(); pkt_b1.parsed_pdv_items = [pdv_b1]
        pkt_a2 = DICOM() / P_DATA_TF(); pkt_a2.parsed_pdv_items = [pdv_a2]
        pkt_b2 = DICOM() / P_DATA_TF(); pkt_b2.parsed_pdv_items = [pdv_b2]

        # The test is that these packets can be built correctly.
        assert b'context A part 1' in bytes(pkt_a1)
        assert b'context B part 1' in bytes(pkt_b1)
        assert bytes(pkt_a1)[7] == 1 # Check context ID
        assert bytes(pkt_b1)[7] == 3 # Check context ID

    def test_req_l14_dimse_mismatch_cross_context(self):
        """REQ-L14: Demonstrates building a command and data in different contexts."""
        # This also demonstrates the layer's capability.
        # The fuzzer would send these two PDUs back-to-back.
        c_store_cmd_bytes = b'\x01\x00' # Placeholder for C-STORE-RQ command
        dicom_object_bytes = b'\x08\x00....' # Placeholder for DICOM object data

        # Command is sent in the context of Presentation Context 5
        pdv_cmd = PresentationDataValueItem(context_id=5, data=c_store_cmd_bytes, is_command=True, is_last=True)
        pkt_cmd = DICOM() / P_DATA_TF(); pkt_cmd.parsed_pdv_items = [pdv_cmd]

        # Data is sent in the context of Presentation Context 7
        pdv_data = PresentationDataValueItem(context_id=7, data=dicom_object_bytes, is_command=False, is_last=True)
        pkt_data = DICOM() / P_DATA_TF(); pkt_data.parsed_pdv_items = [pdv_data]
        
        # The test asserts that the layer builds these distinct packets correctly.
        assert bytes(pkt_cmd)[7] == 5
        assert bytes(pkt_data)[7] == 7
        assert struct.unpack("!B", bytes(pkt_cmd)[8:9])[0] & 0x01 == 1 # is_command flag
        assert struct.unpack("!B", bytes(pkt_data)[8:9])[0] & 0x01 == 0 # not is_command flag

    def test_req_l15_file_stream_confusion(self):
        """REQ-L15: Can encapsulate a full DICOM file (with meta info) in a P-DATA-TF."""
        # 1. Create a fake File Meta Information Header (Explicit VR Little Endian)
        fmi_group_len_tag = b'\x02\x00\x00\x00'
        fmi_group_len_vr = b'UL'
        fmi_group_len_len = b'\x04\x00'
        fmi_group_len_val = struct.pack("<I", 4 + 22) # Length of the two FMI elements below
        
        fmi_ts_tag = b'\x02\x00\x10\x00'
        fmi_ts_vr = b'UI'
        fmi_ts_len = b'\x12\x00' # Length of the UID string (18 bytes)
        fmi_ts_val = b'1.2.840.10008.1.2\x00' # Implicit VR LE UID

        file_meta_info = (fmi_group_len_tag + fmi_group_len_vr + fmi_group_len_len + fmi_group_len_val +
                          fmi_ts_tag + fmi_ts_vr + fmi_ts_len + fmi_ts_val)
        
        # 2. Create the full file-like payload
        dicom_file_payload = (
            b'\x00' * 128 +  # 128-byte preamble
            b'DICM' +        # Magic word
            file_meta_info +
            b'\x08\x00\x05\x00\x0a\x00\x43\x53\x49\x53\x4f\x31' # Patient Name (ISO_IR 100)
        )
        
        # Encapsulate in a P-DATA-TF PDV
        pdv = PresentationDataValueItem(context_id=1, data=dicom_file_payload, is_command=False, is_last=True)
        pkt = DICOM() / P_DATA_TF(); pkt.parsed_pdv_items = [pdv]
        
        # Assert that the entire file-like structure is present
        assert b'DICM' in bytes(pkt)
        assert dicom_file_payload in bytes(pkt)

    def test_req_l16_transfer_syntax_agnosticism(self):
        """REQ-L16: Can encapsulate a payload representing Explicit VR Big Endian."""
        # (0008,0020) Study Date | VR=DA | Len=8 | Value='20250709'
        # Big Endian, Explicit VR encoding
        tag = b'\x00\x08\x00\x20'
        vr = b'DA'
        length = b'\x00\x08'
        value = b'20250709'
        big_endian_payload = tag + vr + length + value
        
        pdv = PresentationDataValueItem(context_id=1, data=big_endian_payload, is_command=False, is_last=True)
        pkt = DICOM() / P_DATA_TF(); pkt.parsed_pdv_items = [pdv]
        
        # Assert that the layer correctly encapsulates this byte sequence without modification.
        assert big_endian_payload in bytes(pkt)

    def test_req_l17_security_negotiation_probing(self):
        """REQ-L17: Can include a Secure Transport Connection sub-item in an A-ASSOCIATE-RQ."""
        # This test now uses the class defined directly in scapy_dicom.py
        secure_item = SecureTransportConnectionSubItem()
        user_info = UserInformationItem(user_data_subitems=bytes(secure_item))
        pkt = DICOM() / A_ASSOCIATE_RQ()
        pkt[A_ASSOCIATE_RQ].variable_items = [user_info]

        # Assert that the bytes for the secure item (0x56, 0x00, 0x00, 0x00) are present.
        assert b'\x56\x00\x00\x00' in bytes(pkt)


# --- Group 4: Integration Test ---
# This test connects to a live SCP to perform a C-ECHO.

# Marker to skip this test if connection details aren't provided
integration_test_marker = pytest.mark.skipif(
    "not config.getoption('--ip') or not config.getoption('--port') or not config.getoption('--ae-title')",
    reason="Integration test requires --ip, --port, and --ae-title"
)

@integration_test_marker
def test_c_echo_integration(scp_ip, scp_port, scp_ae, my_ae, timeout):
    """
    Performs a full C-ECHO workflow against a live SCP.
    Connect -> Associate -> C-ECHO -> Release.
    """
    session = DICOMSession(
        dst_ip=scp_ip,
        dst_port=scp_port,
        dst_ae=scp_ae,
        src_ae=my_ae,
        read_timeout=timeout
    )
    
    echo_status = None
    try:
        # 1. Associate
        verification_context = {VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}
        assoc_success = session.associate(requested_contexts=verification_context)
        assert assoc_success, "Association failed"

        # 2. Perform C-ECHO
        echo_status = session.c_echo()
        assert echo_status is not None, "C-ECHO operation failed at a low level (returned None)"
        assert echo_status == 0x0000, f"C-ECHO failed with non-zero status: 0x{echo_status:04X}"

    finally:
        # 3. Cleanly release the association
        if session and session.assoc_established:
            release_success = session.release()
            assert release_success, "Failed to cleanly release the association"
        elif session and session.stream:
            # If association failed but connection is open, just close it
            session.close()
