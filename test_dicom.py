"""
Pytest test suite for Scapy DICOM contribution.

Includes unit tests for packet crafting/parsing and integration tests
for live SCP verification.
"""
import pytest
import struct
import logging
import sys
import os
import warnings

warnings.filterwarnings("ignore")

# Add current directory to path for local testing
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.contrib.dicom").setLevel(logging.INFO)

from scapy_dicom import (
    DICOM,
    A_ASSOCIATE_RQ,
    A_ASSOCIATE_AC,
    A_ASSOCIATE_RJ,
    A_RELEASE_RQ,
    A_RELEASE_RP,
    A_ABORT,
    P_DATA_TF,
    DICOMVariableItem,
    PresentationDataValueItem,
    build_c_echo_rq_dimse,
    build_c_store_rq_dimse,
    DICOMSession,
    APP_CONTEXT_UID,
    VERIFICATION_SOP_CLASS_UID,
    DEFAULT_TRANSFER_SYNTAX_UID,
    CT_IMAGE_STORAGE_SOP_CLASS_UID,
)
# Internal helper - import separately since it's not in __all__
from scapy_dicom import _uid_to_bytes


# --- Group 1: Layer Unit & Validation Tests ---
class TestCoreLayerValidation:
    """Tests for core packet construction and parsing."""

    def test_req_001_and_006_parse_associate_rq_ac(self):
        """Test A-ASSOCIATE-RQ construction and parsing with variable items."""
        app_context = DICOMVariableItem(
            item_type=0x10, data=_uid_to_bytes(APP_CONTEXT_UID)
        )
        pres_context_data = (
            b'\x01\x00\x00\x00'
            + bytes(DICOMVariableItem(
                item_type=0x30, data=_uid_to_bytes(VERIFICATION_SOP_CLASS_UID)
            ))
            + bytes(DICOMVariableItem(
                item_type=0x40, data=_uid_to_bytes(DEFAULT_TRANSFER_SYNTAX_UID)
            ))
        )
        pres_context = DICOMVariableItem(item_type=0x20, data=pres_context_data)
        user_info_data = bytes(
            DICOMVariableItem(item_type=0x51, data=struct.pack("!I", 16384))
        )
        user_info = DICOMVariableItem(item_type=0x50, data=user_info_data)

        pkt_payload = A_ASSOCIATE_RQ(
            calling_ae_title=b'VALIDATOR'.ljust(16),
            called_ae_title=b'TEST_SCP'.ljust(16),
        )
        pkt_payload.variable_items = [app_context, pres_context, user_info]
        pkt = DICOM() / pkt_payload

        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.haslayer(A_ASSOCIATE_RQ)
        assert len(reparsed_pkt[A_ASSOCIATE_RQ].variable_items) == 3

    def test_req_009_parse_associate_rj(self):
        """Test A-ASSOCIATE-RJ construction and parsing."""
        pkt = DICOM() / A_ASSOCIATE_RJ(result=1, source=2, reason_diag=2)
        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.haslayer(A_ASSOCIATE_RJ)
        assert reparsed_pkt[A_ASSOCIATE_RJ].source == 2

    def test_req_011_parse_pdata_tf(self):
        """Test P-DATA-TF with multiple PDV items."""
        pdv1 = PresentationDataValueItem(
            context_id=1, data=b'\xDE\xAD', is_command=True, is_last=False
        )
        pdv2 = PresentationDataValueItem(
            context_id=1, data=b'\xBE\xEF', is_command=False, is_last=True
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv1, pdv2])
        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.haslayer(P_DATA_TF)
        assert len(reparsed_pkt[P_DATA_TF].pdv_items) == 2
        # Handle both bytes and str returns from Scapy
        data = reparsed_pkt[P_DATA_TF].pdv_items[1].data
        if isinstance(data, str):
            data = data.encode('latin-1')
        assert data == b'\xBE\xEF'

    @pytest.mark.parametrize("pdu_type, layer_class", [
        (0x05, A_RELEASE_RQ),
        (0x06, A_RELEASE_RP),
        (0x07, A_ABORT),
    ])
    def test_req_015_016_017_parse_simple_pdus(self, pdu_type, layer_class):
        """Test simple PDU construction and parsing."""
        pkt = DICOM(pdu_type=pdu_type) / layer_class()
        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.haslayer(layer_class)

    def test_req_023_construct_pdata_with_cecho(self):
        """Test P-DATA-TF with C-ECHO DIMSE command."""
        c_echo_dimse = build_c_echo_rq_dimse(message_id=123)
        pdv_echo = PresentationDataValueItem(
            context_id=1, data=c_echo_dimse, is_command=True, is_last=True
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv_echo])
        raw_bytes = bytes(pkt)
        assert raw_bytes.startswith(b'\x04\x00')
        assert c_echo_dimse in raw_bytes

    def test_req_024_construct_pdata_with_cmd_and_data(self):
        """Test P-DATA-TF with command and data PDVs."""
        pdv_cmd = PresentationDataValueItem(
            context_id=3, data=b'\x01\x02', is_command=True, is_last=True
        )
        pdv_data = PresentationDataValueItem(
            context_id=3, data=b'\xAA\xBB', is_command=False, is_last=True
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv_cmd, pdv_data])
        reparsed_pkt = DICOM(bytes(pkt))
        assert len(reparsed_pkt[P_DATA_TF].pdv_items) == 2


# --- Group 2 & 3: Fuzzing Capability Tests ---
class TestFuzzingCapabilities:
    """Tests for fuzzing and edge case handling."""

    def test_req_002_oversized_ae_title(self):
        """Test that oversized AE titles are truncated to 16 bytes."""
        oversized_title = b'A' * 25
        pkt = DICOM() / A_ASSOCIATE_RQ(called_ae_title=oversized_title)
        assert bytes(pkt)[10:26] == b'A' * 16

    def test_req_004_too_many_presentation_contexts(self):
        """Test handling of many presentation contexts."""
        contexts = []
        for i in range(128):
            ctx_id = (i * 2) + 1
            contexts.append(
                DICOMVariableItem(
                    item_type=0x20, data=struct.pack("!BBBB", ctx_id, 0, 0, 0)
                )
            )
        pkt = DICOM() / A_ASSOCIATE_RQ()
        pkt[A_ASSOCIATE_RQ].variable_items = contexts
        reparsed_pkt = DICOM(bytes(pkt))
        assert len(reparsed_pkt[A_ASSOCIATE_RQ].variable_items) == 128

    def test_req_005_manipulate_user_info(self):
        """Test maximum PDU length manipulation."""
        max_len_subitem = DICOMVariableItem(
            item_type=0x51, data=struct.pack("!I", 0x7FFFFFFF)
        )
        user_info = DICOMVariableItem(item_type=0x50, data=bytes(max_len_subitem))
        pkt = DICOM() / A_ASSOCIATE_RQ()
        pkt[A_ASSOCIATE_RQ].variable_items = [user_info]
        assert b'\x51\x00\x00\x04\x7f\xff\xff\xff' in bytes(pkt)

    @pytest.mark.parametrize("pdu_class, field, value", [
        (A_ASSOCIATE_RJ, "reason_diag", 255),
        (A_ABORT, "source", 1),
    ])
    def test_req_010_018_invalid_enums(self, pdu_class, field, value):
        """Test that invalid enum values are preserved."""
        pkt = DICOM() / pdu_class(**{field: value})
        reparsed_pkt = DICOM(bytes(pkt))
        assert getattr(reparsed_pkt[pdu_class], field) == value

    def test_req_013_illogical_fragmentation(self):
        """Test incomplete fragmentation flag handling."""
        pdv = PresentationDataValueItem(
            context_id=1, data=b'fragment', is_last=False
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv])
        reparsed_pkt = DICOM(bytes(pkt))
        assert not reparsed_pkt[P_DATA_TF].pdv_items[0].is_last

    def test_req_025_incorrect_command_group_length(self):
        """Test corrupted DIMSE command group length."""
        c_echo_dimse = build_c_echo_rq_dimse(message_id=456)
        corrupt_dimse = c_echo_dimse[:8] + struct.pack("<I", 1000) + c_echo_dimse[12:]
        pdv = PresentationDataValueItem(
            context_id=1, is_command=True, is_last=True, data=corrupt_dimse
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv])
        assert corrupt_dimse in bytes(pkt)

    def test_req_l01_pdu_type_confusion(self):
        """Test PDU type mismatch (P-DATA type with A-ASSOCIATE payload)."""
        pkt = DICOM(pdu_type=0x04) / A_ASSOCIATE_RQ()
        raw_bytes = bytes(pkt)
        assert raw_bytes[0] == 0x04
        assert raw_bytes[6:10] == b'\x00\x01\x00\x00'

    def test_req_l02_integer_overflow_in_length(self):
        """Test maximum integer length value."""
        pkt = DICOM(length=0xFFFFFFFF) / A_RELEASE_RQ()
        assert bytes(pkt)[2:6] == b'\xff\xff\xff\xff'

    def test_req_l05_null_byte_injection(self):
        """Test null byte handling in AE titles."""
        injected_title = b'SCAPY\x00FUZZER'.ljust(16)
        pkt = DICOM() / A_ASSOCIATE_RQ(calling_ae_title=injected_title)
        assert bytes(pkt)[26:42] == injected_title

    def test_req_l11_state_confusion(self):
        """Test P-DATA-TF state handling."""
        pdv = PresentationDataValueItem(context_id=1, data=b'some data')
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv])
        assert pkt.pdu_type == 0x04
        assert b'some data' in bytes(pkt)

    def test_req_l12_resource_exhaustion_incomplete_pdu(self):
        """Test incomplete PDU with large declared length."""
        payload = b'\x01\x02\x03\x04'
        raw_pkt = b'\x04\x00' + struct.pack("!I", 1024 * 1024) + payload
        assert raw_pkt.startswith(b'\x04\x00')
        assert struct.unpack("!I", raw_pkt[2:6])[0] == 1024 * 1024

    def test_req_l13_advanced_fragmentation_interleaving(self):
        """Test interleaved fragmentation across contexts."""
        pdv_a1 = PresentationDataValueItem(
            context_id=1, data=b'context A part 1', is_last=False
        )
        pdv_b1 = PresentationDataValueItem(
            context_id=3, data=b'context B part 1', is_last=False
        )
        pkt_a1 = DICOM() / P_DATA_TF(pdv_items=[pdv_a1])
        pkt_b1 = DICOM() / P_DATA_TF(pdv_items=[pdv_b1])
        assert b'context A part 1' in bytes(pkt_a1)
        assert pkt_a1[P_DATA_TF].pdv_items[0].context_id == 1
        assert b'context B part 1' in bytes(pkt_b1)
        assert pkt_b1[P_DATA_TF].pdv_items[0].context_id == 3

    def test_req_l14_dimse_mismatch_cross_context(self):
        """Test DIMSE command with arbitrary context ID."""
        pdv_cmd = PresentationDataValueItem(
            context_id=5, data=b'\x01\x00', is_command=True, is_last=True
        )
        pkt_cmd = DICOM() / P_DATA_TF(pdv_items=[pdv_cmd])
        assert pkt_cmd[P_DATA_TF].pdv_items[0].context_id == 5
        assert pkt_cmd[P_DATA_TF].pdv_items[0].is_command

    def test_req_l15_file_stream_confusion(self):
        """Test DICOM file content embedded in P-DATA."""
        file_meta_info = (
            b'\x02\x00\x00\x00UL\x04\x00' + struct.pack("<I", 34)
            + b'\x02\x00\x10\x00UI\x12\x00' + b'1.2.840.10008.1.2\x00'
        )
        dicom_file_payload = (
            b'\x00' * 128 + b'DICM' + file_meta_info
            + b'\x08\x00\x05\x00\x0a\x00\x43\x53\x49\x53\x4f\x31'
        )
        pdv = PresentationDataValueItem(
            context_id=1, data=dicom_file_payload, is_command=False, is_last=True
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv])
        assert b'DICM' in bytes(pkt)

    def test_req_l16_transfer_syntax_agnosticism(self):
        """Test big-endian payload handling."""
        big_endian_payload = b'\x00\x08\x00\x20DA\x00\x0820250709'
        pdv = PresentationDataValueItem(
            context_id=1, data=big_endian_payload, is_command=False, is_last=True
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv])
        assert big_endian_payload in bytes(pkt)

    def test_req_l17_security_negotiation_probing(self):
        """Test user identity negotiation item."""
        secure_item_bytes = bytes(DICOMVariableItem(item_type=0x56))
        user_info = DICOMVariableItem(item_type=0x50, data=secure_item_bytes)
        pkt = DICOM() / A_ASSOCIATE_RQ()
        pkt[A_ASSOCIATE_RQ].variable_items = [user_info]
        assert b'\x56\x00\x00\x00' in bytes(pkt)


# --- Group 4: Integration Tests ---
integration_test_marker = pytest.mark.skipif(
    "not config.getoption('--ip')",
    reason="Integration test requires --ip, --port, and --ae-title"
)


@integration_test_marker
def test_c_echo_integration(scp_ip, scp_port, scp_ae, my_ae, timeout):
    """Performs a full C-ECHO workflow against a live SCP."""
    session = DICOMSession(
        dst_ip=scp_ip,
        dst_port=scp_port,
        dst_ae=scp_ae,
        src_ae=my_ae,
        read_timeout=timeout,
    )
    try:
        verification_context = {
            VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
        }
        assoc_success = session.associate(requested_contexts=verification_context)
        assert assoc_success, "Association failed"

        echo_status = session.c_echo()
        assert echo_status is not None, "C-ECHO operation returned None"
        assert echo_status == 0x0000, f"C-ECHO failed with status: 0x{echo_status:04X}"
    finally:
        if session and session.stream:
            if session.assoc_established:
                release_success = session.release()
                assert release_success, "Failed to cleanly release the association"
            else:
                session.close()


@integration_test_marker
def test_c_store_integration(scp_ip, scp_port, scp_ae, my_ae, timeout):
    """Performs a full C-STORE workflow against a live SCP."""
    # Create a minimal DICOM dataset with tags in ascending order (required by DICOM)
    sop_instance_uid = "1.2.3.4.5.6.7.8"
    study_instance_uid = "1.2.3.4.5.6.7.8.9"
    series_instance_uid = "1.2.3.4.5.6.7.8.9.10"
    sop_class_uid_bytes = _uid_to_bytes(CT_IMAGE_STORAGE_SOP_CLASS_UID)
    sop_instance_uid_bytes = _uid_to_bytes(sop_instance_uid)
    study_instance_uid_bytes = _uid_to_bytes(study_instance_uid)
    series_instance_uid_bytes = _uid_to_bytes(series_instance_uid)

    # Build dataset with tags in proper ascending order
    dataset_elements = []

    # (0008,0016) SOP Class UID - UI
    dataset_elements.append(
        struct.pack('<HHI', 0x0008, 0x0016, len(sop_class_uid_bytes))
        + sop_class_uid_bytes
    )
    # (0008,0018) SOP Instance UID - UI
    dataset_elements.append(
        struct.pack('<HHI', 0x0008, 0x0018, len(sop_instance_uid_bytes))
        + sop_instance_uid_bytes
    )
    # (0010,0020) Patient ID - LO
    patient_id = b'TEST'
    dataset_elements.append(
        struct.pack('<HHI', 0x0010, 0x0020, len(patient_id)) + patient_id
    )
    # (0020,000D) Study Instance UID - UI (required by Orthanc)
    dataset_elements.append(
        struct.pack('<HHI', 0x0020, 0x000D, len(study_instance_uid_bytes))
        + study_instance_uid_bytes
    )
    # (0020,000E) Series Instance UID - UI (required by Orthanc)
    dataset_elements.append(
        struct.pack('<HHI', 0x0020, 0x000E, len(series_instance_uid_bytes))
        + series_instance_uid_bytes
    )

    dataset_bytes = b''.join(dataset_elements)

    session = DICOMSession(
        dst_ip=scp_ip,
        dst_port=scp_port,
        dst_ae=scp_ae,
        src_ae=my_ae,
        read_timeout=timeout,
    )
    try:
        # Associate with CT Image Storage context
        store_context = {CT_IMAGE_STORAGE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}
        assoc_success = session.associate(requested_contexts=store_context)
        assert assoc_success, "Association for C-STORE failed"

        # Perform C-STORE
        store_status = session.c_store(
            dataset_bytes=dataset_bytes,
            sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            sop_instance_uid=sop_instance_uid,
            transfer_syntax_uid=DEFAULT_TRANSFER_SYNTAX_UID,
        )
        assert store_status is not None, "C-STORE operation returned None"
        assert store_status == 0x0000, f"C-STORE failed with status: 0x{store_status:04X}"
    finally:
        if session and session.stream:
            if session.assoc_established:
                release_success = session.release()
                assert release_success, "Failed to cleanly release the association"
            else:
                session.close()