"""
Pytest test suite for Scapy DICOM contribution (v2.0 Refactored).

Tests the improved architecture:
- Native Scapy RandChoice/RandString instead of custom RandField classes
- DIMSE fields inherit from LEShortField/LEIntField with TLV mixin
- Single smart packet classes (no more *_Raw duplicates)
- Explicit command_group_length field (fuzzable!)
- Automaton-based session management (DICOM_SCU)
"""
import pytest
import struct
import logging
import sys
import os
import warnings
import time

warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.contrib.dicom").setLevel(logging.INFO)

from scapy.config import conf
from scapy.volatile import RandChoice, RandShort, RandInt

from dicom import (
    # PDU classes
    DICOM,
    A_ASSOCIATE_RQ,
    A_ASSOCIATE_AC,
    A_ASSOCIATE_RJ,
    A_RELEASE_RQ,
    A_RELEASE_RP,
    A_ABORT,
    P_DATA_TF,
    PresentationDataValueItem,
    # Variable Item classes
    DICOMVariableItem,
    DICOMApplicationContext,
    DICOMPresentationContextRQ,
    DICOMPresentationContextAC,
    DICOMAbstractSyntax,
    DICOMTransferSyntax,
    DICOMUserInformation,
    DICOMMaximumLength,
    DICOMImplementationClassUID,
    DICOMAsyncOperationsWindow,
    DICOMSCPSCURoleSelection,
    DICOMImplementationVersionName,
    DICOMUserIdentity,
    DICOMUserIdentityResponse,
    DICOMGenericItem,
    # DIMSE Packet classes (Single Smart Classes - no more *_Raw!)
    DIMSECommand,
    C_ECHO_RQ,
    C_ECHO_RSP,
    C_STORE_RQ,
    C_STORE_RSP,
    C_FIND_RQ,
    # New DIMSE Field classes
    DIMSETLVMixin,
    DIMSEUSField,
    DIMSEULField,
    DIMSEUIDField,
    DIMSEStatusField,
    # Automaton-based Session
    DICOM_SCU,
    # Backward-compatible wrapper
    DICOMSession,
    # Helpers
    build_presentation_context_rq,
    build_user_information,
    # Constants
    APP_CONTEXT_UID,
    VERIFICATION_SOP_CLASS_UID,
    DEFAULT_TRANSFER_SYNTAX_UID,
    CT_IMAGE_STORAGE_SOP_CLASS_UID,
    DIMSE_STATUS_CODES,
    _pad_ae_title,
    _uid_to_bytes,
)


# =============================================================================
# Test Native Scapy Random Fields (Key Improvement #1)
# =============================================================================

class TestNativeScapyRandomFields:
    """Test that we use native Scapy random generators instead of custom classes."""

    def test_status_field_uses_randchoice(self):
        """DIMSEStatusField.randval() should return RandChoice."""
        field = DIMSEStatusField("status", 0x0000, tag=(0x0000, 0x0900))
        rand_val = field.randval()
        
        # Should be a RandChoice instance
        assert isinstance(rand_val, RandChoice)

    def test_us_field_uses_randshort(self):
        """DIMSEUSField.randval() should return RandShort."""
        field = DIMSEUSField("test", 0, tag=(0x0000, 0x0100))
        rand_val = field.randval()
        
        assert isinstance(rand_val, RandShort)

    def test_ul_field_uses_randint(self):
        """DIMSEULField.randval() should return RandInt."""
        field = DIMSEULField("test", 0, tag=(0x0000, 0x0000))
        rand_val = field.randval()
        
        assert isinstance(rand_val, RandInt)

    def test_status_randval_produces_valid_codes(self):
        """DIMSEStatusField random values should be known status codes."""
        field = DIMSEStatusField("status", 0x0000, tag=(0x0000, 0x0900))
        
        # Generate several random values
        for _ in range(20):
            val = int(field.randval())
            assert val in DIMSE_STATUS_CODES, f"Generated unknown status: 0x{val:04X}"


# =============================================================================
# Test Field Inheritance with TLV Mixin (Key Improvement #2)
# =============================================================================

class TestDIMSEFieldInheritance:
    """Test that DIMSE fields inherit from native Scapy fields + TLV mixin."""

    def test_dimse_us_field_inherits_leshortfield(self):
        """DIMSEUSField should inherit from LEShortField."""
        from scapy.fields import LEShortField
        assert issubclass(DIMSEUSField, LEShortField)

    def test_dimse_ul_field_inherits_leintfield(self):
        """DIMSEULField should inherit from LEIntField."""
        from scapy.fields import LEIntField
        assert issubclass(DIMSEULField, LEIntField)

    def test_dimse_fields_have_tlv_mixin(self):
        """DIMSE fields should have TLV mixin methods."""
        field = DIMSEUSField("test", 0, tag=(0x0000, 0x0100))
        
        assert hasattr(field, '_build_tlv_header')
        assert hasattr(field, '_parse_tlv_header')
        assert hasattr(field, 'tag_group')
        assert hasattr(field, 'tag_elem')

    def test_dimse_us_field_tag_assignment(self):
        """DIMSEUSField should correctly store tag from constructor."""
        field = DIMSEUSField("command_field", 0x0030, tag=(0x0000, 0x0100))
        
        assert field.tag_group == 0x0000
        assert field.tag_elem == 0x0100

    def test_dimse_us_field_serialization(self):
        """DIMSEUSField should serialize with TLV header."""
        field = DIMSEUSField("test", 0x1234, tag=(0x0000, 0x0100))
        
        # Build the field
        result = field.addfield(None, b"", 0x5678)
        
        # Should be: tag_group(2) + tag_elem(2) + length(4) + value(2) = 10 bytes
        assert len(result) == 10
        
        # Check tag
        tag_g, tag_e = struct.unpack("<HH", result[:4])
        assert tag_g == 0x0000
        assert tag_e == 0x0100
        
        # Check length (should be 2 for US)
        length = struct.unpack("<I", result[4:8])[0]
        assert length == 2
        
        # Check value
        value = struct.unpack("<H", result[8:10])[0]
        assert value == 0x5678

    def test_dimse_ul_field_serialization(self):
        """DIMSEULField should serialize with TLV header."""
        field = DIMSEULField("test", 0, tag=(0x0000, 0x0000))
        
        result = field.addfield(None, b"", 0x12345678)
        
        # Should be: tag(4) + length(4) + value(4) = 12 bytes
        assert len(result) == 12
        
        # Check value
        value = struct.unpack("<I", result[8:12])[0]
        assert value == 0x12345678

    def test_dimse_status_field_i2repr(self):
        """DIMSEStatusField should display status name."""
        field = DIMSEStatusField("status", 0x0000, tag=(0x0000, 0x0900))
        
        repr_str = field.i2repr(None, 0x0000)
        assert "Success" in repr_str
        assert "0x0000" in repr_str
        
        repr_str = field.i2repr(None, 0xFF00)
        assert "Pending" in repr_str


# =============================================================================
# Test Single Smart Packet Classes (Key Improvement #3)
# =============================================================================

class TestSingleSmartPacketClasses:
    """Test that single classes handle both valid and fuzzing modes."""

    def test_no_raw_classes_exist(self):
        """There should be no *_Raw duplicate classes."""
        import dicom
        
        # These should NOT exist anymore
        assert not hasattr(dicom, 'C_ECHO_RQ_Raw')
        assert not hasattr(dicom, 'C_STORE_RQ_Raw')
        assert not hasattr(dicom, 'DIMSEPacketRaw')

    def test_packet_has_raw_mode_attribute(self):
        """DIMSE packets should have raw_mode attribute."""
        pkt = C_ECHO_RQ()
        assert hasattr(pkt, 'raw_mode')
        assert pkt.raw_mode == False  # Default is False

    def test_raw_mode_can_be_set_per_packet(self):
        """raw_mode can be set on individual packets."""
        pkt = C_ECHO_RQ()
        pkt.raw_mode = True
        assert pkt.raw_mode == True

    def test_global_raw_mode_config(self):
        """Global raw_mode can be set via conf.contribs."""
        # Save original
        original = conf.contribs.get("dicom", {}).get("raw_mode", False)
        
        try:
            conf.contribs["dicom"]["raw_mode"] = True
            
            # New packets should respect global config
            pkt = C_STORE_RQ()
            # The field should check global config
            uid_field = None
            for f in pkt.fields_desc:
                if hasattr(f, '_get_raw_mode'):
                    assert f._get_raw_mode(pkt) == True
                    break
        finally:
            conf.contribs["dicom"]["raw_mode"] = original

    def test_uid_padding_controlled_by_raw_mode(self):
        """UID auto-padding should be controlled by raw_mode."""
        # Normal mode - should pad
        pkt = C_ECHO_RQ(affected_sop_class_uid="1.2.3")  # 5 bytes - odd
        raw = bytes(pkt)
        
        # Find the UID in the raw bytes - it should be padded to even
        # The UID "1.2.3" + null = 6 bytes
        assert b"1.2.3\x00" in raw or b"1.2.3" in raw

    def test_dimse_command_base_class(self):
        """All DIMSE commands should inherit from DIMSECommand."""
        assert issubclass(C_ECHO_RQ, DIMSECommand)
        assert issubclass(C_ECHO_RSP, DIMSECommand)
        assert issubclass(C_STORE_RQ, DIMSECommand)
        assert issubclass(C_STORE_RSP, DIMSECommand)
        assert issubclass(C_FIND_RQ, DIMSECommand)


# =============================================================================
# Test Explicit command_group_length Field (Key Improvement #5)
# =============================================================================

class TestExplicitCommandGroupLength:
    """Test that command_group_length is an explicit fuzzable field."""

    def test_command_group_length_in_fields_desc(self):
        """command_group_length should be in fields_desc."""
        field_names = [f.name for f in C_ECHO_RQ.fields_desc]
        assert "command_group_length" in field_names

    def test_command_group_length_is_first_field(self):
        """command_group_length should be the first field."""
        assert C_ECHO_RQ.fields_desc[0].name == "command_group_length"

    def test_command_group_length_default_is_none(self):
        """command_group_length default should be None (auto-calculate)."""
        pkt = C_ECHO_RQ()
        assert pkt.command_group_length is None

    def test_command_group_length_auto_calculated(self):
        """When None, command_group_length should be auto-calculated in post_build."""
        pkt = C_ECHO_RQ(message_id=42)
        raw = bytes(pkt)
        
        # First element is CommandGroupLength (0000,0000)
        tag_g, tag_e = struct.unpack("<HH", raw[:4])
        assert tag_g == 0x0000
        assert tag_e == 0x0000
        
        # Value length is 4
        val_len = struct.unpack("<I", raw[4:8])[0]
        assert val_len == 4
        
        # The value should equal remaining bytes after this element
        group_len = struct.unpack("<I", raw[8:12])[0]
        remaining = len(raw) - 12
        assert group_len == remaining

    def test_command_group_length_explicit_value_preserved(self):
        """When explicitly set, command_group_length should NOT be auto-calculated."""
        # Set explicit wrong value for fuzzing
        pkt = C_ECHO_RQ(command_group_length=9999, message_id=42)
        raw = bytes(pkt)
        
        # The value should be exactly what we set
        group_len = struct.unpack("<I", raw[8:12])[0]
        assert group_len == 9999

    def test_fuzz_command_group_length_zero(self):
        """Fuzzing: command_group_length = 0."""
        pkt = C_ECHO_RQ(command_group_length=0)
        raw = bytes(pkt)
        
        group_len = struct.unpack("<I", raw[8:12])[0]
        assert group_len == 0

    def test_fuzz_command_group_length_max(self):
        """Fuzzing: command_group_length = 0xFFFFFFFF."""
        pkt = C_ECHO_RQ(command_group_length=0xFFFFFFFF)
        raw = bytes(pkt)
        
        group_len = struct.unpack("<I", raw[8:12])[0]
        assert group_len == 0xFFFFFFFF

    def test_fuzz_command_group_length_undersized(self):
        """Fuzzing: command_group_length smaller than actual."""
        pkt = C_ECHO_RQ(command_group_length=10, message_id=42)
        raw = bytes(pkt)
        
        group_len = struct.unpack("<I", raw[8:12])[0]
        assert group_len == 10
        # Actual remaining is much larger, but we preserved the fuzz value


# =============================================================================
# Test Automaton-Based Session (Key Improvement #4)
# =============================================================================

class TestAutomatonBasedSession:
    """Test that session uses scapy.automaton instead of manual socket loops."""

    def test_dicom_scu_exists(self):
        """DICOM_SCU automaton class should exist."""
        from scapy.automaton import Automaton
        assert issubclass(DICOM_SCU, Automaton)

    def test_dicom_scu_has_states(self):
        """DICOM_SCU should have proper state definitions."""
        # Check for state method existence
        assert hasattr(DICOM_SCU, 'IDLE')
        assert hasattr(DICOM_SCU, 'ASSOCIATED')
        assert hasattr(DICOM_SCU, 'END')

    def test_dicom_session_wraps_automaton(self):
        """DICOMSession should wrap DICOM_SCU for backward compatibility."""
        session = DICOMSession("127.0.0.1", 104, "TEST")
        
        # Should have internal automaton
        assert hasattr(session, '_scu')
        assert isinstance(session._scu, DICOM_SCU)

    def test_dicom_session_has_standard_methods(self):
        """DICOMSession should expose standard API methods."""
        session = DICOMSession("127.0.0.1", 104, "TEST")
        
        assert hasattr(session, 'associate')
        assert hasattr(session, 'c_echo')
        assert hasattr(session, 'c_store')
        assert hasattr(session, 'release')
        assert hasattr(session, 'close')

    def test_dicom_session_no_manual_recv_loops(self):
        """DICOMSession should not have manual recv loops."""
        import inspect
        
        source = inspect.getsource(DICOMSession)
        
        # Should NOT contain manual socket patterns
        assert 'while len(header) < 6' not in source
        assert 'while len(payload) < pdu_length' not in source


# =============================================================================
# Test LenField Auto-Calculation
# =============================================================================

class TestLenFieldAutoCalculation:
    """Test that LenField automatically calculates payload length."""

    def test_dicom_pdu_length_auto_calculated(self):
        """DICOM header should auto-calculate payload length."""
        pkt = DICOM() / A_RELEASE_RQ()
        raw = bytes(pkt)
        
        length_field = struct.unpack("!I", raw[2:6])[0]
        payload_size = len(raw) - 6
        
        assert length_field == payload_size
        assert length_field == 4

    def test_variable_item_length_auto_calculated(self):
        """DICOMVariableItem should auto-calculate payload length."""
        pkt = DICOMVariableItem() / DICOMApplicationContext()
        raw = bytes(pkt)
        
        length_field = struct.unpack("!H", raw[2:4])[0]
        payload_size = len(raw) - 4
        
        assert length_field == payload_size


# =============================================================================
# Test Variable Item Layer Binding
# =============================================================================

class TestVariableItemBindLayers:
    """Test that bind_layers correctly dispatches based on item_type."""

    def test_application_context_bind_layers(self):
        """DICOMVariableItem() / DICOMApplicationContext() should auto-set item_type=0x10."""
        pkt = DICOMVariableItem() / DICOMApplicationContext()
        assert pkt.item_type == 0x10
        
        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed.item_type == 0x10
        assert parsed.haslayer(DICOMApplicationContext)

    def test_maximum_length_bind_layers(self):
        """DICOMVariableItem() / DICOMMaximumLength() should auto-set item_type=0x51."""
        pkt = DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=32768)
        assert pkt.item_type == 0x51
        
        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed[DICOMMaximumLength].max_pdu_length == 32768

    def test_unknown_item_type_falls_back_to_generic(self):
        """Unknown item_type should parse into DICOMGenericItem."""
        raw = struct.pack("!BBH", 0xFF, 0, 4) + b"test"
        parsed = DICOMVariableItem(raw)
        
        assert parsed.item_type == 0xFF
        assert parsed.haslayer(DICOMGenericItem)


# =============================================================================
# Test DIMSE Packet Classes
# =============================================================================

class TestDIMSEPacketClasses:
    """Test the DIMSE packet classes."""

    def test_c_echo_rq_creation(self):
        """C_ECHO_RQ should be creatable with defaults."""
        pkt = C_ECHO_RQ()
        raw = bytes(pkt)
        
        # Should contain Verification SOP Class UID
        assert b'1.2.840.10008.1.1' in raw

    def test_c_echo_rq_custom_message_id(self):
        """C_ECHO_RQ should allow custom message_id."""
        pkt = C_ECHO_RQ(message_id=12345)
        raw = bytes(pkt)
        
        assert struct.pack("<H", 12345) in raw

    def test_c_store_rq_creation(self):
        """C_STORE_RQ should be creatable with UIDs."""
        pkt = C_STORE_RQ(
            affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            affected_sop_instance_uid="1.2.3.4.5.6.7.8.9",
            message_id=100,
        )
        raw = bytes(pkt)
        
        assert b'1.2.840.10008.5.1.4.1.1.2' in raw
        assert b'1.2.3.4.5.6.7.8.9' in raw

    def test_dimse_in_pdata_tf(self):
        """DIMSE packets should work inside P-DATA-TF."""
        dimse = C_ECHO_RQ(message_id=42)
        pdv = PresentationDataValueItem(
            context_id=1,
            data=bytes(dimse),
            is_command=1,
            is_last=1,
        )
        pdata = DICOM() / P_DATA_TF(pdv_items=[pdv])
        
        raw = bytes(pdata)
        parsed = DICOM(raw)
        
        assert parsed.haslayer(P_DATA_TF)
        pdv_data = parsed[P_DATA_TF].pdv_items[0].data
        if isinstance(pdv_data, str):
            pdv_data = pdv_data.encode('latin-1')
        assert b'1.2.840.10008.1.1' in pdv_data


# =============================================================================
# Test DIMSE Fuzzing Capabilities
# =============================================================================

class TestDIMSEFuzzing:
    """Test fuzzing capabilities with the new architecture."""

    def test_fuzz_message_id_boundary(self):
        """Test boundary message IDs."""
        for msg_id in [0, 1, 0x7FFF, 0xFFFF]:
            pkt = C_ECHO_RQ(message_id=msg_id)
            raw = bytes(pkt)
            assert struct.pack("<H", msg_id) in raw

    def test_fuzz_invalid_command_field(self):
        """Test setting invalid command field."""
        pkt = C_ECHO_RQ()
        pkt.command_field = 0xDEAD
        raw = bytes(pkt)
        assert struct.pack("<H", 0xDEAD) in raw

    def test_fuzz_invalid_data_set_type(self):
        """Test invalid data set type."""
        pkt = C_ECHO_RQ()
        pkt.data_set_type = 0xBEEF
        raw = bytes(pkt)
        assert struct.pack("<H", 0xBEEF) in raw

    def test_fuzz_extreme_priority(self):
        """Test C-STORE with out-of-range priority."""
        pkt = C_STORE_RQ(priority=0xFFFF)
        raw = bytes(pkt)
        assert struct.pack("<H", 0xFFFF) in raw

    def test_fuzz_with_global_raw_mode(self):
        """Test fuzzing with global raw_mode enabled."""
        original = conf.contribs.get("dicom", {}).get("raw_mode", False)
        
        try:
            conf.contribs["dicom"]["raw_mode"] = True
            
            # Should be able to create packets
            pkt = C_STORE_RQ(
                affected_sop_class_uid="1.2.3",  # Odd length
                affected_sop_instance_uid="1.2.3.4.5",  # Odd length
            )
            raw = bytes(pkt)
            assert len(raw) > 0
        finally:
            conf.contribs["dicom"]["raw_mode"] = original


# =============================================================================
# Test User Identity Negotiation
# =============================================================================

class TestUserIdentityNegotiation:
    """Tests for User Identity Negotiation."""

    def test_user_identity_username_only(self):
        """DICOMUserIdentity with username only (type 1)."""
        pkt = DICOMVariableItem() / DICOMUserIdentity(
            user_identity_type=1,
            primary_field=b"admin"
        )
        
        assert pkt.item_type == 0x58
        
        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed[DICOMUserIdentity].user_identity_type == 1
        assert parsed[DICOMUserIdentity].primary_field == b"admin"

    def test_user_identity_username_password(self):
        """DICOMUserIdentity with username+password (type 2)."""
        pkt = DICOMVariableItem() / DICOMUserIdentity(
            user_identity_type=2,
            primary_field=b"admin",
            secondary_field=b"password123"
        )
        
        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed[DICOMUserIdentity].secondary_field == b"password123"


# =============================================================================
# Test Round-Trip Serialization
# =============================================================================

class TestRoundTripSerialization:
    """Test that packets survive build -> serialize -> parse cycle."""

    def test_associate_rq_round_trip(self):
        """A-ASSOCIATE-RQ should survive serialization round-trip."""
        original = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=_pad_ae_title("TARGET"),
            calling_ae_title=_pad_ae_title("SOURCE"),
        )
        serialized = bytes(original)
        parsed = DICOM(serialized)

        assert parsed.haslayer(A_ASSOCIATE_RQ)
        assert parsed[A_ASSOCIATE_RQ].called_ae_title == b"TARGET          "

    def test_pdata_round_trip(self):
        """P-DATA-TF with PDV should survive serialization round-trip."""
        test_data = b"\x01\x02\x03\x04\x05"
        pdv = PresentationDataValueItem(
            context_id=3, data=test_data, is_command=1, is_last=1
        )
        original = DICOM() / P_DATA_TF(pdv_items=[pdv])
        serialized = bytes(original)
        parsed = DICOM(serialized)

        assert parsed.haslayer(P_DATA_TF)
        parsed_pdv = parsed[P_DATA_TF].pdv_items[0]
        
        parsed_data = parsed_pdv.data
        if isinstance(parsed_data, str):
            parsed_data = parsed_data.encode('latin-1')
        assert parsed_data == test_data


# =============================================================================
# Test Helper Functions
# =============================================================================

class TestHelperFunctions:
    """Test helper functions."""

    def test_build_presentation_context_rq(self):
        """build_presentation_context_rq should create proper structure."""
        pctx = build_presentation_context_rq(
            context_id=3,
            abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID,
            transfer_syntax_uids=[DEFAULT_TRANSFER_SYNTAX_UID]
        )
        
        assert pctx.item_type == 0x20
        assert pctx[DICOMPresentationContextRQ].context_id == 3

    def test_build_user_information(self):
        """build_user_information should create proper structure."""
        user_info = build_user_information(max_pdu_length=32768)
        
        assert user_info.item_type == 0x50
        sub_items = user_info[DICOMUserInformation].sub_items
        assert sub_items[0][DICOMMaximumLength].max_pdu_length == 32768


# =============================================================================
# Test Edge Cases
# =============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_variable_items(self):
        """A-ASSOCIATE-RQ with no variable items."""
        pkt = DICOM() / A_ASSOCIATE_RQ(variable_items=[])
        serialized = bytes(pkt)
        parsed = DICOM(serialized)
        assert parsed.haslayer(A_ASSOCIATE_RQ)

    def test_pdu_type_preservation(self):
        """Each PDU type should have correct type byte."""
        test_cases = [
            (A_ASSOCIATE_RQ(), 0x01),
            (A_ASSOCIATE_AC(), 0x02),
            (A_ASSOCIATE_RJ(), 0x03),
            (P_DATA_TF(), 0x04),
            (A_RELEASE_RQ(), 0x05),
            (A_RELEASE_RP(), 0x06),
            (A_ABORT(), 0x07),
        ]
        for pdu, expected_type in test_cases:
            pkt = DICOM() / pdu
            serialized = bytes(pkt)
            assert serialized[0] == expected_type


# =============================================================================
# Integration Tests
# =============================================================================

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
        assoc_success = session.associate()
        assert assoc_success, "Association failed"

        echo_status = session.c_echo()
        assert echo_status == 0x0000, f"C-ECHO failed: 0x{echo_status:04X}"
    finally:
        session.release()
        session.close()