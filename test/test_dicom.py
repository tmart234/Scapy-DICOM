"""
Pytest test suite for Scapy DICOM contribution.

Includes unit tests for packet crafting/parsing and integration tests
for live SCP verification.

Tests the "kosher" Scapy approach:
- DICOMVariableItem dispatches to typed sub-packets via bind_layers
- No manual struct.pack - Scapy calculates lengths and types automatically
"""
import pytest
import struct
import logging
import sys
import os
import warnings

warnings.filterwarnings("ignore")

# Add parent directory to path for local testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.contrib.dicom").setLevel(logging.INFO)

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
    # Variable Item classes (the "kosher" approach)
    DICOMVariableItem,
    DICOMApplicationContext,
    DICOMPresentationContextRQ,
    DICOMPresentationContextAC,
    DICOMAbstractSyntax,
    DICOMTransferSyntax,
    DICOMUserInformation,
    DICOMMaximumLength,
    DICOMImplementationClassUID,
    DICOMImplementationVersionName,
    DICOMGenericItem,
    # DIMSE Packet classes (Phase 3 - the kosher approach)
    C_ECHO_RQ,
    C_ECHO_RSP,
    C_STORE_RQ,
    C_STORE_RSP,
    C_FIND_RQ,
    # Helpers
    build_c_echo_rq_dimse,
    build_presentation_context_rq,
    build_user_information,
    DICOMSession,
    # Constants
    APP_CONTEXT_UID,
    VERIFICATION_SOP_CLASS_UID,
    DEFAULT_TRANSFER_SYNTAX_UID,
    CT_IMAGE_STORAGE_SOP_CLASS_UID,
    _pad_ae_title,
    _uid_to_bytes,
)


# =============================================================================
# Test Variable Item Layer Binding (The "Kosher" Approach)
# =============================================================================

class TestVariableItemBindLayers:
    """Test that bind_layers correctly dispatches based on item_type."""

    def test_application_context_bind_layers(self):
        """DICOMVariableItem() / DICOMApplicationContext() should auto-set item_type=0x10."""
        pkt = DICOMVariableItem() / DICOMApplicationContext()
        
        # item_type should be automatically set by bind_layers
        assert pkt.item_type == 0x10
        
        # Length should be auto-calculated
        raw = bytes(pkt)
        assert len(raw) > 4  # Header + payload
        
        # Verify round-trip
        parsed = DICOMVariableItem(raw)
        assert parsed.item_type == 0x10
        assert parsed.haslayer(DICOMApplicationContext)
        
    def test_abstract_syntax_bind_layers(self):
        """DICOMVariableItem() / DICOMAbstractSyntax() should auto-set item_type=0x30."""
        uid = _uid_to_bytes(VERIFICATION_SOP_CLASS_UID)
        pkt = DICOMVariableItem() / DICOMAbstractSyntax(uid=uid)
        
        assert pkt.item_type == 0x30
        
        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed.item_type == 0x30
        assert parsed.haslayer(DICOMAbstractSyntax)
        assert parsed[DICOMAbstractSyntax].uid == uid

    def test_transfer_syntax_bind_layers(self):
        """DICOMVariableItem() / DICOMTransferSyntax() should auto-set item_type=0x40."""
        pkt = DICOMVariableItem() / DICOMTransferSyntax()
        
        assert pkt.item_type == 0x40
        
        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed.item_type == 0x40
        assert parsed.haslayer(DICOMTransferSyntax)

    def test_maximum_length_bind_layers(self):
        """DICOMVariableItem() / DICOMMaximumLength() should auto-set item_type=0x51."""
        pkt = DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=32768)
        
        assert pkt.item_type == 0x51
        
        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed.item_type == 0x51
        assert parsed.haslayer(DICOMMaximumLength)
        assert parsed[DICOMMaximumLength].max_pdu_length == 32768

    def test_user_information_bind_layers(self):
        """DICOMVariableItem() / DICOMUserInformation() should auto-set item_type=0x50."""
        max_len = DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=16384)
        pkt = DICOMVariableItem() / DICOMUserInformation(sub_items=[max_len])
        
        assert pkt.item_type == 0x50
        
        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed.item_type == 0x50
        assert parsed.haslayer(DICOMUserInformation)

    def test_presentation_context_rq_bind_layers(self):
        """DICOMVariableItem() / DICOMPresentationContextRQ() should auto-set item_type=0x20."""
        abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid=_uid_to_bytes(VERIFICATION_SOP_CLASS_UID))
        ts = DICOMVariableItem() / DICOMTransferSyntax()
        
        pkt = DICOMVariableItem() / DICOMPresentationContextRQ(
            context_id=1,
            sub_items=[abs_syn, ts]
        )
        
        assert pkt.item_type == 0x20
        
        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed.item_type == 0x20
        assert parsed.haslayer(DICOMPresentationContextRQ)
        assert parsed[DICOMPresentationContextRQ].context_id == 1

    def test_presentation_context_ac_bind_layers(self):
        """DICOMVariableItem() / DICOMPresentationContextAC() should auto-set item_type=0x21."""
        ts = DICOMVariableItem() / DICOMTransferSyntax()
        
        pkt = DICOMVariableItem() / DICOMPresentationContextAC(
            context_id=1,
            result=0,
            sub_items=[ts]
        )
        
        assert pkt.item_type == 0x21
        
        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed.item_type == 0x21
        assert parsed.haslayer(DICOMPresentationContextAC)
        assert parsed[DICOMPresentationContextAC].result == 0

    def test_unknown_item_type_falls_back_to_generic(self):
        """Unknown item_type should parse into DICOMGenericItem."""
        # Manually construct an item with unknown type 0xFF
        raw = struct.pack("!BBH", 0xFF, 0, 4) + b"test"
        
        parsed = DICOMVariableItem(raw)
        assert parsed.item_type == 0xFF
        assert parsed.haslayer(DICOMGenericItem)
        assert parsed[DICOMGenericItem].data == b"test"


class TestVariableItemAutoLength:
    """Test that length field is auto-calculated from payload."""

    def test_application_context_length_auto(self):
        """Application Context length should be auto-calculated."""
        pkt = DICOMVariableItem() / DICOMApplicationContext()
        raw = bytes(pkt)
        
        # Parse length from raw bytes (bytes 2-3, big-endian)
        length_field = struct.unpack("!H", raw[2:4])[0]
        actual_payload = len(raw) - 4  # Total - header
        
        assert length_field == actual_payload

    def test_maximum_length_item_size(self):
        """Maximum Length item should be exactly 8 bytes (4 header + 4 data)."""
        pkt = DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=16384)
        raw = bytes(pkt)
        
        assert len(raw) == 8
        # Header: type=0x51, reserved=0, length=4
        assert raw[:4] == b'\x51\x00\x00\x04'

    def test_nested_items_length(self):
        """Nested items should have correct cumulative length."""
        max_len = DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=16384)
        user_info = DICOMVariableItem() / DICOMUserInformation(sub_items=[max_len])
        
        raw = bytes(user_info)
        
        # User info header (4) + nested max_len item (8)
        assert len(raw) == 12
        
        # User info length should be 8 (the nested item)
        ui_length = struct.unpack("!H", raw[2:4])[0]
        assert ui_length == 8


class TestHelperFunctions:
    """Test the helper functions for building common structures."""

    def test_build_presentation_context_rq(self):
        """build_presentation_context_rq should create proper nested structure."""
        pctx = build_presentation_context_rq(
            context_id=3,
            abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID,
            transfer_syntax_uids=[DEFAULT_TRANSFER_SYNTAX_UID]
        )
        
        assert pctx.item_type == 0x20
        assert pctx.haslayer(DICOMPresentationContextRQ)
        assert pctx[DICOMPresentationContextRQ].context_id == 3
        
        # Should have 2 sub-items: abstract syntax + transfer syntax
        sub_items = pctx[DICOMPresentationContextRQ].sub_items
        assert len(sub_items) == 2
        assert sub_items[0].item_type == 0x30  # Abstract Syntax
        assert sub_items[1].item_type == 0x40  # Transfer Syntax

    def test_build_user_information(self):
        """build_user_information should create proper nested structure."""
        user_info = build_user_information(max_pdu_length=32768)
        
        assert user_info.item_type == 0x50
        assert user_info.haslayer(DICOMUserInformation)
        
        sub_items = user_info[DICOMUserInformation].sub_items
        assert len(sub_items) >= 1
        assert sub_items[0].item_type == 0x51  # Maximum Length
        assert sub_items[0][DICOMMaximumLength].max_pdu_length == 32768

    def test_build_user_information_with_implementation(self):
        """build_user_information with implementation info."""
        user_info = build_user_information(
            max_pdu_length=16384,
            implementation_class_uid="1.2.3.4.5",
            implementation_version="SCAPY_V1"
        )
        
        sub_items = user_info[DICOMUserInformation].sub_items
        assert len(sub_items) == 3
        
        # Verify types
        types = [item.item_type for item in sub_items]
        assert 0x51 in types  # Maximum Length
        assert 0x52 in types  # Implementation Class UID
        assert 0x55 in types  # Implementation Version Name


# =============================================================================
# Test A-ASSOCIATE-RQ with Typed Variable Items
# =============================================================================

class TestAssociateRQWithTypedItems:
    """Test A-ASSOCIATE-RQ construction with the new typed item classes."""

    def test_simple_associate_rq(self):
        """Build simple A-ASSOCIATE-RQ with typed items."""
        # Application Context
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        
        # Presentation Context
        pctx = build_presentation_context_rq(
            context_id=1,
            abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID,
            transfer_syntax_uids=[DEFAULT_TRANSFER_SYNTAX_UID]
        )
        
        # User Information
        user_info = build_user_information(max_pdu_length=16384)
        
        # Build A-ASSOCIATE-RQ
        assoc_rq = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=_pad_ae_title("TARGET"),
            calling_ae_title=_pad_ae_title("SOURCE"),
            variable_items=[app_ctx, pctx, user_info]
        )
        
        raw = bytes(assoc_rq)
        
        # Verify it parses back correctly
        parsed = DICOM(raw)
        assert parsed.haslayer(A_ASSOCIATE_RQ)
        
        items = parsed[A_ASSOCIATE_RQ].variable_items
        assert len(items) == 3
        
        # Check types
        assert items[0].item_type == 0x10  # Application Context
        assert items[1].item_type == 0x20  # Presentation Context RQ
        assert items[2].item_type == 0x50  # User Information

    def test_associate_rq_with_multiple_presentation_contexts(self):
        """Build A-ASSOCIATE-RQ with multiple presentation contexts."""
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        
        pctx1 = build_presentation_context_rq(
            context_id=1,
            abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID,
            transfer_syntax_uids=[DEFAULT_TRANSFER_SYNTAX_UID]
        )
        pctx2 = build_presentation_context_rq(
            context_id=3,
            abstract_syntax_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            transfer_syntax_uids=[DEFAULT_TRANSFER_SYNTAX_UID]
        )
        
        user_info = build_user_information()
        
        assoc_rq = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=_pad_ae_title("TARGET"),
            calling_ae_title=_pad_ae_title("SOURCE"),
            variable_items=[app_ctx, pctx1, pctx2, user_info]
        )
        
        raw = bytes(assoc_rq)
        parsed = DICOM(raw)
        
        items = parsed[A_ASSOCIATE_RQ].variable_items
        assert len(items) == 4
        
        # Verify presentation context IDs
        pctx_items = [i for i in items if i.item_type == 0x20]
        assert len(pctx_items) == 2
        assert pctx_items[0][DICOMPresentationContextRQ].context_id == 1
        assert pctx_items[1][DICOMPresentationContextRQ].context_id == 3

    def test_associate_rq_round_trip_preserves_structure(self):
        """Verify complete nested structure survives round-trip."""
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        pctx = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
        user_info = build_user_information(max_pdu_length=32768)
        
        assoc_rq = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=_pad_ae_title("TARGET"),
            calling_ae_title=_pad_ae_title("SOURCE"),
            variable_items=[app_ctx, pctx, user_info]
        )
        
        raw = bytes(assoc_rq)
        parsed = DICOM(raw)
        
        # Drill down into nested structure
        user_info_parsed = None
        for item in parsed[A_ASSOCIATE_RQ].variable_items:
            if item.item_type == 0x50:
                user_info_parsed = item
                break
        
        assert user_info_parsed is not None
        assert user_info_parsed.haslayer(DICOMUserInformation)
        
        # Check nested Maximum Length
        max_len_item = user_info_parsed[DICOMUserInformation].sub_items[0]
        assert max_len_item.item_type == 0x51
        assert max_len_item[DICOMMaximumLength].max_pdu_length == 32768


# =============================================================================
# Original Test Classes (Updated for New Structure)
# =============================================================================

class TestCoreLayerValidation:
    """Tests for core packet construction and parsing."""

    def test_parse_associate_rq(self):
        """Test A-ASSOCIATE-RQ construction and parsing with variable items."""
        app_context = DICOMVariableItem() / DICOMApplicationContext()
        pctx = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
        user_info = build_user_information()

        pkt = DICOM() / A_ASSOCIATE_RQ(
            calling_ae_title=_pad_ae_title('VALIDATOR'),
            called_ae_title=_pad_ae_title('TEST_SCP'),
            variable_items=[app_context, pctx, user_info],
        )

        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.haslayer(A_ASSOCIATE_RQ)
        assert len(reparsed_pkt[A_ASSOCIATE_RQ].variable_items) == 3

    def test_parse_associate_rj(self):
        """Test A-ASSOCIATE-RJ construction and parsing."""
        pkt = DICOM() / A_ASSOCIATE_RJ(result=1, source=2, reason_diag=2)
        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.haslayer(A_ASSOCIATE_RJ)
        assert reparsed_pkt[A_ASSOCIATE_RJ].source == 2

    def test_parse_pdata_tf(self):
        """Test P-DATA-TF with multiple PDV items."""
        pdv1 = PresentationDataValueItem(
            context_id=1, data=b'\xDE\xAD', is_command=1, is_last=0
        )
        pdv2 = PresentationDataValueItem(
            context_id=1, data=b'\xBE\xEF', is_command=0, is_last=1
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv1, pdv2])
        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.haslayer(P_DATA_TF)
        assert len(reparsed_pkt[P_DATA_TF].pdv_items) == 2
        
        data = reparsed_pkt[P_DATA_TF].pdv_items[1].data
        if isinstance(data, str):
            data = data.encode('latin-1')
        assert data == b'\xBE\xEF'

    @pytest.mark.parametrize("pdu_type, layer_class", [
        (0x05, A_RELEASE_RQ),
        (0x06, A_RELEASE_RP),
        (0x07, A_ABORT),
    ])
    def test_parse_simple_pdus(self, pdu_type, layer_class):
        """Test simple PDU construction and parsing."""
        pkt = DICOM(pdu_type=pdu_type) / layer_class()
        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt.haslayer(layer_class)

    def test_construct_pdata_with_cecho(self):
        """Test P-DATA-TF with C-ECHO DIMSE command."""
        c_echo_dimse = build_c_echo_rq_dimse(message_id=123)
        pdv_echo = PresentationDataValueItem(
            context_id=1, data=c_echo_dimse, is_command=1, is_last=1
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv_echo])
        raw_bytes = bytes(pkt)
        assert raw_bytes.startswith(b'\x04\x00')
        assert c_echo_dimse in raw_bytes


class TestFuzzingCapabilities:
    """Tests for fuzzing and edge case handling."""

    def test_oversized_ae_title(self):
        """Test that oversized AE titles are truncated to 16 bytes."""
        oversized_title = b'A' * 25
        pkt = DICOM() / A_ASSOCIATE_RQ(called_ae_title=oversized_title)
        assert bytes(pkt)[10:26] == b'A' * 16

    def test_too_many_presentation_contexts(self):
        """Test handling of many presentation contexts (up to 128)."""
        contexts = []
        for i in range(128):
            ctx_id = (i * 2) + 1
            pctx = build_presentation_context_rq(
                context_id=ctx_id,
                abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID,
                transfer_syntax_uids=[DEFAULT_TRANSFER_SYNTAX_UID]
            )
            contexts.append(pctx)
        
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        user_info = build_user_information()
        
        pkt = DICOM() / A_ASSOCIATE_RQ(variable_items=[app_ctx] + contexts + [user_info])
        reparsed_pkt = DICOM(bytes(pkt))
        assert len(reparsed_pkt[A_ASSOCIATE_RQ].variable_items) == 130  # 1 app + 128 pctx + 1 user

    def test_manipulate_max_pdu_length(self):
        """Test maximum PDU length manipulation."""
        user_info = build_user_information(max_pdu_length=0x7FFFFFFF)
        raw = bytes(user_info)
        assert b'\x7f\xff\xff\xff' in raw

    def test_illogical_fragmentation(self):
        """Test incomplete fragmentation flag handling."""
        pdv = PresentationDataValueItem(
            context_id=1, data=b'fragment', is_last=0
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv])
        reparsed_pkt = DICOM(bytes(pkt))
        assert reparsed_pkt[P_DATA_TF].pdv_items[0].is_last == 0

    def test_pdu_type_confusion(self):
        """Test PDU type mismatch (P-DATA type with A-ASSOCIATE payload)."""
        pkt = DICOM(pdu_type=0x04) / A_ASSOCIATE_RQ()
        raw_bytes = bytes(pkt)
        assert raw_bytes[0] == 0x04
        assert raw_bytes[6:10] == b'\x00\x01\x00\x00'

    def test_null_byte_injection_in_ae(self):
        """Test null byte handling in AE titles."""
        injected_title = b'SCAPY\x00FUZZER'.ljust(16)
        pkt = DICOM() / A_ASSOCIATE_RQ(calling_ae_title=injected_title)
        assert bytes(pkt)[26:42] == injected_title


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
        assert parsed[A_ASSOCIATE_RQ].calling_ae_title == b"SOURCE          "

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
        assert len(parsed[P_DATA_TF].pdv_items) == 1
        parsed_pdv = parsed[P_DATA_TF].pdv_items[0]
        assert parsed_pdv.context_id == 3
        
        parsed_data = parsed_pdv.data
        if isinstance(parsed_data, str):
            parsed_data = parsed_data.encode('latin-1')
        assert parsed_data == test_data

    def test_abort_round_trip(self):
        """A-ABORT should survive serialization round-trip."""
        original = DICOM() / A_ABORT(source=2, reason_diag=6)
        serialized = bytes(original)
        parsed = DICOM(serialized)

        assert parsed.haslayer(A_ABORT)
        assert parsed[A_ABORT].source == 2
        assert parsed[A_ABORT].reason_diag == 6

    def test_pdv_flags_round_trip(self):
        """PresentationDataValueItem flags should survive round-trip."""
        for is_cmd in [0, 1]:
            for is_last in [0, 1]:
                pdv = PresentationDataValueItem(
                    context_id=1, data=b'test', is_command=is_cmd, is_last=is_last
                )
                pkt = DICOM() / P_DATA_TF(pdv_items=[pdv])
                parsed = DICOM(bytes(pkt))
                parsed_pdv = parsed[P_DATA_TF].pdv_items[0]
                assert parsed_pdv.is_command == is_cmd
                assert parsed_pdv.is_last == is_last


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_variable_items(self):
        """A-ASSOCIATE-RQ with no variable items."""
        pkt = DICOM() / A_ASSOCIATE_RQ(variable_items=[])
        serialized = bytes(pkt)
        parsed = DICOM(serialized)
        assert parsed.haslayer(A_ASSOCIATE_RQ)

    def test_pdata_no_pdv_items(self):
        """P-DATA-TF with empty PDV list."""
        pkt = DICOM() / P_DATA_TF(pdv_items=[])
        serialized = bytes(pkt)
        assert len(serialized) == 6

    def test_pdu_type_preservation(self):
        """Each PDU type should have correct type byte after serialization."""
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


class TestBitFieldFlags:
    """Test the BitField-based is_command and is_last flags."""

    def test_is_command_flag(self):
        """Test is_command flag encoding."""
        pdv = PresentationDataValueItem(context_id=1, data=b'x', is_command=1, is_last=0)
        raw = bytes(pdv)
        msg_ctrl = raw[5]
        assert msg_ctrl & 0x01 == 1
        assert msg_ctrl & 0x02 == 0

    def test_is_last_flag(self):
        """Test is_last flag encoding."""
        pdv = PresentationDataValueItem(context_id=1, data=b'x', is_command=0, is_last=1)
        raw = bytes(pdv)
        msg_ctrl = raw[5]
        assert msg_ctrl & 0x01 == 0
        assert msg_ctrl & 0x02 == 2

    def test_both_flags_set(self):
        """Test both flags set together."""
        pdv = PresentationDataValueItem(context_id=1, data=b'x', is_command=1, is_last=1)
        raw = bytes(pdv)
        msg_ctrl = raw[5]
        assert msg_ctrl == 0x03


# =============================================================================
# Test DIMSE Packet Classes (Phase 3 - The Kosher Approach)
# =============================================================================

class TestDIMSEPacketClasses:
    """Test the new DIMSE packet classes that replace build_*_dimse functions."""

    def test_c_echo_rq_creation(self):
        """C_ECHO_RQ packet should be creatable with default values."""
        pkt = C_ECHO_RQ()
        raw = bytes(pkt)
        
        # Should have CommandGroupLength at the start
        assert raw[:4] == b'\x00\x00\x00\x00'  # Tag (0000,0000)
        
        # Should contain the Verification SOP Class UID
        assert b'1.2.840.10008.1.1' in raw

    def test_c_echo_rq_custom_message_id(self):
        """C_ECHO_RQ should allow custom message_id for fuzzing."""
        pkt = C_ECHO_RQ(message_id=12345)
        raw = bytes(pkt)
        
        # Message ID should be encoded as little-endian at tag (0000,0110)
        # Find the tag and check the value
        assert b'\x10\x01' in raw  # Tag element 0x0110
        assert struct.pack("<H", 12345) in raw

    def test_c_echo_rq_matches_legacy_builder(self):
        """C_ECHO_RQ packet should produce same bytes as legacy build function."""
        legacy = build_c_echo_rq_dimse(message_id=42)
        kosher = bytes(C_ECHO_RQ(message_id=42))
        
        assert legacy == kosher

    def test_c_echo_rsp_creation(self):
        """C_ECHO_RSP packet should be creatable."""
        pkt = C_ECHO_RSP(message_id_responded=42, status=0x0000)
        raw = bytes(pkt)
        
        # Should have command field 0x8030
        assert struct.pack("<H", 0x8030) in raw
        # Should have status 0x0000
        assert b'\x00\x09' in raw  # Tag element 0x0900

    def test_c_store_rq_creation(self):
        """C_STORE_RQ packet should be creatable with UIDs."""
        pkt = C_STORE_RQ(
            affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            affected_sop_instance_uid="1.2.3.4.5.6.7.8.9",
            message_id=100,
        )
        raw = bytes(pkt)
        
        # Should contain CT Image Storage SOP Class UID
        assert b'1.2.840.10008.5.1.4.1.1.2' in raw
        # Should contain the instance UID
        assert b'1.2.3.4.5.6.7.8.9' in raw
        # Should have command field 0x0001 (C-STORE-RQ)
        assert struct.pack("<H", 0x0001) in raw

    def test_c_store_rq_with_priority(self):
        """C_STORE_RQ should allow setting priority."""
        pkt = C_STORE_RQ(priority=0x0001)  # HIGH priority
        raw = bytes(pkt)
        
        # Priority tag (0000,0700) should contain 0x0001
        assert b'\x00\x07' in raw  # Tag element 0x0700

    def test_c_find_rq_creation(self):
        """C_FIND_RQ packet should be creatable."""
        pkt = C_FIND_RQ(message_id=55)
        raw = bytes(pkt)
        
        # Should have command field 0x0020 (C-FIND-RQ)
        assert struct.pack("<H", 0x0020) in raw

    def test_dimse_show_output(self):
        """DIMSE packets should have meaningful show() output."""
        pkt = C_ECHO_RQ(message_id=999)
        # Just verify it doesn't crash - show() returns None
        pkt.show()

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
        assert len(parsed[P_DATA_TF].pdv_items) == 1
        
        # The DIMSE data should be in the PDV
        pdv_data = parsed[P_DATA_TF].pdv_items[0].data
        if isinstance(pdv_data, str):
            pdv_data = pdv_data.encode('latin-1')
        assert b'1.2.840.10008.1.1' in pdv_data  # Verification SOP Class UID


class TestDIMSEFuzzing:
    """Test fuzzing capabilities with the new DIMSE packet classes."""

    def test_fuzz_message_id_boundary(self):
        """Test boundary message IDs."""
        for msg_id in [0, 1, 0x7FFF, 0xFFFF]:
            pkt = C_ECHO_RQ(message_id=msg_id)
            raw = bytes(pkt)
            assert struct.pack("<H", msg_id) in raw

    def test_fuzz_invalid_command_field(self):
        """Test setting invalid command field values."""
        pkt = C_ECHO_RQ()
        pkt.command_field = 0xDEAD  # Invalid command
        raw = bytes(pkt)
        assert struct.pack("<H", 0xDEAD) in raw

    def test_fuzz_invalid_data_set_type(self):
        """Test invalid data set type values."""
        pkt = C_ECHO_RQ()
        pkt.data_set_type = 0xBEEF
        raw = bytes(pkt)
        assert struct.pack("<H", 0xBEEF) in raw

    def test_fuzz_malformed_uid(self):
        """Test with intentionally malformed UID."""
        # Odd-length UID (should normally be padded)
        pkt = C_ECHO_RQ(affected_sop_class_uid="1.2.3")
        raw = bytes(pkt)
        # The UID gets padded to even length by DICOMUIDField
        assert b'1.2.3' in raw

    def test_fuzz_c_store_empty_instance_uid(self):
        """Test C-STORE with empty instance UID."""
        pkt = C_STORE_RQ(
            affected_sop_instance_uid="",
            message_id=1,
        )
        raw = bytes(pkt)
        # Should still serialize without crashing
        assert len(raw) > 0

    def test_fuzz_extreme_priority(self):
        """Test C-STORE with out-of-range priority."""
        pkt = C_STORE_RQ(priority=0xFFFF)
        raw = bytes(pkt)
        assert struct.pack("<H", 0xFFFF) in raw


class TestStreamSocketFraming:
    """Test that DICOM class has proper framing for StreamSocket."""

    def test_dicom_extract_padding_single_pdu(self):
        """DICOM.extract_padding should separate PDU from trailing data."""
        # Build a packet
        pkt = DICOM() / A_RELEASE_RQ()
        raw = bytes(pkt)
        
        # Add some trailing "next PDU" data
        trailing = b'\x07\x00\x00\x00\x00\x04\x00\x00\x00\x00'  # A-ABORT header
        combined = raw + trailing
        
        # Parse just the first PDU
        parsed = DICOM(combined)
        
        # The parsed packet should have the correct length
        assert parsed.length == 4  # A_RELEASE_RQ payload is 4 bytes
        
        # extract_padding should separate the trailing data
        # (This is what enables PacketListField and StreamSocket to work)

    def test_dicom_extract_padding_with_length(self):
        """Verify extract_padding returns correct split based on length field."""
        # Create a DICOM header with known length
        pkt = DICOM() / A_ASSOCIATE_RJ(result=1, source=2, reason_diag=3)
        raw = bytes(pkt)
        
        # Parse it
        parsed = DICOM(raw)
        
        # Length should be 4 (A_ASSOCIATE_RJ is 4 bytes)
        assert parsed.length == 4
        assert parsed.haslayer(A_ASSOCIATE_RJ)

    def test_dicom_has_extract_padding_method(self):
        """DICOM class should have extract_padding for StreamSocket compatibility."""
        pkt = DICOM()
        assert hasattr(pkt, 'extract_padding')
        
        # Test the method
        pkt.length = 10
        payload, remaining = pkt.extract_padding(b'0123456789EXTRA')
        assert payload == b'0123456789'
        assert remaining == b'EXTRA'


class TestSessionUsesStreamSocket:
    """Test that DICOMSession uses StreamSocket idioms."""

    def test_session_has_stream_methods(self):
        """DICOMSession should expose send/recv/sr1 methods."""
        from dicom import DICOMSession
        
        session = DICOMSession("127.0.0.1", 104, "TEST")
        
        # Should have these methods (StreamSocket pattern)
        assert hasattr(session, 'send')
        assert hasattr(session, 'recv')
        assert hasattr(session, 'sr1')
        
        # Should NOT have the old manual methods
        assert not hasattr(session, '_recv_pdu')
        assert not hasattr(session, '_send_pdu')

    def test_session_no_manual_socket_loops(self):
        """DICOMSession should not have manual recv loops."""
        import inspect
        from dicom import DICOMSession
        
        # Get source code of the class
        source = inspect.getsource(DICOMSession)
        
        # Should not contain manual recv loop patterns
        assert 'while len(header) < 6' not in source
        assert 'while len(payload) < pdu_length' not in source
        
        # Should use StreamSocket methods
        assert 'self.stream.recv()' in source or 'self.recv()' in source
        assert 'self.stream.sr1(' in source or 'self.sr1(' in source


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
    sop_instance_uid = "1.2.3.4.5.6.7.8"
    study_instance_uid = "1.2.3.4.5.6.7.8.9"
    series_instance_uid = "1.2.3.4.5.6.7.8.9.10"
    sop_class_uid_bytes = _uid_to_bytes(CT_IMAGE_STORAGE_SOP_CLASS_UID)
    sop_instance_uid_bytes = _uid_to_bytes(sop_instance_uid)
    study_instance_uid_bytes = _uid_to_bytes(study_instance_uid)
    series_instance_uid_bytes = _uid_to_bytes(series_instance_uid)

    dataset_elements = []
    dataset_elements.append(
        struct.pack('<HHI', 0x0008, 0x0016, len(sop_class_uid_bytes))
        + sop_class_uid_bytes
    )
    dataset_elements.append(
        struct.pack('<HHI', 0x0008, 0x0018, len(sop_instance_uid_bytes))
        + sop_instance_uid_bytes
    )
    patient_id = b'TEST'
    dataset_elements.append(
        struct.pack('<HHI', 0x0010, 0x0020, len(patient_id)) + patient_id
    )
    dataset_elements.append(
        struct.pack('<HHI', 0x0020, 0x000D, len(study_instance_uid_bytes))
        + study_instance_uid_bytes
    )
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
        store_context = {CT_IMAGE_STORAGE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}
        assoc_success = session.associate(requested_contexts=store_context)
        assert assoc_success, "Association for C-STORE failed"

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