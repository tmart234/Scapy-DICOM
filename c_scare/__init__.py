# SPDX-License-Identifier: GPL-2.0-only
"""
C-Scare - DICOM Security Testing Framework

"Scapy for DICOM" - Full control over every byte at every layer.

Architecture:
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                         C-Scare Framework                               │
    ├─────────────────────────────────────────────────────────────────────────┤
    │  Attack Patterns                                                        │
    │    ParserAttacks, ProtocolAttacks, MemoryAttacks, StateMachineAttacks   │
    ├─────────────────────────────────────────────────────────────────────────┤
    │  Corruptor (THE KEY)                                                    │
    │    pydicom.Dataset ──→ [surgical corruption] ──→ our encoder            │
    ├─────────────────────────────────────────────────────────────────────────┤
    │  Dataset Layer              File Layer              Pixel Layer         │
    │    element.py                 file.py                 pixel.py          │
    │    Element, Dataset           DicomFile               Fragments         │
    ├─────────────────────────────────────────────────────────────────────────┤
    │  Scapy Protocol Layer (scapy_dicom.py)                                  │
    │    A_ASSOCIATE_RQ/AC/RJ, P_DATA_TF, A_RELEASE, A_ABORT                  │
    │    C_ECHO_RQ, C_STORE_RQ, C_FIND_RQ, C_MOVE_RQ + responses              │
    │    DICOMSocket (client), RawSCP (rogue server)                          │
    └─────────────────────────────────────────────────────────────────────────┘

Quick Start:
    # 1. Corrupt existing DICOM (pydicom bridge)
    import pydicom
    from c_scare import Corruptor
    
    ds = pydicom.dcmread("ct_scan.dcm")
    c = Corruptor(ds)
    c.set_vr(0x00100010, 'XX')           # Invalid VR
    c.set_length(0x00100020, 0xFFFFFFFF) # Lie about length
    corrupted = c.to_file()
    
    # 2. Build datasets from scratch (Scapy-style)
    from c_scare import Element, Dataset
    
    ds = (Dataset()
        / Element(0x0010, 0x0010, 'PN', 'Test^Patient')
        / Element.raw(tag=0x00100020, vr='XX', value=b'fuzz')
    )
    
    # 3. Protocol fuzzing with Scapy packets
    from c_scare.scapy_dicom import *
    from scapy.packet import raw, fuzz
    
    # Build malformed association
    pkt = DICOM() / A_ASSOCIATE_RQ(protocol_version=0xFFFF)
    pdu_bytes = raw(pkt)
    
    # Use DICOMSocket for full association
    with DICOMSocket('target', 11112, 'PACS', 'EVIL') as sock:
        sock.associate({CT_IMAGE_STORAGE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]})
        sock.c_store(corrupted_dataset, sop_class, sop_instance, ts)
    
    # 4. Rogue server for fuzzing clients
    from c_scare import RawSCP, ConnectionState
    from c_scare.scapy_dicom import A_ASSOCIATE_AC, A_ABORT
    
    scp = RawSCP(port=11112)
    
    @scp.on_associate_rq
    def handle(conn, pdu_bytes, pkt):
        return raw(DICOM() / A_ASSOCIATE_AC(protocol_version=0xFFFF))
    
    @scp.on_state(ConnectionState.ASSOCIATED)
    def on_sta6(conn):
        conn.inject(raw(DICOM() / A_ABORT()))
    
    scp.start()
"""

__version__ = '0.3.0'
__author__ = 'Tyler M'

# =============================================================================
# Core Building Blocks (Dataset Layer)
# =============================================================================

from element import (
    Element,
    Dataset,
    Sequence,
    Tag,
    VR,
    hexdump,
    parse,
    parse_element,
)

# =============================================================================
# Pydicom Integration (THE KEY VALUE-ADD)
# =============================================================================

from corruptor import (
    Corruptor,
    Override,
    Injection,
    InjectionPoint,
    SequencePath,
    corrupt_vr,
    corrupt_length,
    duplicate_tag,
)

# =============================================================================
# Encapsulated Pixel Data
# =============================================================================

from pixel import (
    EncapsulatedPixelData,
    PixelData,
    Fragment,
    corrupt_jpeg_header,
    corrupt_jpeg_eoi,
    truncate_fragment,
)

# =============================================================================
# File Handling (Part 10)
# =============================================================================

from file import (
    DicomFile,
    FileMetaInformation,
    TransferSyntax,
    make_secondary_capture,
)

# =============================================================================
# Scapy Protocol Layer (ALL PDU/DIMSE from here)
# =============================================================================

# Scapy may not be available or may fail in sandboxed environments
try:
    from scapy_dicom import (
        # PDU packets
        DICOM,
        A_ASSOCIATE_RQ,
        A_ASSOCIATE_AC,
        A_ASSOCIATE_RJ,
        P_DATA_TF,
        A_RELEASE_RQ,
        A_RELEASE_RP,
        A_ABORT,
        
        # DIMSE packets
        C_ECHO_RQ,
        C_ECHO_RSP,
        C_STORE_RQ,
        C_STORE_RSP,
        C_FIND_RQ,
        C_FIND_RSP,
        C_MOVE_RQ,
        C_MOVE_RSP,
        C_GET_RQ,
        C_GET_RSP,
        
        # Fuzz packet variants (explicit fields, no auto-calculation)
        DIMSEPacketFuzz,
        C_ECHO_RQ_Fuzz,
        C_STORE_RQ_Fuzz,
        C_FIND_RQ_Fuzz,
        C_MOVE_RQ_Fuzz,
        
        # Helper packets
        PresentationDataValueItem,
        DICOMVariableItem,
        DICOMApplicationContext,
        DICOMPresentationContextRQ,
        DICOMPresentationContextAC,
        DICOMUserInformation,
        DICOMMaximumLength,
        DICOMAbstractSyntax,
        DICOMTransferSyntax,
        
        # Client socket
        DICOMSocket,
        
        # Helper functions
        build_presentation_context_rq,
        build_user_information,
        
        # Common UIDs
        DEFAULT_TRANSFER_SYNTAX_UID,
        EXPLICIT_VR_LITTLE_ENDIAN_UID,
        IMPLICIT_VR_LITTLE_ENDIAN_UID,
        VERIFICATION_SOP_CLASS_UID,
        CT_IMAGE_STORAGE_SOP_CLASS_UID,
        MR_IMAGE_STORAGE_SOP_CLASS_UID,
        SECONDARY_CAPTURE_SOP_CLASS_UID,
        IMPLEMENTATION_CLASS_UID,
    )
    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_AVAILABLE = False
    _scapy_import_error = str(e)
    
    # Provide stubs so imports don't fail
    DICOM = None
    A_ASSOCIATE_RQ = A_ASSOCIATE_AC = A_ASSOCIATE_RJ = None
    P_DATA_TF = A_RELEASE_RQ = A_RELEASE_RP = A_ABORT = None
    C_ECHO_RQ = C_ECHO_RSP = C_STORE_RQ = C_STORE_RSP = None
    C_FIND_RQ = C_FIND_RSP = C_MOVE_RQ = C_MOVE_RSP = None
    C_GET_RQ = C_GET_RSP = None
    DIMSEPacketFuzz = C_ECHO_RQ_Fuzz = C_STORE_RQ_Fuzz = None
    C_FIND_RQ_Fuzz = C_MOVE_RQ_Fuzz = None
    PresentationDataValueItem = DICOMVariableItem = None
    DICOMApplicationContext = DICOMPresentationContextRQ = None
    DICOMPresentationContextAC = DICOMUserInformation = None
    DICOMMaximumLength = DICOMAbstractSyntax = DICOMTransferSyntax = None
    DICOMSocket = None
    build_presentation_context_rq = build_user_information = None
    
    # UIDs are just strings, safe to define
    DEFAULT_TRANSFER_SYNTAX_UID = '1.2.840.10008.1.2'
    EXPLICIT_VR_LITTLE_ENDIAN_UID = '1.2.840.10008.1.2.1'
    IMPLICIT_VR_LITTLE_ENDIAN_UID = '1.2.840.10008.1.2'
    VERIFICATION_SOP_CLASS_UID = '1.2.840.10008.1.1'
    CT_IMAGE_STORAGE_SOP_CLASS_UID = '1.2.840.10008.5.1.4.1.1.2'
    MR_IMAGE_STORAGE_SOP_CLASS_UID = '1.2.840.10008.5.1.4.1.1.4'
    SECONDARY_CAPTURE_SOP_CLASS_UID = '1.2.840.10008.5.1.4.1.1.7'
    IMPLEMENTATION_CLASS_UID = '1.2.3.4.5.6.7.8.9'

# =============================================================================
# Rogue Server (for fuzzing clients)
# =============================================================================

from c_scare.server import (
    RawSCP,
    Connection,
    ConnectionState,
)

# =============================================================================
# Attack Patterns (High-level API)
# =============================================================================

from attacks import (
    AttackResult,
    ParserAttacks,
    ProtocolAttacks,
    MemoryAttacks,
    LogicAttacks,
    TargetedFuzzer,
    CombinedAttacks,
    StateMachineAttacks,
    CVEAttacks,
    ProtocolFuzzer,
)

# =============================================================================
# Scapy Layer Installation Helper
# =============================================================================

from c_scare.scapy_layer import (
    install_scapy_layer,
    load_scapy_layer,
    get_scapy_layer_path,
)

# =============================================================================
# All Exports
# =============================================================================

__all__ = [
    # Version
    '__version__',
    
    # Core Dataset
    'Element', 'Dataset', 'Sequence', 'Tag', 'VR',
    'hexdump', 'parse', 'parse_element',
    
    # Corruptor (KEY)
    'Corruptor', 'Override', 'Injection', 'InjectionPoint', 'SequencePath',
    'corrupt_vr', 'corrupt_length', 'duplicate_tag',
    
    # Pixel Data
    'EncapsulatedPixelData', 'PixelData', 'Fragment',
    'corrupt_jpeg_header', 'corrupt_jpeg_eoi', 'truncate_fragment',
    
    # File
    'DicomFile', 'FileMetaInformation', 'TransferSyntax',
    'make_secondary_capture',
    
    # Scapy PDU Packets
    'DICOM',
    'A_ASSOCIATE_RQ', 'A_ASSOCIATE_AC', 'A_ASSOCIATE_RJ',
    'P_DATA_TF', 'A_RELEASE_RQ', 'A_RELEASE_RP', 'A_ABORT',
    
    # Scapy DIMSE Packets
    'C_ECHO_RQ', 'C_ECHO_RSP',
    'C_STORE_RQ', 'C_STORE_RSP',
    'C_FIND_RQ', 'C_FIND_RSP',
    'C_MOVE_RQ', 'C_MOVE_RSP',
    'C_GET_RQ', 'C_GET_RSP',
    
    # Scapy Fuzz Packets (explicit fields, no auto-calculation)
    'DIMSEPacketFuzz',
    'C_ECHO_RQ_Fuzz', 'C_STORE_RQ_Fuzz',
    'C_FIND_RQ_Fuzz', 'C_MOVE_RQ_Fuzz',
    
    # Scapy Helper Packets
    'PresentationDataValueItem',
    'DICOMVariableItem', 'DICOMApplicationContext',
    'DICOMPresentationContextRQ', 'DICOMPresentationContextAC',
    'DICOMUserInformation', 'DICOMMaximumLength',
    'DICOMAbstractSyntax', 'DICOMTransferSyntax',
    
    # Client Socket
    'DICOMSocket',
    
    # Helpers
    'build_presentation_context_rq', 'build_user_information',
    
    # Common UIDs
    'DEFAULT_TRANSFER_SYNTAX_UID', 'EXPLICIT_VR_LITTLE_ENDIAN_UID',
    'IMPLICIT_VR_LITTLE_ENDIAN_UID', 'VERIFICATION_SOP_CLASS_UID',
    'CT_IMAGE_STORAGE_SOP_CLASS_UID', 'MR_IMAGE_STORAGE_SOP_CLASS_UID',
    'SECONDARY_CAPTURE_SOP_CLASS_UID', 'IMPLEMENTATION_CLASS_UID',
    
    # Rogue Server
    'RawSCP', 'Connection', 'ConnectionState',
    
    # Attack Patterns
    'AttackResult',
    'ParserAttacks', 'ProtocolAttacks', 'MemoryAttacks', 'LogicAttacks',
    'TargetedFuzzer', 'CombinedAttacks', 'StateMachineAttacks',
    'CVEAttacks', 'ProtocolFuzzer',
    
    # Scapy Installation
    'install_scapy_layer', 'load_scapy_layer', 'get_scapy_layer_path',
]
