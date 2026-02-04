# C-Scare

A DICOM Security Testing Framework

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              C-Scare Framework                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│  Attack Patterns (attacks.py)                                                   │
│    ParserAttacks, ProtocolAttacks, MemoryAttacks, StateMachineAttacks           │
│    Corpus generation, targeted fuzzing, combined attacks                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│  Corruptor (corruptor.py)                                         │
│    pydicom.Dataset ──→ [surgical corruption] ──→ our encoder                    │
│    Preserves: transfer syntax, sequences, private tags, pixel data              │
│    Corrupts: VR, length, value, tag order, duplicates                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│  Dataset Layer              File Layer              Pixel Layer                 │
│    element.py                 file.py                 pixel.py                  │
│    Element, Dataset           DicomFile               EncapsulatedPixelData     │
│    Scapy-style chaining       Part 10 files           Fragment manipulation     │
│    Element.raw() control      Transfer syntax         Offset table attacks      │
├─────────────────────────────────────────────────────────────────────────────────┤
│  Scapy Protocol Layer (scapy_dicom.py)             │
│    PDU: A_ASSOCIATE_RQ/AC/RJ, P_DATA_TF, A_RELEASE, A_ABORT                     │
│    DIMSE: C_ECHO_RQ, C_STORE_RQ, C_FIND_RQ, C_MOVE_RQ + responses               │
│    Client: DICOMSocket with full Scapy integration                              │
│    Server: RawSCP with state machine hooks (Sta1-Sta13)                         │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## DICOM Stack Coverage

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Application Layer                                                               │
│   IOD constraints, SOP Class semantics                                          │
│   ► LogicAttacks: SOP class mismatch, transfer syntax mismatch                  │
│   ► Tool: attacks.py (LogicAttacks class)                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Dataset Layer                                                                   │
│   Elements, Sequences, Values                                                   │
│   ► Element.raw(): arbitrary VR, length, value bytes                            │
│   ► Corruptor: surgical corruption of pydicom datasets                          │
│   ► ParserAttacks: VR fuzzing, length overflow/underflow, sequence bombs        │
│   ► Tool: element.py, corruptor.py, attacks.py                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│ DIMSE Layer                                                                     │
│   C-STORE, C-FIND, C-ECHO commands + data                                       │
│   ► Scapy DIMSE packets with field overrides                                    │
│   ► fuzz() for automatic field mutation                                         │
│   ► Tool: scapy_dicom.py (C_ECHO_RQ, C_STORE_RQ, etc.)                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│ PDU Layer                                                                       │
│   A-ASSOCIATE, P-DATA-TF, A-RELEASE, A-ABORT                                    │
│   ► Scapy PDU packets with raw() for byte-level control                         │
│   ► ProtocolAttacks, StateMachineAttacks                                        │
│   ► Tool: scapy_dicom.py (A_ASSOCIATE_RQ, P_DATA_TF, etc.)                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Transport Layer                                                                 │
│   TCP segments                                                                  │
│   ► DICOMSocket: full Scapy integration                                         │
│   ► RawSCP: rogue server for fuzzing clients                                    │
│   ► Tool: scapy_dicom.py (DICOMSocket), server.py (RawSCP)                      │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Corrupt Existing DICOM (Pydicom Bridge)

```python
import pydicom
from c_scare import Corruptor

# Load with pydicom (it understands everything)
ds = pydicom.dcmread("real_scanner_output.dcm")

# Wrap for surgical corruption
c = Corruptor(ds)

# Corrupt specific fields - everything else stays intact
c.set_vr(0x00100010, 'XX')           # Change only the VR
c.set_length(0x00100020, 0xFFFFFFFF) # Lie about length
c.inject_before(0x00100010, b'garbage')  # Insert bytes
c.duplicate(0x00100010)               # Duplicate tag
c.reorder([(0x0020,0x0010), (0x0010,0x0010)])  # Wrong order

# Encode (pydicom would reject this)
corrupted = c.to_file()
```

### 2. Build Malformed Datasets (Scapy-style)

```python
from c_scare import Element, Dataset

# Chain elements like Scapy's IP()/TCP()
ds = (Dataset()
    / Element(0x0010, 0x0010, 'PN', 'Doe^John')
    / Element(0x0010, 0x0020, 'LO', '12345')
)

# Full byte control with Element.raw()
ds = (Dataset()
    / Element.raw(tag=0x00100010, vr='XX', value=b'fuzz')  # Invalid VR
    / Element.raw(tag=0x00100020, vr='LO', length=0xFFFF, value=b'x')  # Lie about length
)

raw_bytes = ds.encode()
```

### 3. Protocol Fuzzing (Scapy Packets)

```python
from c_scare.scapy_dicom import *
from scapy.packet import raw, fuzz

# Build malformed association
pkt = DICOM() / A_ASSOCIATE_RQ(
    protocol_version=0xFFFF,  # Invalid!
    called_ae_title='TARGET',
    calling_ae_title='EVIL',
)

# Get raw bytes
pdu_bytes = raw(pkt)

# Automatic fuzzing
fuzzed_pkt = fuzz(DICOM() / A_ASSOCIATE_RQ())

# Full DICOM session
with DICOMSocket('192.168.1.100', 11112, 'PACS', 'ATTACKER') as sock:
    if sock.associate({CT_IMAGE_STORAGE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}):
        sock.c_store(dataset_bytes, sop_class_uid, sop_instance_uid, transfer_syntax)
        sock.release()
```

### 4. Rogue Server (Fuzz Clients)

```python
from c_scare import RawSCP, ConnectionState
from c_scare.scapy_dicom import DICOM, A_ASSOCIATE_AC, A_ABORT
from scapy.packet import raw

scp = RawSCP(port=11112)

@scp.on_associate_rq
def handle_assoc(conn, pdu_bytes, pkt):
    # pkt is Scapy A_ASSOCIATE_RQ (or None if parse failed)
    # Return malformed response
    ac = DICOM() / A_ASSOCIATE_AC(protocol_version=0xFFFF)
    return raw(ac)

@scp.on_state(ConnectionState.ASSOCIATED)
def on_sta6(conn):
    # Inject A-ABORT when association established (Sta6)
    conn.inject(raw(DICOM() / A_ABORT()))

@scp.on_pdata
def handle_pdata(conn, pdu_bytes, pkt):
    # Full control over response
    return malformed_response_bytes

scp.start()
```

### 5. Pre-built Attack Patterns

```python
from c_scare import ParserAttacks, ProtocolAttacks, MemoryAttacks, StateMachineAttacks

# Generate fuzzing corpus
corpus = ParserAttacks.generate_corpus('/path/to/corpus', count=100)

# Individual attacks
attack = ParserAttacks.invalid_vr('ZZ')
attack = ParserAttacks.length_overflow(0xFFFFFFFF, 10)
attack = ParserAttacks.sequence_bomb(depth=500)
attack = MemoryAttacks.pixel_dimension_overflow()

# Protocol fuzzing
results = ProtocolAttacks.fuzz_association('target', 11112, count=50)

# State machine attacks
sm = StateMachineAttacks(('target', 11112))
result = sm.pdata_before_assoc()    # P-DATA-TF in Sta1
result = sm.double_association()     # Second A-ASSOCIATE-RQ in Sta6
result = sm.release_then_pdata()     # P-DATA-TF after A-RELEASE
```

### 6. Targeted Fuzzing (Pydicom + Attacks)

```python
import pydicom
from c_scare import TargetedFuzzer

ds = pydicom.dcmread("real_scanner.dcm")
fuzzer = TargetedFuzzer(ds)

# Target specific VR parser
for attack in fuzzer.target_vr_parser('PN'):
    test_target(attack.payload)

# Target length handling
for attack in fuzzer.target_length_handling():
    test_target(attack.payload)

# Target pixel data
for attack in fuzzer.target_pixel_data():
    test_target(attack.payload)
```

## Module Reference

| Module | Purpose |
|--------|---------|
| `element.py` | Core Dataset/Element building with Scapy-style chaining |
| `corruptor.py` | Pydicom bridge for surgical corruption (THE KEY) |
| `pixel.py` | Encapsulated pixel data with fragment-level control |
| `file.py` | Part 10 file handling (preamble, meta header) |
| `scapy_dicom.py` | **ALL protocol** - PDUs, DIMSE, DICOMSocket |
| `server.py` | RawSCP - rogue server for fuzzing clients |
| `attacks.py` | Pre-built attack patterns and corpus generation |
| `scapy_layer.py` | Scapy layer installation helper |

## Installation

```bash
# Core (no Scapy dependency for dataset manipulation)
pip install c_scare

# Full (with Scapy for protocol testing)
pip install c_scare scapy

# With pydicom (for Corruptor)
pip install c_scare pydicom scapy
```

## Design Philosophy

1. **Scapy for protocol, our code for datasets**
   - scapy_dicom.py is the single source of truth for PDU/DIMSE
   - No redundant packet builders - Scapy does it right

2. **Pydicom for understanding, our encoder for output**
   - Pydicom excels at parsing (transfer syntaxes, sequences, private tags)
   - But it validates on encoding - we bypass that

3. **Every byte controllable**
   - `Element.raw()` gives full byte control for datasets
   - `raw()` from Scapy gives byte control for packets

4. **Works without network access**
   - Core dataset/file manipulation works without Scapy
   - Scapy features gracefully degrade if unavailable

## Protocol Reference

See [PROTOCOL.md](PROTOCOL.md) for detailed byte-level structure of:
- DICOM file format (Part 10)
- Data element encoding (Explicit/Implicit VR)
- All PDU types with field layouts
- DIMSE command structures
- State machine reference (Sta1-Sta13)

## License

GPL-2.0-only
