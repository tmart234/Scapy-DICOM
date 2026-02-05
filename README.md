# C-Scare

A DICOM Security Testing Framework

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              C-Scare Framework                                      │
├──────────────────────────────────┬──────────────────────────────────────────────────┤
│         DICOM STACK              │              C-SCARE TOOLS                       │
├──────────────────────────────────┼──────────────────────────────────────────────────┤
│                                  │                                                  │
│  Application Layer               │  attacks.py (LogicAttacks)                       │
│    IOD constraints               │    SOP class mismatch, transfer syntax mismatch  │
│    SOP Class semantics           │    SSRF via URI, file:// injection               │
│                                  │                                                  │
├──────────────────────────────────┼──────────────────────────────────────────────────┤
│                                  │                                                  │
│  Dataset Layer                   │  element.py    ─ Element.raw() byte control      │
│    Elements, Sequences, Values   │  corruptor.py  ─ pydicom surgical corruption     │
│    Part 10 Files, Pixel Data     │  file.py       ─ Part 10 file handling           │
│                                  │  pixel.py      ─ Encapsulated/fragment attacks   │
│                                  │  attacks.py (ParserAttacks, MemoryAttacks)       │
│                                  │    VR fuzzing, length overflow, sequence bombs   │
│                                  │    Buffer overflow, fragment bombs, LUT attacks  │
│                                  │                                                  │
├──────────────────────────────────┼──────────────────────────────────────────────────┤
│                                  │                                                  │
│  DIMSE Layer                     │  scapy_dicom.py (DIMSE packets)                  │
│    C-STORE, C-FIND, C-ECHO       │    C_ECHO_RQ, C_STORE_RQ, C_FIND_RQ, C_MOVE_RQ   │
│    Command + Data                │    C_STORE_RQ_Fuzz ─ explicit group_length       │
│                                  │    fuzz() for automatic field mutation           │
│                                  │                                                  │
├──────────────────────────────────┼──────────────────────────────────────────────────┤
│                                  │                                                  │
│  PDU Layer                       │  scapy_dicom.py (PDU packets)                    │
│    A-ASSOCIATE-RQ/AC/RJ          │    A_ASSOCIATE_RQ, A_ASSOCIATE_AC, A_ABORT       │
│    P-DATA-TF, A-RELEASE          │    P_DATA_TF, A_RELEASE_RQ/RP                    │
│    A-ABORT                       │  attacks.py (ProtocolAttacks, StateMachineAttacks)│
│                                  │    PDU malformation, AE title fuzzing            │
│                                  │    State violations (Sta1-Sta13)                 │
│                                  │                                                  │
├──────────────────────────────────┼──────────────────────────────────────────────────┤
│                                  │                                                  │
│  Transport Layer                 │  scapy_dicom.py (DICOMSocket)                    │
│    TCP segments                  │    Client with full Scapy integration            │
│                                  │  server.py (RawSCP)                              │
│                                  │    Rogue server for fuzzing DICOM clients        │
│                                  │    State machine hooks, response injection       │
│                                  │                                                  │
└──────────────────────────────────┴──────────────────────────────────────────────────┘
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
| `corruptor.py` | Pydicom bridge for surgical corruption |
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

## Protocol Reference

See [PROTOCOL.md](PROTOCOL.md) for detailed byte-level structure

## License

GPL-2.0-only
