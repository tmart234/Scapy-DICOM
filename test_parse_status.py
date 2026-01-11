#!/usr/bin/env python3
"""
Standalone test to verify parse_dimse_status works correctly.
This doesn't require pytest and can be run directly.
"""

from scapy.all import *
load_contrib("dicom")

from dicom import (
    C_ECHO_RSP,
    parse_dimse_status,
)

def test_parse_status_unit():
    """Test that parse_dimse_status can extract status from a C-ECHO-RSP."""
    # Create a C-ECHO-RSP packet
    pkt = C_ECHO_RSP(message_id_responded=1, status=0x0000)
    raw = bytes(pkt)

    print(f"Created C-ECHO-RSP packet")
    print(f"Raw bytes length: {len(raw)}")
    print(f"First 64 bytes (hex): {raw[:64].hex()}")
    print()

    # Try to parse the status
    status = parse_dimse_status(raw)

    print(f"Parsed status: {status}")
    if status is None:
        print("ERROR: parse_dimse_status returned None!")
        return False
    elif status != 0x0000:
        print(f"ERROR: Expected status 0x0000, got 0x{status:04X}")
        return False
    else:
        print("SUCCESS: Status parsed correctly as 0x0000")
        return True

def test_parse_status_with_different_values():
    """Test parsing with different status values."""
    test_values = [0x0000, 0x0001, 0xFF00, 0xC000]

    for val in test_values:
        pkt = C_ECHO_RSP(message_id_responded=1, status=val)
        raw = bytes(pkt)
        status = parse_dimse_status(raw)

        if status == val:
            print(f"✓ Status 0x{val:04X} parsed correctly")
        else:
            print(f"✗ Status 0x{val:04X} failed - got {status}")
            return False

    return True

if __name__ == "__main__":
    print("=" * 60)
    print("Testing parse_dimse_status function")
    print("=" * 60)
    print()

    success = test_parse_status_unit()
    print()

    if success:
        print("=" * 60)
        print("Testing with different status values")
        print("=" * 60)
        success = test_parse_status_with_different_values()
        print()

    if success:
        print("All tests passed! ✓")
    else:
        print("Tests failed! ✗")

    exit(0 if success else 1)
