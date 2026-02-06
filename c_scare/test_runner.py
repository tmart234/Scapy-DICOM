# SPDX-License-Identifier: GPL-2.0-only
"""
C-Scare Test Runner - CLI interface for running attack tests.

Usage:
    python -m c_scare.test_runner <command> [options]
    
Commands:
    cve_attacks       - Run CVE-specific attack reproductions
    fuzz_packets      - Test fuzzed DIMSE packets
    protocol_fuzzing  - Live protocol fuzzing against a target
    generate_corpus   - Generate fuzzing corpus files
    parser_attacks    - Run parser attack tests
    memory_attacks    - Run memory corruption tests
    all               - Run all tests

Examples:
    python -m c_scare.test_runner cve_attacks
    python -m c_scare.test_runner protocol_fuzzing --target 192.168.1.100:11112
    python -m c_scare.test_runner generate_corpus --output ./corpus --count 100
"""

import sys
import os
import argparse
from typing import List, Optional
import tempfile

# Import attack modules
try:
    from .attacks import (
        ParserAttacks, ProtocolAttacks, MemoryAttacks, LogicAttacks,
        StateMachineAttacks, CVEAttacks, ProtocolFuzzer, AttackResult,
        SCAPY_AVAILABLE
    )
except ImportError:
    from attacks import (
        ParserAttacks, ProtocolAttacks, MemoryAttacks, LogicAttacks,
        StateMachineAttacks, CVEAttacks, ProtocolFuzzer, AttackResult,
        SCAPY_AVAILABLE
    )

__all__ = ['main', 'run_command']


def print_banner():
    """Print C-Scare banner."""
    banner = r"""
   ____        ____                       
  / ___|      / ___|  ___ __ _ _ __ ___  
 | |   _____ \___ \ / __/ _` | '__/ _ \ 
 | |__|_____|___) | (_| (_| | | |  __/ 
  \____|     |____/ \___\__,_|_|  \___|
                                        
    DICOM Security Testing Framework
    """
    print(banner)


def print_result(result: AttackResult, verbose: bool = False):
    """Print an attack result."""
    status = "✓" if result.success is not False else "✗"
    cve_tag = f" [{result.cve}]" if result.cve else ""
    
    print(f"{status} {result.name}{cve_tag}")
    if verbose:
        print(f"  Category: {result.category}")
        print(f"  Description: {result.description}")
        print(f"  Expected: {result.expected_behavior}")
        if result.metadata:
            print(f"  Metadata: {result.metadata}")
        print(f"  Payload size: {len(result.payload)} bytes")
        if result.response:
            print(f"  Response size: {len(result.response)} bytes")
        print()


def run_cve_attacks(args) -> int:
    """Run CVE-specific attack reproductions."""
    print("\n=== CVE Attack Patterns ===\n")
    print("Testing CVE reproductions:")
    print("  - CVE-2023-32135 (Use-After-Free DCM parsing)")
    print("  - CVE-2024-24793 (Use-After-Free Meta Info)")
    print("  - CVE-2024-24794 (Use-After-Free Sequences)")
    print("  - CVE-2019-11687 (PEDICOM/ELFDICOM polyglot)")
    print()
    
    all_results = []
    
    # CVE-2023-32135
    print("CVE-2023-32135: Use-After-Free in DCM File Parsing")
    results = CVEAttacks.cve_2023_32135_sequence_uaf()
    for result in results:
        print_result(result, args.verbose)
        all_results.append(result)
    
    # CVE-2024-24793
    print("\nCVE-2024-24793: Use-After-Free in File Meta Information")
    results = CVEAttacks.cve_2024_24793_duplicate_meta_tags()
    for result in results:
        print_result(result, args.verbose)
        all_results.append(result)
    
    # CVE-2024-24794
    print("\nCVE-2024-24794: Use-After-Free in Sequence Parsing")
    results = CVEAttacks.cve_2024_24794_sequence_duplicates()
    for result in results:
        print_result(result, args.verbose)
        all_results.append(result)
    
    # CVE-2019-11687
    print("\nCVE-2019-11687: Executable Embedding (Polyglot Files)")
    results = CVEAttacks.cve_2019_11687_polyglot()
    for result in results:
        print_result(result, args.verbose)
        all_results.append(result)
    
    print(f"\nTotal CVE test cases: {len(all_results)}")
    
    # Save to output if requested
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in all_results:
            filename = f"{result.name}.dcm"
            filepath = os.path.join(args.output, filename)
            
            # Add DICOM file wrapper
            file_data = b'\x00' * 128 + b'DICM' + result.payload
            
            with open(filepath, 'wb') as f:
                f.write(file_data)
            
            if args.verbose:
                print(f"Saved: {filepath}")
    
    return 0


def run_fuzz_packets(args) -> int:
    """Test fuzzed DIMSE packets."""
    if not SCAPY_AVAILABLE:
        print("ERROR: Scapy not available. Install with: pip install scapy")
        return 1
    
    print("\n=== Fuzz Packet Tests ===\n")
    print("Testing: Fuzzed DIMSE packets with various malformations")
    print()
    
    # Try to import fuzz classes - they may not exist
    try:
        try:
            from .attacks import C_ECHO_RQ, C_STORE_RQ
            from scapy.packet import raw, fuzz
        except ImportError:
            from attacks import C_ECHO_RQ, C_STORE_RQ
            from scapy.packet import raw, fuzz
        
        # Try to import Fuzz variants if they exist
        try:
            from .attacks import C_ECHO_RQ_Fuzz, C_STORE_RQ_Fuzz
            has_fuzz_classes = True
        except ImportError:
            try:
                from attacks import C_ECHO_RQ_Fuzz, C_STORE_RQ_Fuzz
                has_fuzz_classes = True
            except ImportError:
                has_fuzz_classes = False
                print("Note: Specialized fuzz classes not available, using standard classes\n")
    except ImportError as e:
        print(f"ERROR: Could not import DIMSE classes: {e}")
        return 1
    
    count = args.count if hasattr(args, 'count') else 10
    results = []
    
    # Test 1: C_ECHO with various modifications
    print("1. C_ECHO_RQ with field variations")
    for i in range(min(5, count)):
        try:
            if has_fuzz_classes:
                # Use specialized fuzz class if available
                cmd = C_ECHO_RQ_Fuzz(
                    command_group_length=0xFFFF,
                    message_id=i+1
                )
            else:
                # Use standard class
                cmd = C_ECHO_RQ(message_id=i+1)
            
            payload = raw(cmd)
            result = AttackResult(
                name=f"c_echo_fuzz_{i}",
                category="fuzz",
                payload=payload,
                description=f"C-ECHO-RQ test case #{i}",
                expected_behavior="Parser should handle malformed fields",
            )
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ Failed to create C_ECHO_RQ #{i}: {e}")
    
    # Test 2: C_STORE with variations
    print("\n2. C_STORE_RQ with field variations")
    for i in range(min(5, count)):
        try:
            if has_fuzz_classes:
                cmd = C_STORE_RQ_Fuzz(
                    command_group_length=100,
                    affected_sop_class_uid=b'1.2.3.4.5',
                    affected_sop_instance_uid=f'1.2.3.4.5.6.{i}'.encode(),
                    message_id=i+1
                )
            else:
                # Use standard class with modifications
                cmd = C_STORE_RQ(
                    affected_sop_class_uid='1.2.840.10008.5.1.4.1.1.2',
                    affected_sop_instance_uid=f'1.2.3.4.5.6.{i}',
                    message_id=i+1
                )
            
            payload = raw(cmd)
            result = AttackResult(
                name=f"c_store_fuzz_{i}",
                category="fuzz",
                payload=payload,
                description=f"C-STORE-RQ test case #{i}",
                expected_behavior="Parser should handle variations",
            )
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ Failed to create C_STORE_RQ #{i}: {e}")
    
    # Test 3: Generic Scapy fuzz()
    print("\n3. Generic Scapy fuzz()")
    for i in range(min(5, count)):
        try:
            cmd = fuzz(C_ECHO_RQ())
            payload = raw(cmd)
            result = AttackResult(
                name=f"c_echo_scapy_fuzz_{i}",
                category="fuzz",
                payload=payload,
                description=f"C-ECHO-RQ with Scapy fuzz() #{i}",
                expected_behavior="Parser should handle malformed fields",
            )
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ Failed to create fuzzed C_ECHO_RQ #{i}: {e}")
    
    print(f"\nTotal fuzz test cases: {len(results)}")
    
    # Save if output dir specified
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in results:
            filename = f"{result.name}.bin"
            filepath = os.path.join(args.output, filename)
            with open(filepath, 'wb') as f:
                f.write(result.payload)
            if args.verbose:
                print(f"Saved: {filepath}")
    
    return 0


def run_protocol_fuzzing(args) -> int:
    """Run live protocol fuzzing against a target."""
    if not SCAPY_AVAILABLE:
        print("ERROR: Scapy not available. Install with: pip install scapy")
        return 1
    
    if not args.target:
        print("ERROR: --target required (format: host:port)")
        return 1
    
    print("\n=== Live Protocol Fuzzing ===\n")
    
    # Parse target
    try:
        host, port = args.target.rsplit(':', 1)
        port = int(port)
        target = (host, port)
    except ValueError:
        print(f"ERROR: Invalid target format: {args.target}")
        print("Expected format: host:port (e.g., 192.168.1.100:11112)")
        return 1
    
    print(f"Target: {host}:{port}")
    print(f"Running {args.count} fuzzed A-ASSOCIATE-RQ packets against server")
    print()
    
    try:
        fuzzer = ProtocolFuzzer(target, timeout=args.timeout)
        
        interesting_count = 0
        for i, result in enumerate(fuzzer.fuzz_association(count=args.count)):
            if result.success:
                interesting = result.metadata.get('interesting', False)
                status = "!" if interesting else "✓"
                print(f"{status} #{i+1}: {result.name}")
                
                if interesting:
                    interesting_count += 1
                    if args.verbose:
                        print(f"  Mutation: {result.metadata.get('mutation')}")
                        if result.response:
                            print(f"  Response: {len(result.response)} bytes")
                        else:
                            print(f"  Response: None (timeout or connection closed)")
            else:
                print(f"✗ #{i+1}: {result.description}")
        
        print(f"\nInteresting results: {interesting_count}/{args.count}")
        
    except Exception as e:
        print(f"ERROR: Fuzzing failed: {e}")
        return 1
    
    return 0


def run_generate_corpus(args) -> int:
    """Generate fuzzing corpus files."""
    print("\n=== Generating Fuzzing Corpus ===\n")
    
    output_dir = args.output or tempfile.mkdtemp(prefix='c_scare_corpus_')
    count = args.count
    
    print(f"Output directory: {output_dir}")
    print(f"Generating {count} test cases...")
    print()
    
    # Generate parser attacks
    print("Parser attacks...")
    results = ParserAttacks.generate_corpus(output_dir, count=count)
    
    print(f"Generated {len(results)} files:")
    for result in results:
        filepath = result.metadata.get('filepath', '')
        filesize = len(result.payload) if result.payload else 0
        print(f"  {os.path.basename(filepath):30s} {filesize:>8} bytes  {result.description}")
    
    print(f"\nCorpus saved to: {output_dir}")
    print(f"Total files: {len(results)}")
    
    return 0


def run_parser_attacks(args) -> int:
    """Run parser attack tests."""
    print("\n=== Parser Attacks ===\n")
    
    attacks = [
        ("Invalid VR", lambda: ParserAttacks.invalid_vr('XX')),
        ("Length overflow", lambda: ParserAttacks.length_overflow()),
        ("Length underflow", lambda: ParserAttacks.length_underflow()),
        ("Undefined length abuse", ParserAttacks.undefined_length_abuse),
        ("Sequence bomb (10)", lambda: ParserAttacks.sequence_bomb(10)),
        ("Tag out of order", ParserAttacks.tag_out_of_order),
        ("Duplicate tag", ParserAttacks.duplicate_tag),
        ("Null in string", ParserAttacks.null_in_string),
        ("Format string injection", ParserAttacks.format_string_injection),
        ("Path traversal", ParserAttacks.path_traversal_in_string),
        ("Unicode expansion", ParserAttacks.unicode_expansion),
    ]
    
    results = []
    for name, attack_fn in attacks:
        try:
            result = attack_fn()
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ {name}: {e}")
    
    print(f"\nTotal parser attack tests: {len(results)}")
    
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in results:
            filename = f"{result.name}.dcm"
            filepath = os.path.join(args.output, filename)
            
            # Add DICOM file wrapper
            file_data = b'\x00' * 128 + b'DICM' + result.payload
            
            with open(filepath, 'wb') as f:
                f.write(file_data)
    
    return 0


def run_memory_attacks(args) -> int:
    """Run memory corruption attack tests."""
    print("\n=== Memory Attacks ===\n")
    
    attacks = [
        ("Pixel dimension overflow", MemoryAttacks.pixel_dimension_overflow),
        ("Fragment count bomb", MemoryAttacks.fragment_count_bomb),
        ("Offset table bomb", MemoryAttacks.offset_table_bomb),
        ("Value multiplicity bomb", MemoryAttacks.value_multiplicity_bomb),
        ("Oversized string VR", lambda: MemoryAttacks.oversized_string_vr(0x10000)),
        ("Maximum length field", MemoryAttacks.maximum_length_field),
        ("OB VR overflow", MemoryAttacks.ob_vr_overflow),
        ("OW VR overflow", MemoryAttacks.ow_vr_overflow),
        ("LUT overflow", MemoryAttacks.lut_overflow),
        ("Encapsulated frame overflow", MemoryAttacks.encapsulated_frame_overflow),
    ]
    
    results = []
    for name, attack_fn in attacks:
        try:
            result = attack_fn()
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ {name}: {e}")
    
    print(f"\nTotal memory attack tests: {len(results)}")
    
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in results:
            filename = f"{result.name}.dcm"
            filepath = os.path.join(args.output, filename)
            
            # Add DICOM file wrapper if not already present
            if not result.payload.startswith(b'DICM'):
                file_data = b'\x00' * 128 + b'DICM' + result.payload
            else:
                file_data = result.payload
            
            with open(filepath, 'wb') as f:
                f.write(file_data)
    
    return 0


def run_all_tests(args) -> int:
    """Run all tests."""
    print_banner()
    
    # Run each test suite
    commands = [
        ('CVE Attacks', run_cve_attacks),
        ('Parser Attacks', run_parser_attacks),
        ('Memory Attacks', run_memory_attacks),
        ('Fuzz Packets', run_fuzz_packets),
    ]
    
    results = {}
    for name, func in commands:
        print(f"\n{'='*60}")
        print(f"Running: {name}")
        print('='*60)
        try:
            ret = func(args)
            results[name] = 'PASS' if ret == 0 else 'FAIL'
        except Exception as e:
            print(f"\nERROR in {name}: {e}")
            results[name] = 'ERROR'
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print('='*60)
    for name, status in results.items():
        symbol = '✓' if status == 'PASS' else '✗'
        print(f"{symbol} {name}: {status}")
    
    return 0


def run_command(command: str, args) -> int:
    """Run a specific command."""
    commands = {
        'cve_attacks': run_cve_attacks,
        'fuzz_packets': run_fuzz_packets,
        'protocol_fuzzing': run_protocol_fuzzing,
        'generate_corpus': run_generate_corpus,
        'parser_attacks': run_parser_attacks,
        'memory_attacks': run_memory_attacks,
        'all': run_all_tests,
    }
    
    if command not in commands:
        print(f"ERROR: Unknown command: {command}")
        print(f"Available commands: {', '.join(commands.keys())}")
        return 1
    
    return commands[command](args)


def main(argv: Optional[List[str]] = None):
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='C-Scare DICOM Security Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        'command',
        choices=['cve_attacks', 'fuzz_packets', 'protocol_fuzzing', 
                 'generate_corpus', 'parser_attacks', 'memory_attacks', 'all'],
        help='Command to run'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output directory for generated files'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=10,
        help='Number of test cases to generate (default: 10)'
    )
    
    parser.add_argument(
        '-t', '--target',
        help='Target for protocol fuzzing (format: host:port)'
    )
    
    parser.add_argument(
        '--timeout',
        type=float,
        default=5.0,
        help='Timeout for network operations (default: 5.0)'
    )
    
    args = parser.parse_args(argv)
    
    try:
        return run_command(args.command, args)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"\nERROR: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
