# SPDX-License-Identifier: GPL-2.0-only
"""
Scapy DICOM layer integration.

This module provides helpers to install/use the custom DICOM Scapy layer.

The scapy_dicom.py file can be used in two ways:

1. Copy to scapy/contrib/ directory for global use
2. Load dynamically at runtime

Example:
    from dicom_hacker.scapy_layer import install_scapy_layer, DICOMSocket
    
    # Install layer (one-time)
    install_scapy_layer()
    
    # Or just use directly
    from dicom_hacker.scapy_layer import (
        DICOMSocket, A_ASSOCIATE_RQ, A_ASSOCIATE_AC,
        P_DATA_TF, C_STORE_RQ, C_ECHO_RQ,
    )
    
    sock = DICOMSocket(('192.168.1.100', 11112))
    sock.connect()
    sock.associate({'1.2.840.10008.1.1': ['1.2.840.10008.1.2']})
    sock.c_echo()
"""

import os
import shutil
import sys
from typing import Optional

__all__ = [
    'install_scapy_layer',
    'get_scapy_layer_path',
    'load_scapy_layer',
    # Re-exports from scapy layer (when available)
    'DICOMSocket',
    'DICOM',
    'A_ASSOCIATE_RQ', 'A_ASSOCIATE_AC', 'A_ASSOCIATE_RJ',
    'P_DATA_TF', 'A_RELEASE_RQ', 'A_RELEASE_RP', 'A_ABORT',
    'C_ECHO_RQ', 'C_ECHO_RSP',
    'C_STORE_RQ', 'C_STORE_RSP',
    'C_FIND_RQ', 'C_FIND_RSP',
    'C_MOVE_RQ', 'C_MOVE_RSP',
    'C_GET_RQ', 'C_GET_RSP',
]


def get_scapy_layer_path() -> str:
    """Get path to the bundled scapy_dicom.py file."""
    # Check in package directory
    pkg_dir = os.path.dirname(__file__)
    bundled = os.path.join(pkg_dir, 'scapy_dicom.py')
    if os.path.exists(bundled):
        return bundled
    
    # Check in outputs (development)
    dev_path = '/mnt/user-data/outputs/scapy_dicom.py'
    if os.path.exists(dev_path):
        return dev_path
    
    raise FileNotFoundError(
        "scapy_dicom.py not found. Please ensure it's bundled with the package."
    )


def install_scapy_layer(force: bool = False) -> str:
    """
    Install the DICOM Scapy layer to scapy/contrib/.
    
    Args:
        force: Overwrite existing installation
    
    Returns:
        Path to installed file
    """
    try:
        import scapy
    except ImportError:
        raise ImportError("Scapy is not installed. pip install scapy")
    
    source = get_scapy_layer_path()
    
    # Find scapy contrib directory
    scapy_dir = os.path.dirname(scapy.__file__)
    contrib_dir = os.path.join(scapy_dir, 'contrib')
    
    if not os.path.exists(contrib_dir):
        os.makedirs(contrib_dir, exist_ok=True)
    
    dest = os.path.join(contrib_dir, 'dicom.py')
    
    if os.path.exists(dest) and not force:
        print(f"Scapy DICOM layer already installed at {dest}")
        print("Use force=True to overwrite")
        return dest
    
    shutil.copy(source, dest)
    print(f"Installed DICOM Scapy layer to {dest}")
    return dest


def load_scapy_layer():
    """
    Load the DICOM Scapy layer dynamically.
    
    Returns:
        The loaded module
    """
    import importlib.util
    
    path = get_scapy_layer_path()
    
    spec = importlib.util.spec_from_file_location("scapy_dicom", path)
    module = importlib.util.module_from_spec(spec)
    
    # Make sure scapy is configured
    try:
        import scapy.config
        scapy.config.conf.ipv6_enabled = False
    except Exception:
        pass
    
    spec.loader.exec_module(module)
    
    # Add to sys.modules for imports
    sys.modules['scapy_dicom'] = module
    sys.modules['scapy.contrib.dicom'] = module
    
    return module


# Try to load scapy layer and provide exports
_scapy_layer = None

def _ensure_scapy_layer():
    global _scapy_layer
    if _scapy_layer is None:
        try:
            _scapy_layer = load_scapy_layer()
        except Exception as e:
            raise ImportError(
                f"Could not load Scapy DICOM layer: {e}\n"
                "Make sure scapy is installed: pip install scapy"
            )
    return _scapy_layer


# Lazy attribute access for scapy layer classes
class _LazyLoader:
    """Lazy loader for scapy layer classes."""
    
    def __init__(self, name: str):
        self._name = name
        self._obj = None
    
    def __call__(self, *args, **kwargs):
        if self._obj is None:
            module = _ensure_scapy_layer()
            self._obj = getattr(module, self._name)
        return self._obj(*args, **kwargs)
    
    def __repr__(self):
        return f"<LazyLoader for {self._name}>"


# Create lazy loaders for commonly used classes
DICOMSocket = _LazyLoader('DICOMSocket')
DICOM = _LazyLoader('DICOM')
A_ASSOCIATE_RQ = _LazyLoader('A_ASSOCIATE_RQ')
A_ASSOCIATE_AC = _LazyLoader('A_ASSOCIATE_AC')
A_ASSOCIATE_RJ = _LazyLoader('A_ASSOCIATE_RJ')
P_DATA_TF = _LazyLoader('P_DATA_TF')
A_RELEASE_RQ = _LazyLoader('A_RELEASE_RQ')
A_RELEASE_RP = _LazyLoader('A_RELEASE_RP')
A_ABORT = _LazyLoader('A_ABORT')
C_ECHO_RQ = _LazyLoader('C_ECHO_RQ')
C_ECHO_RSP = _LazyLoader('C_ECHO_RSP')
C_STORE_RQ = _LazyLoader('C_STORE_RQ')
C_STORE_RSP = _LazyLoader('C_STORE_RSP')
C_FIND_RQ = _LazyLoader('C_FIND_RQ')
C_FIND_RSP = _LazyLoader('C_FIND_RSP')
C_MOVE_RQ = _LazyLoader('C_MOVE_RQ')
C_MOVE_RSP = _LazyLoader('C_MOVE_RSP')
C_GET_RQ = _LazyLoader('C_GET_RQ')
C_GET_RSP = _LazyLoader('C_GET_RSP')
