"""
Pytest configuration for DICOM integration tests.

Provides command-line options and fixtures for connecting to DICOM SCPs.
"""
# =============================================================================
# SCAPY IPv6 FIX - Must be at the VERY TOP before any scapy imports
# Fixes KeyError: 'scope' in containerized environments without full IPv6
# =============================================================================
import warnings as _warnings
_warnings.filterwarnings("ignore")


class _FakeRoute6:
    """Fake Route6 class to avoid IPv6 routing errors in containers."""
    routes = []
    def resync(self): pass
    def route(self, *args, **kwargs): return ("::", "::", "::")


try:
    import scapy.config
    scapy.config.conf.route6 = _FakeRoute6()
except Exception:
    pass
# =============================================================================

import pytest


def pytest_addoption(parser):
    """Add custom command-line options for DICOM integration tests."""
    parser.addoption(
        "--ip",
        action="store",
        default=None,
        help="IP address of the DICOM SCP",
    )
    parser.addoption(
        "--port",
        action="store",
        type=int,
        default=None,
        help="Port of the DICOM SCP",
    )
    parser.addoption(
        "--ae-title",
        action="store",
        default=None,
        help="AE Title of the DICOM SCP",
    )
    parser.addoption(
        "--calling-ae",
        action="store",
        default="PYTEST_SCU",
        help="Our calling AE Title",
    )
    parser.addoption(
        "--timeout",
        action="store",
        type=int,
        default=30,
        help="Network timeout in seconds",
    )


@pytest.fixture
def scp_ip(request):
    """Fixture providing the SCP IP address."""
    return request.config.getoption("--ip")


@pytest.fixture
def scp_port(request):
    """Fixture providing the SCP port."""
    return request.config.getoption("--port")


@pytest.fixture
def scp_ae(request):
    """Fixture providing the SCP AE title."""
    return request.config.getoption("--ae-title")


@pytest.fixture
def my_ae(request):
    """Fixture providing our calling AE title."""
    return request.config.getoption("--calling-ae")


@pytest.fixture
def timeout(request):
    """Fixture providing the network timeout."""
    return request.config.getoption("--timeout")