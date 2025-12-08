"""
Pytest configuration for DICOM integration tests.

Provides command-line options and fixtures for connecting to DICOM SCPs.
"""
# CRITICAL: Apply scapy IPv6 fix BEFORE any other imports
# This avoids KeyError: 'scope' in containerized environments
import scapy_ipv6_fix  # noqa: F401

import sys
import warnings
import pytest

warnings.filterwarnings("ignore")


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