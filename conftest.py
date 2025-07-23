import pytest

def pytest_addoption(parser):
    """This function adds custom command-line options to pytest."""
    parser.addoption(
        "--ip", action="store", default=None, help="IP address of the DICOM SCP"
    )
    parser.addoption(
        "--port", action="store", type=int, default=None, help="Port of the DICOM SCP"
    )
    parser.addoption(
        "--ae-title", action="store", default=None, help="AE Title of the DICOM SCP"
    )
    parser.addoption(
        "--calling-ae", action="store", default="PYTEST_SCU", help="Our calling AE Title"
    )
    parser.addoption(
        "--timeout", action="store", type=int, default=30, help="Network timeout in seconds"
    )

@pytest.fixture
def scp_ip(request):
    """Fixture to get the --ip value from the command line."""
    return request.config.getoption("--ip")

@pytest.axfixture
def scp_port(request):
    """Fixture to get the --port value from the command line."""
    return request.config.getoption("--port")

@pytest.fixture
def scp_ae(request):
    """Fixture to get the --ae-title value from the command line."""
    return request.config.getoption("--ae-title")

@pytest.fixture
def my_ae(request):
    """Fixture to get the --calling-ae value from the command line."""
    return request.config.getoption("--calling-ae")

@pytest.fixture
def timeout(request):
    """Fixture to get the --timeout value from the command line."""
    return request.config.getoption("--timeout")