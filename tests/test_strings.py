# pylint: disable=no-member

from typer.testing import CliRunner
import pytest

from malw.malw import app  # pylint: disable=import-error
from malw.strings import StringType, IPv4String  # pylint: disable=import-error

runner = CliRunner()


def test_StringType_is_matching(pe):
    for StringTypeSubClass in StringType.subclasses:
        assert StringTypeSubClass.is_matching(StringTypeSubClass.example)


def test_command_strings_file(pe):
    result = runner.invoke(app, ["strings", str(pe)])
    assert result.exit_code == 0
    for StringTypeSubClass in StringType.subclasses:
        assert StringTypeSubClass.example in result.stdout
        assert StringTypeSubClass.hint in result.stdout

    assert pytest.unicode_example in result.stdout


def test_command_strings_options(pe):
    # Just see if it works
    result = runner.invoke(
        app, ["strings", str(pe), "--min-chars=3", "--radix=x", f"--max-bytes={pytest.max_bytes}", f"--offset={pytest.offset}"])
    assert result.exit_code == 0


def test_command_strings_options_with_the_whole_file(pe):
    # Similar to the test without options but
    # just see if it is working with options and without a need to change many pytest constants
    result = runner.invoke(
        app, ["strings", str(pe), "--min-chars=4", "--radix=x", f"--max-bytes=9999999999", f"--offset=0"])

    assert result.exit_code == 0
    assert pytest.ip_offset_on_file in result.stdout
    assert IPv4String.example in result.stdout
