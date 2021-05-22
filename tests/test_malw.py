# pylint: disable=no-member
import pytest
from typer.testing import CliRunner

from malw.malw import app, __version__  # pylint: disable=import-error

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_overview(pe):
    result = runner.invoke(app, ["overview", str(pe)])
    assert result.exit_code == 0
    assert "md5" in result.stdout
    assert "sha1" in result.stdout
    assert "sha256" in result.stdout
    assert pytest.pe_filetype in result.stdout
    assert pytest.pe_name in result.stdout
    assert "1.1.1.1" in result.stdout
    # assert pytest.is_not_packed_message in result.stdout


def test_overview_invalid_is_directory(pe):
    result = runner.invoke(app, ["overview", str(pe.parent)])
    assert result.exit_code == 2
    assert "is a directory" in result.stdout
