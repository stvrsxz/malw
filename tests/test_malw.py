# pylint: disable=no-member
import pytest
from typer.testing import CliRunner

from malw.malw import app, __version__  # pylint: disable=import-error

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


# Just some randomly selected things from the big overview output for
# ensuring that probably the overview is working correctly
def test_overview_file(pe):
    result = runner.invoke(app, ["overview", str(pe)])
    assert result.exit_code == 0
    assert "md5" in result.stdout
    assert "sha1" in result.stdout
    assert "sha256" in result.stdout
    assert pytest.pe_filetype in result.stdout
    assert pytest.pe_name in result.stdout
    assert "1.1.1.1" in result.stdout
    assert pytest.fuzzy_hash in result.stdout
    assert pytest.imphash in result.stdout
    assert pytest.compilation_date in result.stdout
    assert pytest.subsystem in result.stdout
    assert pytest.dll.decode("utf8") in result.stdout
    assert pytest.import_.decode("utf8") in result.stdout
    assert pytest.built_with in result.stdout
    assert "virtual_size" in result.stdout
    assert ".text" in result.stdout


# Just some randomly selected things from the big overview output for
# ensuring that probably the overview is working correctly
def test_overview_directory(pe):
    result = runner.invoke(app, ["overview", str(pe.parent)])
    assert result.exit_code == 0
    assert "md5" in result.stdout
    assert "sha1" in result.stdout
    assert "sha256" in result.stdout
    assert pytest.pe_filetype in result.stdout
    assert pytest.pe_name in result.stdout
    assert "1.1.1.1" in result.stdout
    assert pytest.fuzzy_hash in result.stdout
    assert pytest.imphash in result.stdout
    assert pytest.compilation_date in result.stdout
    assert pytest.subsystem in result.stdout
    assert pytest.dll.decode("utf8") in result.stdout
    assert pytest.import_.decode("utf8") in result.stdout
    assert pytest.built_with in result.stdout
    assert "virtual_size" in result.stdout
    assert ".text" in result.stdout
    assert pytest.pe_packed_name in result.stdout
    assert pytest.fuzzy_hash_packed in result.stdout
    assert pytest.import_packed.decode("utf8") in result.stdout
    assert pytest.imphash_packed in result.stdout
    assert pytest.dll_packed.decode("utf8") in result.stdout
    assert pytest.compilation_date_packed in result.stdout
    assert "UPX1" in result.stdout
