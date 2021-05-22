# pylint: disable=no-member

from typer.testing import CliRunner
import pytest

from malw.malw import app  # pylint: disable=import-error
from malw.hashes import MD5Checksum, SHA1Checksum, SHA256Checksum  # pylint: disable=import-error

#  =================== Hashes: (Let's say) Unit tests =====================


def test_md5_checksum(temp_file):
    assert MD5Checksum(temp_file).value == pytest.temp_file_md5


def test_sha1_checksum(temp_file):
    assert SHA1Checksum(temp_file).value == pytest.temp_file_sha1


def test_sha256_checksum(temp_file):
    assert SHA256Checksum(temp_file).value == pytest.temp_file_sha256


#  =================== Hashes: Integration tests =====================

runner = CliRunner()


def test_command_hashes_all_file(temp_file):
    result = runner.invoke(app, ["hashes", str(temp_file)])
    assert result.exit_code == 0
    assert "md5" in result.stdout
    assert "sha1" in result.stdout
    assert "sha256" in result.stdout
    assert pytest.temp_file_md5 in result.stdout
    assert pytest.temp_file_sha1 in result.stdout
    assert pytest.temp_file_sha256 in result.stdout
    assert pytest.temp_file_name in result.stdout


def test_command_hashes_all_directory(temp_file):
    result = runner.invoke(app, ["hashes", str(temp_file.parent)])
    assert result.exit_code == 0
    assert "md5" in result.stdout
    assert "sha1" in result.stdout
    assert "sha256" in result.stdout
    assert pytest.temp_file_md5 in result.stdout
    assert pytest.temp_file_sha1 in result.stdout
    assert pytest.temp_file_sha256 in result.stdout
    assert pytest.temp_file_name in result.stdout


def test_command_hashes_md5_file(temp_file):
    result = runner.invoke(
        app, ["hashes", str(temp_file), "--hash-function=md5"])
    assert result.exit_code == 0
    assert "md5" in result.stdout
    assert pytest.temp_file_md5 in result.stdout
    assert pytest.temp_file_name in result.stdout


def test_command_hashes_sha1_file(temp_file):
    result = runner.invoke(
        app, ["hashes", str(temp_file), "--hash-function=sha1"])
    assert result.exit_code == 0
    assert "sha1" in result.stdout
    assert pytest.temp_file_sha1 in result.stdout
    assert pytest.temp_file_name in result.stdout


def test_command_hashes_sha256_file(temp_file):
    result = runner.invoke(
        app, ["hashes", str(temp_file), "--hash-function=sha256"])
    assert result.exit_code == 0
    assert "sha256" in result.stdout
    assert pytest.temp_file_sha256 in result.stdout
    assert pytest.temp_file_name in result.stdout
