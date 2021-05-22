# pylint: disable=no-member

from typer.testing import CliRunner
import pytest

from malw.malw import app  # pylint: disable=import-error
from malw.filetypes import get_filetypes  # pylint: disable=import-error

#  =================== Filetypes: (Let's say) Unit tests =====================


def test_get_filetypes(temp_file):
    FileType = get_filetypes(temp_file)[0]
    assert FileType.filename == pytest.temp_file_name
    assert FileType.filepath == temp_file
    assert FileType.value == pytest.temp_file_filetype


#  =================== Filetypes: Integration tests =====================

runner = CliRunner()


def test_command_filetypes_file(temp_file):
    result = runner.invoke(app, ["filetypes", str(temp_file)])
    assert result.exit_code == 0
    assert pytest.temp_file_name in result.stdout
    assert pytest.temp_file_filetype in result.stdout


def test_command_filetypes_directory(temp_file):
    result = runner.invoke(app, ["filetypes", str(temp_file.parent)])
    assert result.exit_code == 0
    assert pytest.temp_file_name in result.stdout
    assert pytest.temp_file_filetype in result.stdout
