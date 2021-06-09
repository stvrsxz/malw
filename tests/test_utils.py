# pylint: disable=no-member
import pytest

from malw.strings import Radix  # pylint: disable=import-error
import malw.utils as utils  # pylint: disable=import-error


def test_get_filepaths_file(temp_file):
    assert utils.get_filepaths(temp_file) == [temp_file]


def test_get_filepaths_directory(temp_file):
    assert utils.get_filepaths(temp_file.parent) == [temp_file]


def test_get_human_readable_size(temp_file):
    assert utils.get_human_readable_size(
        temp_file.stat().st_size) == pytest.temp_file_size_human_readable


@pytest.mark.parametrize("radix, value, expected",
                         [
                             (Radix.D, 10, "10"),
                             (Radix.O, 10, '0o12'),
                             (Radix.X, 10, '0xa')
                         ]
                         )
def test_convert_radix(radix, value, expected):
    assert utils.convert_radix(radix, value) == expected


def test_accept_file_size(temp_file):
    assert utils.accept_file_size(temp_file) is True


def test_unpack_paths(temp_file):
    assert utils.get_filepaths(temp_file.parent) == [temp_file]


def test_get_fuzzy_hash(pe):
    assert utils.get_fuzzy_hash(pe) == pytest.fuzzy_hash


def test_get_path_from_parent(pe):
    assert utils.get_path_from_parent(pe) == "files/pe.exe"
