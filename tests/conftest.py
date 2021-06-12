import os
from pathlib import Path

import pytest

from malw.pe_info import PEInfo  # pylint: disable=import-error

FILE_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    'files',
)


@pytest.fixture(scope="session")
def file_dir():
    return FILE_DIR


@pytest.fixture(scope="session")
def temp_file(tmp_path_factory):
    # An ultra simple temp file
    file_ = tmp_path_factory.mktemp("data") / pytest.temp_file_name
    file_.write_bytes(b"A" * pytest.temp_file_size)
    return file_


@pytest.fixture(scope="session")
def pe():
    return Path(FILE_DIR + "/pe.exe")


@pytest.fixture(scope="session")
def pe_packed():
    return Path(FILE_DIR + "/pe_packed.exe")


@pytest.fixture(scope="session")
def pe_similar():
    return Path(FILE_DIR + "/pe_similar.exe")


@pytest.fixture(scope="session")
def pe_info_obj(pe):
    return PEInfo(pe)


@pytest.fixture(scope="session")
def pe_info_obj_packed(pe_packed):
    return PEInfo(pe_packed)


@pytest.fixture(scope="session")
def pe_info_obj_similar():
    return Path(FILE_DIR + "/pe_similar.exe")


@pytest.fixture(scope="session")
def compare_filepaths(pe, pe_similar):
    return {pe, pe_similar}



# TODO: Refactor this. And make it more dynamic when possible
def pytest_configure():
    # These values are subject to frequent changes

    # For temp_file fixture:
    pytest.temp_file_md5 = "0f53217fc7c8e7f89e8a8558e64a7083"
    pytest.temp_file_sha1 = "bf6db7112b56812702e99d48a7b1dab62d09b3f6"
    pytest.temp_file_sha256 = "85757d9ef5868bb53472a6be8d81d1e3c398546b69b107141ad336053c40cb54"
    pytest.temp_file_name = "simple.exe"
    pytest.temp_file_filetype = "ASCII text, with very long lines, with no line terminators"
    pytest.temp_file_size = 10000
    pytest.temp_file_size_human_readable = "9.77 KiB"

    # For pe fixture:
    pytest.pe_name = "pe.exe"

    # Possible need to change when creating pe.exe:
    pytest.ip_offset_on_file = "0x9c00"
    pytest.offset = "39900"
    pytest.max_bytes = "250"

    pytest.unicode_example = "test@testutf16.com"
    pytest.pe_filetype = "PE32+ executable (console) x86-64, for MS Windows"

    # Need to change when creating pe.exe:
    pytest.fuzzy_hash = "3072:qWZi4kt2TFcRPItMsEivXv04QyJ7Uwfd4ZmM0mrcqSp5gnEtMNZ/I4MiJ:lZhNT1hv0DmhLKMiJ"
    # Need to change when creating pe.exe:
    pytest.imphash = "62c852ae981c077c1abe7a85b686f6f5"
    # Need to change when creating pe.exe:
    pytest.compilation_date = "2021-05-23 15:02:40"

    pytest.subsystem = "IMAGE_SUBSYSTEM_WINDOWS_CUI"
    pytest.dll = b"KERNEL32.dll"
    pytest.import_ = b"DeleteCriticalSection"
    pytest.built_with = "Microsoft Visual C++ 8.0 (DLL)"
    pytest.section_keys = ["name", "raw_size",
                           "virtual_size", "entropy", "md5", "suspicious"]
    # more tests?
    pytest.sections_values = {"name": ".text", "suspicious": False}

    # For pe_packed fixture:
    pytest.pe_packed_name = "pe_packed.exe"

    # Need to change when creating pe_packed.exe:
    pytest.fuzzy_hash_packed = "3072:hNinJutyrXYb+AgTzrX6UNmgaqqGLpHDrD/I4MiJ:bcJuUoqrX6UbaQZ5MiJ"
    # Need to change when creating pe_packed.exe:
    pytest.imphash_packed = "9aebf3da4677af9275c461261e5abde3"
    # Need to change when creating pe_packed.exe:
    pytest.compilation_date_packed = "2021-05-23 15:02:40"

    pytest.dll_packed = b"KERNEL32.DLL"  # Why this is upped DLL?
    pytest.import_packed = b"LoadLibraryA"
    pytest.built_with_packed = ""  # fix to show upx?
    # more tests?
    pytest.sections_packed_values = {"name": "UPX1", "suspicious": True}

    # compare constants
    pytest.similarity = 54  # Need to change when changing pe.exe or pe_similar.exe
