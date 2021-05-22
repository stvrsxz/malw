# pylint: disable=no-member

from typer.testing import CliRunner
import pytest

from malw.malw import app  # pylint: disable=import-error
from malw.pe_info import get_pe_info, PEInfo  # pylint: disable=import-error

# Can you refactor something more in this file?


@pytest.mark.parametrize('pe_type, expected', [
    ('pe_info_obj', pytest.fuzzy_hash),
    ('pe_info_obj_packed', pytest.fuzzy_hash_packed)])
def test_fuzzy_hash(pe_type, expected, request):
    pe_info = request.getfixturevalue(pe_type)
    assert pe_info.fuzzy_hash == expected


@pytest.mark.parametrize('pe_type, expected', [
    ('pe_info_obj', pytest.imphash),
    ('pe_info_obj_packed', pytest.imphash_packed)])
def test_imphash(pe_type, expected, request):
    pe_info = request.getfixturevalue(pe_type)
    assert pe_info.imphash == expected


@pytest.mark.parametrize('pe_type, expected', [
    ('pe_info_obj', pytest.compilation_date),
    ('pe_info_obj_packed', pytest.compilation_date_packed)])
def test_compilation_date(pe_type, expected, request):
    pe_info = request.getfixturevalue(pe_type)
    assert pe_info.compilation_date == expected


@pytest.mark.parametrize('pe_type, expected', [
    ('pe_info_obj', pytest.subsystem),
    ('pe_info_obj_packed', pytest.subsystem)])
def test_subsystem(pe_type, expected, request):
    pe_info = request.getfixturevalue(pe_type)
    assert pe_info.subsystem == expected


@pytest.mark.parametrize('pe_type, expected_import, expected_dll', [
    ('pe_info_obj', pytest.import_, pytest.dll),
    ('pe_info_obj_packed', pytest.import_packed, pytest.dll_packed)])
def test_imports(pe_type, expected_import, expected_dll, request):
    pe_info = request.getfixturevalue(pe_type)
    assert expected_dll in pe_info.imports
    assert expected_import in pe_info.imports[expected_dll]


@pytest.mark.parametrize('pe_type, expected', [
    ('pe_info_obj', pytest.built_with),
    ('pe_info_obj_packed', pytest.built_with_packed)])
def test_built_with(pe_type, expected, request):
    pe_info = request.getfixturevalue(pe_type)
    assert pe_info.built_with == expected


@pytest.mark.parametrize('pe_type, expected', [
    ('pe_info_obj', pytest.sections_values),
    ('pe_info_obj_packed', pytest.sections_packed_values)])
def test_section(pe_type, expected, request):
    # better tests?
    pe_info = request.getfixturevalue(pe_type)
    for k, v in pe_info.sections.items():
        for section_key in pytest.section_keys:
            assert section_key in v
            if expected["name"] == v["name"]:
                assert expected["suspicious"] == v["suspicious"]


runner = CliRunner()


def test_command_pe_file(pe):
    result = runner.invoke(app, ["pe", str(pe)])
    assert result.exit_code == 0
    assert pytest.fuzzy_hash in result.stdout
    assert pytest.imphash in result.stdout
    assert pytest.compilation_date in result.stdout
    assert pytest.subsystem in result.stdout
    assert pytest.dll.decode("utf8") in result.stdout
    assert pytest.import_.decode("utf8") in result.stdout
    assert pytest.built_with in result.stdout
    for section_key in pytest.section_keys:
        assert section_key in result.stdout
    for k, v in pytest.sections_values.items():
        assert str(k) in result.stdout
        assert str(v) in result.stdout


def test_command_pe_directory(pe):
    result = runner.invoke(app, ["pe", str(pe.parent)])
    assert result.exit_code == 0
    assert pytest.fuzzy_hash in result.stdout
    assert pytest.imphash in result.stdout
    assert pytest.compilation_date in result.stdout
    assert pytest.subsystem in result.stdout
    assert pytest.dll.decode("utf8") in result.stdout
    assert pytest.import_.decode("utf8") in result.stdout
    assert pytest.built_with in result.stdout
    for section_key in pytest.section_keys:
        assert section_key in result.stdout
    for k, v in pytest.sections_values.items():
        assert str(k) in result.stdout
        assert str(v) in result.stdout


def test_command_pe_packed_file(pe_packed):
    result = runner.invoke(app, ["pe", str(pe_packed)])
    assert result.exit_code == 0
    assert pytest.fuzzy_hash_packed in result.stdout
    assert pytest.imphash_packed in result.stdout
    assert pytest.compilation_date_packed in result.stdout
    assert pytest.subsystem in result.stdout
    assert pytest.dll_packed.decode("utf8") in result.stdout
    assert pytest.import_packed.decode("utf8") in result.stdout
    assert pytest.built_with_packed in result.stdout
    for section_key in pytest.section_keys:
        assert section_key in result.stdout
    for k, v in pytest.sections_packed_values.items():
        assert str(k) in result.stdout
        assert str(v) in result.stdout


def test_command_pe_packed_directory(pe_packed):
    result = runner.invoke(app, ["pe", str(pe_packed.parent)])
    assert result.exit_code == 0
    assert pytest.fuzzy_hash_packed in result.stdout
    assert pytest.imphash_packed in result.stdout
    assert pytest.compilation_date_packed in result.stdout
    assert pytest.subsystem in result.stdout
    assert pytest.dll_packed.decode("utf8") in result.stdout
    assert pytest.import_packed.decode("utf8") in result.stdout
    assert pytest.built_with_packed in result.stdout
    for section_key in pytest.section_keys:
        assert section_key in result.stdout
    for k, v in pytest.sections_packed_values.items():
        assert str(k) in result.stdout
        assert str(v) in result.stdout
