# pylint: disable=no-member

from typer.testing import CliRunner
import pytest

from malw.compare import get_imphash, imphash_compare, fuzzy_compare, get_section_hashes, compare_sections
from malw.malw import app  # pylint: disable=import-error


#  =================== Compare: (Let's say) Unit tests =====================


def test_fuzzy_compare(pe, pe_similar, compare_filepaths):
    # Make it better
    assert fuzzy_compare(compare_filepaths) in (
        {(pe, pe_similar): pytest.similarity},
        {(pe_similar, pe): pytest.similarity}
    )


def test_get_imphash(pe_similar):
    assert get_imphash(pe_similar) == pytest.imphash


def test_imphash_compare(compare_filepaths):
    assert imphash_compare(compare_filepaths)[pytest.imphash] == compare_filepaths


def test_get_section_hashes(pe):
    # Make it better
    assert pytest.sections_values["name"] in get_section_hashes(pe)


def test_compare_sections(compare_filepaths):
    # Make it better
    assert pytest.sections_values["name"] in compare_sections(compare_filepaths)
    assert set.union(*compare_sections(compare_filepaths)[pytest.sections_values["name"]].values()) == compare_filepaths


# #  =================== Compare: Integration tests =====================

runner = CliRunner()


# Not the best test but good enough for seeing if at least running ok
def test_command_compare_all(pe, pe_similar):
    result = runner.invoke(app, ["compare", str(pe), str(pe_similar)])
    assert result.exit_code == 0

    assert pe.name in result.stdout
    assert pe_similar.name in result.stdout

    assert str(pytest.similarity) in result.stdout
    assert "similarity" in result.stdout

    assert "imphash" in result.stdout
    assert pytest.imphash in result.stdout

    assert "section" in result.stdout
    assert ".idata" in result.stdout
    assert "md5" in result.stdout
