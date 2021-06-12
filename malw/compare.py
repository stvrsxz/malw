from itertools import combinations
from pathlib import Path
from typing import List, Set

import pefile
import ssdeep
import typer

from malw.pe_info import PEInfo
from malw.utils import unpack_paths, get_fuzzy_hash


def fuzzy_compare(filepaths: Set[Path]):
    fuzzy_hashes = {filepath: get_fuzzy_hash(filepath) for filepath in filepaths}

    rv = {}
    filepath_pairs = combinations(fuzzy_hashes, 2)
    for first_filepath, second_filepath in filepath_pairs:
        rv.update({(first_filepath, second_filepath): ssdeep.compare(fuzzy_hashes[first_filepath],
                                                                     fuzzy_hashes[second_filepath])})
    rv = dict(sorted(rv.items(), key=lambda item: item[1], reverse=True))
    return rv


def print_fuzzy_results(fuzzy_compare_results: dict):
    typer.secho("Comparison of fuzzy hashes:", fg=typer.colors.RED)

    for index, ((first_filepath, second_filepath), similarity) in enumerate(fuzzy_compare_results.items()):
        first_filepath = typer.style(first_filepath.name, fg=typer.colors.CYAN)
        second_filepath = typer.style(second_filepath.name, fg=typer.colors.CYAN)
        similarity = typer.style(str(similarity) + "%", fg=typer.colors.BRIGHT_MAGENTA)
        typer.echo(f"similarity: {similarity}")
        typer.echo(f"\tfile: {first_filepath}")
        typer.echo(f"\tfile: {second_filepath}")


def get_imphash(filepath: Path):
    try:
        return PEInfo(filepath).imphash
    except pefile.PEFormatError as ex:
        return


def imphash_compare(filepaths: Set[Path]):
    rv = {}
    for filepath in filepaths:
        imphash = get_imphash(filepath)
        if imphash:
            rv.setdefault(imphash, set()).add(filepath)
    return rv


def print_imphash_results(imphash_results: dict):
    interesting_results = {imphash: filepaths for imphash, filepaths in imphash_results.items() if len(filepaths) > 1}

    if interesting_results:
        typer.secho("Files with the same imphash:", fg=typer.colors.RED)

        for imphash, filepaths in interesting_results.items():
            file_names = [filepath.name for filepath in filepaths]
            imphash = typer.style(imphash, fg=typer.colors.BRIGHT_MAGENTA)

            typer.echo(f"imphash: {imphash}")
            for filepath in file_names:
                typer.echo(f"\tfile: {filepath}")

    else:
        typer.secho("There are no files with the same imphash", fg=typer.colors.RED)


def get_section_hashes(filepath: Path):
    try:
        sections = PEInfo(filepath).sections
        return {section["name"]: section["md5"] for _, section in sections.items()}
    except pefile.PEFormatError as ex:
        return


def compare_sections(filepaths: Set[Path]):
    rv = {}
    for filepath in filepaths:
        section_hashes = get_section_hashes(filepath)
        if section_hashes:
            for name, md5 in section_hashes.items():
                rv.setdefault(name, {}).setdefault(md5, set()).add(filepath)

    return rv


def print_section_results(section_results: dict):
    interesting_sections = {}
    for section_name, md5_to_filepaths in section_results.items():
        for md5, filepaths in md5_to_filepaths.items():
            if len(filepaths) > 1:
                interesting_sections.setdefault(section_name, {}).setdefault(md5, set()).update(filepaths)

    if interesting_sections:
        typer.secho("Sections with the same md5 hashes:", fg=typer.colors.RED)
        for section_name, md5_to_filepaths in interesting_sections.items():
            name = typer.style(section_name, fg=typer.colors.CYAN)
            typer.echo(f"section: {name}")
            for md5, filepaths in md5_to_filepaths.items():
                md5 = typer.style(md5, fg=typer.colors.BLUE)
                typer.echo(f"\tmd5: {md5}")

                for filepath in filepaths:
                    filepath = typer.style(filepath.name, fg=typer.colors.MAGENTA)
                    typer.echo(f"\t\tfile: {filepath}")
    else:
        typer.secho("No duplicate section md5 hashes", fg=typer.colors.RED)


def compare_paths(paths: List[Path]):
    filepaths = unpack_paths(paths)

    fuzzy_compare_results = fuzzy_compare(filepaths)
    print_fuzzy_results(fuzzy_compare_results)

    typer.secho(f"\n---", fg=typer.colors.MAGENTA)

    imphash_results = imphash_compare(filepaths)
    print_imphash_results(imphash_results)

    typer.secho(f"\n---", fg=typer.colors.MAGENTA)

    section_results = compare_sections(filepaths)
    print_section_results(section_results)
