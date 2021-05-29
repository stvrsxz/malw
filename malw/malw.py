from pathlib import Path
from typing import Optional

import typer

from .filetypes import get_filetypes
from .hashes import HashFunction, get_checksum_groups
from .strings import get_strings, Radix
from .pe_info import get_pe_info
from .utils import get_human_readable_size, get_filepaths

__version__ = "0.1.0"

app = typer.Typer()


@app.command()
def hashes(path: Path = typer.Argument(...,
                                       exists=True,
                                       file_okay=True,
                                       dir_okay=True),
           hash_function: HashFunction = HashFunction.ALL):
    """
    Get the checksums for files in the path.
    path can be a directory or a single file.
    hash-function can be 'md5', 'sha1', 'sha256' or 'all' (default) to get all checksums
    for the provided hash functions
    """
    # The group here refers to a group of checksums for a file
    checksum_groups = get_checksum_groups(hash_function, path)

    for index, checksum_group in enumerate(checksum_groups):
        if index:
            typer.secho(f"---", fg=typer.colors.MAGENTA)

        for checksum in checksum_group:
            checksum.print_info_for_checksum()


@app.command()
def filetypes(path: Path = typer.Argument(...,
                                          exists=True,
                                          file_okay=True,
                                          dir_okay=True)):
    """
    Get the filetype for files in the path.
    path can be a directory or a single file.
    """
    filetypes_ = get_filetypes(path)

    for index, FileType in enumerate(filetypes_):
        if index:
            typer.secho(f"---", fg=typer.colors.MAGENTA)

        FileType.print_info_for_filetype()


# TODO: option to search to certain sections .data? and maybe call pe data strings inside get strings?
@app.command()
def strings(path: Path = typer.Argument(...,
                                        exists=True,
                                        file_okay=True,
                                        dir_okay=False),
            min_chars: int = 4,
            max_bytes: Optional[int] = None,
            offset: Optional[int] = None,
            radix: Optional[Radix] = None):
    """
    Get the strings objects for files in the path.
    path can be a single file (Simply for not having extremely long output)

    Tries to emulate some common "strings" functionalities.

    min_chars: Min string length in characters. (ASCII or Unicode)
    max_bytes: Max bytes of file to scan
    offset: File offset at which to start scanning.
    radix: The offset the string appears in the file. x for hex (default), o for octal, d for decimal. If no 
    radix is given then it will not be shown in the output
    """
    strings_ = get_strings(path, min_chars, max_bytes, offset, radix)

    for string in strings_:
        string.print_info_for_string(
            show_offset_in_file=True if radix else False)


@app.command()
def pe(path: Path = typer.Argument(...,
                                   exists=True,
                                   file_okay=True,
                                   dir_okay=True)):
    """
    Get the Portable Executable info for files in the path.
    path can be a directory or a single file.
    """

    for index, pe_info in enumerate(get_pe_info(path)):
        if index:
            typer.secho(f"---", fg=typer.colors.MAGENTA)

        pe_info.print_pe_info()


@app.command()
def overview(path: Path = typer.Argument(...,
                                         exists=True,
                                         file_okay=True,
                                         dir_okay=True)):
    """
    Get an overview of information for the provided path files through
    running most of the malw commands with default values.
    path can be a single file or directory
    """
    for index, filepath in enumerate(get_filepaths(path)):
        if index:
            typer.secho(f"---\n", fg=typer.colors.MAGENTA)

        typer.secho(
            f"{filepath.name} - {get_human_readable_size(filepath.stat().st_size)}", fg=typer.colors.RED)

        typer.secho(f"\nChecksums:", fg=typer.colors.MAGENTA)

        for checksum in get_checksum_groups(HashFunction.ALL, filepath)[0]:
            checksum.print_info_for_checksum(show_filename=False)

        typer.secho(f"\nFiletype:", fg=typer.colors.MAGENTA)

        for FileType in get_filetypes(filepath):
            FileType.print_info_for_filetype(show_filename=False)

        typer.secho(f"\nInteresting Strings?",
                    fg=typer.colors.MAGENTA)

        for string in get_strings(filepath):
            string.print_info_for_string(
                only_interesting=True, show_offset_in_file=True)

        typer.secho(f"\nPE information:", fg=typer.colors.MAGENTA)

        for pe_info in get_pe_info(filepath):
            pe_info.print_pe_info(show_filename=False)


def version_callback(value: bool):
    if value:
        typer.echo(f"Malw version: {__version__}")
        raise typer.Exit()


@app.callback()
def main(version: Optional[bool] = typer.Option(None,
                                                "--version",
                                                callback=version_callback,
                                                is_eager=True)):
    """
    A Simple Malware Analyzer with Python
    """
