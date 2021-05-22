from dataclasses import dataclass
from pathlib import Path

import magic
import typer

from .utils import get_filepaths


@dataclass
class FileType:
    """Data class for info related to a filetype of a file."""
    filename: str
    filepath: Path
    value: str

    def print_info_for_filetype(self, show_filename: bool = True):
        parts_for_echo = []
        if show_filename:
            parts_for_echo.append(typer.style(
                self.filename, fg=typer.colors.RED))

        parts_for_echo.append(typer.style(
            self.value, fg=typer.colors.GREEN))

        typer.echo(f"{' - '.join(parts_for_echo)}")


def get_filetypes(path: Path):
    """
    Return a list of filetypes for every file in the path.
    """
    rv = []
    for filepath in get_filepaths(path):
        rv.append(FileType(filename=filepath.name,
                  filepath=filepath, value=magic.from_file(str(filepath))))
    return rv
