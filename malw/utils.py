from enum import Enum
from pathlib import Path
from typing import List

import ssdeep
import typer


def get_filepaths(path: Path, ignore_subdir: bool = True):
    """
    Given a Path object return it as the sole member of a list, if it is a file.
    If it is a directory return a list of all Path objects for every file in this directory.
    ignore_subdir ignores sub directories when the given object is a directory.
    """
    filepaths = []
    if path.is_dir():
        filepaths = [filepath for filepath in path.iterdir()]
        if ignore_subdir:
            filepaths = [
                filepath for filepath in filepaths if not filepath.is_dir()]
    else:
        filepaths.append(path)

    return filepaths


def get_human_readable_size(size: int, decimal_places: int = 2):
    # https://stackoverflow.com/a/43690506
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']:
        if size < 1024.0 or unit == 'PiB':
            break
        size /= 1024.0
    return f"{size:.{decimal_places}f} {unit}"


class Radix(str, Enum):
    D = "d"  # decimal
    O = "o"  # octal
    X = "x"  # hex


def convert_radix(radix: Radix, value: int):
    if radix == Radix.D:
        return str(value)
    elif radix == Radix.O:
        return oct(value)
    elif radix == Radix.X:
        return hex(value)


def accept_file_size(path: Path, prompt_message_part: str = "", bytes_to_prompt: int = 104857600):  # 100 MiB
    accept = True
    if path.stat().st_size > bytes_to_prompt:
        accept = typer.confirm(
            f"File is bigger than {get_human_readable_size(bytes_to_prompt)}. {prompt_message_part}")

    return accept


def unpack_paths(paths: List[Path]):
    """Get a list of paths. Whatever there are. Directories, files and
    return a set of distinct filepaths
    """
    filepaths = set()
    for path in paths:
        filepaths.update(set(get_filepaths(path)))
    return filepaths


def get_fuzzy_hash(filepath: Path):
    return ssdeep.hash_from_file(str(filepath))


def get_path_from_parent(path: Path):
    return str(path.relative_to(path.parent.parent))
