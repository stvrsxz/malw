from enum import Enum
import hashlib
from pathlib import Path

import typer

from .utils import get_filepaths


class HashFunction(str, Enum):
    ALL = "all"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class Checksum:
    hash_algorithm = None

    def __init__(self, filepath):
        self.bytes_ = filepath.stat().st_size
        self.filepath = filepath
        self.name = filepath.name
        self.hashlib_object = getattr(hashlib, self.hash_algorithm)

    @property
    def value(self):
        with open(self.filepath, "rb") as f:
            checksum = self.hashlib_object()
            while chunk := f.read(8192):
                checksum.update(chunk)

        return checksum.hexdigest()

    def print_info_for_checksum(self, show_filename: bool = True):
        parts_for_echo = []
        if show_filename:
            parts_for_echo.append(typer.style(
                self.name, fg=typer.colors.RED))

        parts_for_echo.append(typer.style(
            self.value, fg=typer.colors.GREEN))

        parts_for_echo.append(self.hash_algorithm)

        typer.echo(f"{' '.join(parts_for_echo)}")


class MD5Checksum(Checksum):
    hash_algorithm = HashFunction.MD5


class SHA1Checksum(Checksum):
    hash_algorithm = HashFunction.SHA1


class SHA256Checksum(Checksum):
    hash_algorithm = HashFunction.SHA256


# Register Checksum subclasses:
checksum_classes = {
    sub_class.hash_algorithm: sub_class for sub_class in Checksum.__subclasses__()}


def get_checksum_groups(hash_function: str, path: Path):
    """
    Return a list of lists of checksum objects for every file in the path.
    If hash_function == 'all' then return all the results for all the registered
    checksum subclasses.
    Otherwise return only the checksum for the specific function provided by the user. e.g. md5
    """
    checksum_groups = []

    for filepath in get_filepaths(path):
        checksum_group = []
        if hash_function == "all":
            for checksum_class in checksum_classes:
                checksum_group.append(
                    checksum_classes[checksum_class](filepath))
        else:
            checksum_group.append(
                checksum_classes[hash_function](filepath))
        checksum_groups.append(checksum_group)
    return checksum_groups
