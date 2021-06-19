
from datetime import datetime
import os
from pathlib import Path

import magic
import pefile
import peutils
from tabulate import tabulate
import typer

from .utils import get_filepaths, get_fuzzy_hash


USER_DB_TXT = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    'userdb.txt',
)


class PEInfo:
    def __init__(self, path: Path):
        self.path = path
        self.pe = pefile.PE(path)

    @property
    def fuzzy_hash(self):
        return get_fuzzy_hash(self.path)

    @property
    def imphash(self):
        return self.pe.get_imphash()

    @property
    def sections(self):
        rv = {}
        for index, section in enumerate(self.pe.sections):
            rv[index] = {}
            rv[index]["name"] = section.Name.decode("utf8").rstrip("\x00")
            rv[index]["raw_size"] = section.SizeOfRawData
            rv[index]["virtual_size"] = section.Misc_VirtualSize
            rv[index]["entropy"] = round(section.get_entropy(), 2)
            rv[index]["md5"] = section.get_hash_md5()
            rv[index]["virtual_address"] = hex(section.VirtualAddress)
            # TODO: More rules for suspiciousness?
            rv[index]["suspicious"] = section.SizeOfRawData == 0 or (
                0 < section.get_entropy() < 1) or section.get_entropy() > 7

        return rv

    def print_sections(self):
        section_keys = ["name", "raw_size",
                        "virtual_size", "entropy", "md5", "suspicious"]

        styled_section_keys = [typer.style(
            key, fg=typer.colors.CYAN) for key in section_keys]

        list_for_tabulate = [styled_section_keys]

        for k, v in self.sections.items():
            list_for_tabulate.append([v[section_key]
                                     for section_key in section_keys])

        typer.secho("\nSections:")
        typer.echo(f"{tabulate(list_for_tabulate)}")

    @property
    def imports(self):
        rv = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:  # pylint: disable=no-member
                rv[entry.dll] = []
                for import_ in entry.imports:
                    import_name = import_.name if import_.name is not None else "ord(%s)" % (
                        str(import_.ordinal))
                    rv[entry.dll].append(import_name)
        return rv

    def print_imports(self):
        typer.echo("\nImports:\n")
        for lib in self.imports:
            typer.secho(f"{lib.decode('utf8')}:", fg=typer.colors.BRIGHT_GREEN)
            for import_ in self.imports[lib]:
                typer.secho(f"\t{import_.decode('utf8')}",
                            fg=typer.colors.CYAN)

    @property
    def exports(self):  # TODO: testing for exports
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return [export.name.decode("utf8") for export in self.pe.DIRECTORY_ENTRY_EXPORT.symbols]  # pylint: disable=no-member
        return []

    def print_exports(self):
        exports_string = "\n".join(self.exports)
        typer.echo(
            f"\nExports:\n{typer.style(exports_string, fg=typer.colors.CYAN)}")

    @property
    def built_with(self):
        signatures = peutils.SignatureDatabase(USER_DB_TXT)
        matched = signatures.match(self.pe)
        return matched[0] if matched else ""

    @property
    def compilation_date(self):
        return datetime.utcfromtimestamp(
            self.pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')  # pylint: disable=no-member

    @property
    def resources(self):
        # TODO: Add Tests For Resources
        # TODO: Handle all cases + refactor.
        rv = {}
        # https://github.com/hiddenillusion/AnalyzePE/blob/9c76ecbc3ac417bc07439c244f2d5ed19af06578/pescanner.py#L190
        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for index, resource_entry in enumerate(self.pe.DIRECTORY_ENTRY_RESOURCE.entries):  # pylint: disable=no-member
                rv[index] = {"name": "",
                             "filetype": "",
                             "lang": "",
                             "sublang": ""}
                if resource_entry.name is not None:
                    rv[index]["name"] = resource_entry.name
                else:
                    rv[index]["name"] = pefile.RESOURCE_TYPE.get(
                        resource_entry.struct.Id, resource_entry.struct.Id)

                if hasattr(resource_entry, 'directory'):
                    for resource_id in resource_entry.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for entry in resource_id.directory.entries:
                                data = self.pe.get_data(
                                    entry.data.struct.OffsetToData, entry.data.struct.Size)
                                rv[index]["filetype"] = magic.from_buffer(data)
                                rv[index]["lang"] = pefile.LANG.get(
                                    entry.data.lang, '*unknown*')
                                rv[index]["sublang"] = pefile.get_sublang_name_for_lang(
                                    entry.data.lang, entry.data.sublang)

        return rv

    def print_resources(self):

        resources_keys = ["name", "filetype", "lang", "sublang"]

        styled_resources_keys = [typer.style(
            key, fg=typer.colors.CYAN) for key in resources_keys]

        list_for_tabulate = [styled_resources_keys]

        for k, v in self.resources.items():
            list_for_tabulate.append([v[resources_key]
                                     for resources_key in resources_keys])

        typer.secho("\nResources:")
        if not self.resources:
            typer.echo(f"No resources")
        else:
            # TODO: Add maxcolwidths=[None, 20, None, None] or something on tabulate call when the tabulate is upgraded on pypi.
            typer.echo(f"{tabulate(list_for_tabulate, tablefmt='grid')}")

    @property
    def subsystem(self):
        return pefile.SUBSYSTEM_TYPE[self.pe.OPTIONAL_HEADER.Subsystem]

    def print_pe_info(self, show_filename: bool = True):
        if show_filename:
            typer.secho(self.path.name, fg=typer.colors.RED)

        val_color = typer.colors.CYAN
        typer.echo(
            f"\nFuzzy hash: {typer.style(self.fuzzy_hash, fg=val_color)}")

        typer.echo(f"\nImphash: {typer.style(self.imphash, fg=val_color)}")

        typer.echo(
            f"\nBuilt with: {typer.style(self.built_with, fg=val_color)}")

        typer.echo(
            f"\nCompilation date: {typer.style(self.compilation_date, fg=val_color)}")

        typer.echo(f"\nSubsystem: {typer.style(self.subsystem, fg=val_color)}")

        self.print_imports()
        self.print_exports()
        self.print_sections()
        self.print_resources()


def get_pe_info(path: Path):
    """
    Return a list of pe_info objects for every file in the path.
    """
    rv = []
    for filepath in get_filepaths(path):
        try:
            rv.append(PEInfo(filepath))
        except pefile.PEFormatError as ex:
            typer.secho(
                f"Can't analyze {filepath}", fg=typer.colors.RED)
            if path.is_dir():
                typer.secho(f"---", fg=typer.colors.MAGENTA)
    return rv
