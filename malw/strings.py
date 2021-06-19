from pathlib import Path
import re
import string
from typing import Optional

import typer

from .utils import accept_file_size, convert_radix, Radix


# TODO: Integrate floss https://github.com/fireeye/flare-floss when is python3 ready and maybe use floss instead of malw.strings
#       Or replicate floss. Probably a nice exercise  ¯\_(ツ)_/¯

class StringType:

    regex = None
    type_ = None
    hint = None
    color = typer.colors.BRIGHT_RED
    example = None
    subclasses = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Have in mind that the order of the subclasses matters on what the match will be.
        # because a string can match multiple patterns
        cls.subclasses.append(cls)

    # For the most types is not super easy or clear to match everything with regex (e.g. domains)
    # Regexes are for giving possible, and not certain, positive results
    # You can override this function and use something else than regex. With the possible performance cost
    @classmethod
    def is_matching(cls, value: str):
        return re.match(r"%s" % cls.regex, value)


class InterestingString(StringType):
    """
    Just anything interesting that comes to mind or found after analyzing samples, that can't be matched with the other regexes
        for now or simply doesn't belong to other string types-regexes.

    TODO: Try to edit the other regexes to match these strings when appropriate.
    """

    interesting_strings = [".exe", "c://", ".dll", "exec", "sleep"]

    @classmethod
    def is_matching(cls, value: str):
        for interesting in cls.interesting_strings:
            if interesting in value.lower():
                return True

    type_ = "interesing"
    hint = "Interesting?"
    example = "exec"


class IPv4String(StringType):
    # https://stackoverflow.com/a/36760050
    regex = "^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$"
    type_ = "ipv4"
    hint = "IPv4?"
    example = "1.1.1.1"


class IPv6String(StringType):
    # https://stackoverflow.com/a/17871737
    regex = "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    type_ = "ipv6"
    hint = "IPv6?"
    example = "2001:4860:4860::8888"


class BitcoinString(StringType):
    # https://stackoverflow.com/a/48643915
    regex = "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$"
    type_ = "bitcoin"
    hint = "Bitcoin?"
    example = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


class EthereumTokenString(StringType):
    # https://ethereum.stackexchange.com/q/1374
    regex = "^(0x)?[a-fA-F0-9]{40}$"
    type_ = "ethereum"
    hint = "Ethereum?"
    example = "0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7"


class FileString(StringType):
    # TODO: MAke it better?
    regex = "^\S+\.(dll|exe|pdf|doc|docx|html|htm|zip|rar|xls|odt|msi|bat|ps1|ppt)$"
    type_ = "file"
    hint = "File?"
    example = "malmalmalw.dll"


class RegistryString(StringType):
    # https://stackoverflow.com/a/54569327
    regex = "^HKEY_\S+$"  # TODO: MAke it better? # What about HKCR?
    type_ = "registry"
    hint = "Registry Key?"
    example = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto\Parameters\ServiceDLL"


class DomainString(StringType):
    # https://stackoverflow.com/a/20204811  and edited for common tlds
    # TODO: MAke it better?
    regex = "(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+(com|eu|net|org|ru|uk|de|in|edu)$)"
    type_ = "domain"
    hint = "Domain?"
    example = "google.de"


class URLString(StringType):
    # https://stackoverflow.com/a/6041965
    regex = "(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?"
    type_ = "url"
    hint = "URL?"
    example = "https://www.example.com"


class EmailString(StringType):
    # https://stackoverflow.com/a/742588
    regex = "^.+@.+\..+$"
    type_ = "email"
    hint = "Email?"
    example = "test@test.com"


class MD5HashString(StringType):
    # https://stackoverflow.com/questions/21517102/regex-to-match-md5-hashes
    regex = "^[a-fA-F0-9]{32}"
    type_ = "md5"
    hint = "MD5 Hash?"
    example = "0f53217fc7c8e7f89e8a8558e64a7083"


class SHA1HashString(StringType):
    # https://stackoverflow.com/questions/468370/a-regex-to-match-a-sha1
    regex = "^[A-Fa-f0-9]{40}$"
    type_ = "sha1"
    hint = "SHA1 Hash?"
    example = "bf6db7112b56812702e99d48a7b1dab62d09b3f6"


class SHA256HashString(StringType):
    # https://stackoverflow.com/a/6630280
    regex = "^[A-Fa-f0-9]{64}$"
    type_ = "sha256"
    hint = "SHA256 Hash?"
    example = "85757d9ef5868bb53472a6be8d81d1e3c398546b69b107141ad336053c40cb54"


class String:
    __slots__ = ("value", "offset_in_file", "hint", "color", "type_")

    def __init__(self, value: str, offset_in_file: str, type_: Optional[str] = None, hint: Optional[str] = None):
        self.value = value
        self.offset_in_file = offset_in_file
        self.hint = hint
        self.color = None
        self.type_ = type_
        self._initialize()

    def _initialize(self):
        for StringTypeSubClass in StringType.subclasses:
            if StringTypeSubClass.is_matching(self.value):
                # if value matched an is_matching method
                self.type_ = StringTypeSubClass.type_
                self.color = StringTypeSubClass.color
                self.hint = StringTypeSubClass.hint

    def print_info_for_string(self, only_interesting: bool = False, show_offset_in_file: bool = False):
        parts_for_echo = []

        if only_interesting and not self.type_:
            return

        if show_offset_in_file:
            parts_for_echo.append(str(self.offset_in_file))

        parts_for_echo.append(typer.style(self.value, fg=self.color))

        if self.hint:
            parts_for_echo.append(typer.style(
                self.hint, fg=typer.colors.GREEN))

        typer.echo(f"{'  '.join(parts_for_echo)}")


def get_strings(path: Path, min_chars: int = 4, max_bytes: Optional[int] = None, offset: Optional[int] = None, radix: Radix = Radix.X):
    find_strings = accept_file_size(path,
                                    prompt_message_part="Are you sure you want to run strings? (You can use max_bytes and/or offset instead)")

    if find_strings:
        with path.open(mode="rb") as f:
            if offset:
                f.seek(offset)

            if max_bytes:
                buf = f.read(max_bytes)
            else:
                buf = f.read()

            filtered_string_characters = string.printable.replace(
                "\n", "").replace("\r", "").replace("\x0c", "").replace("\x0b", "")

            filtered_string_characters = "".join(
                re.escape(filtered_string_characters))

            r = re.compile(br"([%s]{%d,})" %
                           (filtered_string_characters.encode(), min_chars))

            typer.secho(f"ASCII strings:", fg=typer.colors.CYAN)
            for match in r.finditer(buf):
                if match.group():
                    yield String(match.group().decode("ascii").strip(), offset_in_file=convert_radix(radix, match.start()))

            r = re.compile(br"((?:[%s]\x00){%d,})" % (
                filtered_string_characters.encode(), min_chars))

            # TODO: Make it catch other encodings + non ascii printable strings also?
            for index, match in enumerate(r.finditer(buf)):
                if not index:
                    typer.secho(f"UTF-16 strings:", fg=typer.colors.CYAN)
                if match.group():
                    try:
                        yield String(
                            value=match.group().decode("utf-16").strip(),
                            offset_in_file=convert_radix(radix, match.start()))
                    except UnicodeDecodeError:
                        pass

    else:
        typer.secho(f"Aborted strings command", fg=typer.colors.RED)
        raise typer.Exit()
