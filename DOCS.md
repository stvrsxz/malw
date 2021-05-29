# `malw`

A Simple Malware Analyzer with Python

**Usage**:

```console
$ malw [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--version`
* `--install-completion`: Install completion for the current shell.
* `--show-completion`: Show completion for the current shell, to copy it or customize the installation.
* `--help`: Show this message and exit.

**Commands**:

* `filetypes`: Get the filetype for files in the path.
* `hashes`: Get the checksums for files in the path.
* `overview`: Get an overview of information for the...
* `pe`: Get the Portable Executable info for files in...
* `strings`: Get the strings objects for files in the...

## `malw filetypes`

Get the filetype for files in the path.
path can be a directory or a single file.

**Usage**:

```console
$ malw filetypes [OPTIONS] PATH
```

**Arguments**:

* `PATH`: [required]

**Options**:

* `--help`: Show this message and exit.

## `malw hashes`

Get the checksums for files in the path.
path can be a directory or a single file.
hash-function can be 'md5', 'sha1', 'sha256' or 'all' (default) to get all checksums
for the provided hash functions

**Usage**:

```console
$ malw hashes [OPTIONS] PATH
```

**Arguments**:

* `PATH`: [required]

**Options**:

* `--hash-function [all|md5|sha1|sha256]`: [default: all]
* `--help`: Show this message and exit.

## `malw overview`

Get an overview of information for the provided path files through
running most of the malw commands with default values.
path can be a single file or directory

**Usage**:

```console
$ malw overview [OPTIONS] PATH
```

**Arguments**:

* `PATH`: [required]

**Options**:

* `--help`: Show this message and exit.

## `malw pe`

Get the Portable Executable info for files in the path.
path can be a directory or a single file.

**Usage**:

```console
$ malw pe [OPTIONS] PATH
```

**Arguments**:

* `PATH`: [required]

**Options**:

* `--help`: Show this message and exit.

## `malw strings`

Get the strings objects for files in the path.
path can be a single file (Simply for not having extremely long output)

Tries to emulate some common "strings" functionalities.

min_chars: Min string length in characters. (ASCII or Unicode)
max_bytes: Max bytes of file to scan
offset: File offset at which to start scanning.
radix: The offset the string appears in the file. x for hex (default), o for octal, d for decimal. If no 
radix is given then it will not be shown in the output

**Usage**:

```console
$ malw strings [OPTIONS] PATH
```

**Arguments**:

* `PATH`: [required]

**Options**:

* `--min-chars INTEGER`: [default: 4]
* `--max-bytes INTEGER`
* `--offset INTEGER`
* `--radix [d|o|x]`
* `--help`: Show this message and exit.
