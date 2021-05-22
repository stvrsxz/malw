TODO: refactor this in the end

A Malware Analyzer with Python and Typer

(A simplistic project with the purpose of combining some new python features, the typer cli framework and malware analysis)

---

## Installation:

(TODO: Publish to pypi?)

(TODO: Make project public) From Github with pip:

`pip3 install --user https://github.com/0xstvrs/malw/raw/master/dist/malw-0.1.0-py3-none-any.whl`

Locally with pip:

`git clone https://github.com/0xstvrs/malw.git`

`cd malw`

`pip3 install --user dist/malw-0.1.0-py3-none-any.whl`

(Optional)

When installed:

Install completion:

`malw --install-completion`

Remove installed with pip:

`pip3 uninstall malw`

Locally within a virtual env:

`pip3 install poetry`

`git clone https://github.com/0xstvrs/malw.git`

`cd malw`

`poetry install`

`poetry shell`

`malw`

(Optional)

`poetry build`
and then install the generated .whl file (see step with the .whl installation)

Upgrade:

`pip3 install malw -U`


Testing: (use a make file? see floss)
Create the pe file:
`sudo apt-get install mingw-w64`
`x86_64-w64-mingw32-gcc -o tests/files/pe.exe tests/files/pe_source.c`

Packed:
`upx -o tests/files/pe_packed.exe tests/files/pe.exe`


Quick: (maybe remove this):
`rm tests/files/*.exe; x86_64-w64-mingw32-gcc -o tests/files/pe.exe tests/files/pe_source.c; upx -o tests/files/pe_packed.exe tests/files/pe.exe`


Troubleshooting:
- malw uses python-magic for file type detection. If you have problems with it, first check the prerequisites for using this package https://github.com/ahupp/python-magic#installation
- if the ssdeep is failing, try to install: `sudo apt install libffi-dev libfuzzy-dev libfuzzy2`
- TODO: Python version?