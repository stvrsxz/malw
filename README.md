A Really Simple Static Malware Analyzer with Python and Typer


## Usage
[Click Here For Bigger Gif](https://raw.githubusercontent.com/0xstvrs/malw/master/malw.gif)

![](malw.gif) 

## Documentation

[Docs Here](DOCS.md)
---

## Installation

First have a look in this section for requirements: [Troubleshooting](#troubleshooting)

**From Github with pip:**

`pip3 install --user https://github.com/0xstvrs/malw/raw/master/dist/malw-0.1.0-py3-none-any.whl`

**Locally with pip:**

`git clone https://github.com/0xstvrs/malw.git`

`cd malw`

`pip3 install --user dist/malw-0.1.0-py3-none-any.whl`

**Locally within a virtual env:**

`pip3 install poetry`

`git clone https://github.com/0xstvrs/malw.git`

`cd malw`

`poetry install`

`poetry shell`

`malw`

Optional after installed:

Install completion:

`malw --install-completion`

---

## Uninstall

Remove with pip:

`pip3 uninstall malw`

---

## Building and Testing Locally

`poetry build`

**Testing:** 



Create the unpacked pe file:

`sudo apt-get install mingw-w64`
`x86_64-w64-mingw32-gcc -o tests/files/pe.exe tests/files/pe_source.c`

Create the packed pe file:

`upx -o tests/files/pe_packed.exe tests/files/pe.exe`


One liner (with remove):

`rm tests/files/*.exe; x86_64-w64-mingw32-gcc -o tests/files/pe.exe tests/files/pe_source.c; upx -o tests/files/pe_packed.exe tests/files/pe.exe`

---

## Generating Docs

`typer malw.malw utils docs --output=DOCS.md --name=malw`


---

## Troubleshooting
- malw uses python-magic for file type detection. If you have problems with it, first check the prerequisites for using this package https://github.com/ahupp/python-magic#installation

- if the ssdeep is failing, try:

     `sudo apt install libffi-dev libfuzzy-dev libfuzzy2`

- python3.9 is a requirement. 

    `apt install python3.9 python3.9-dev`

    If pip fails with python versions try:
    
    `python3.9 -m pip install --user https://github.com/0xstvrs/malw/raw/master/dist/malw-0.1.0-py3-none-any.whl`


## Recording
`asciinema rec malw.cast -i 2`

`sudo docker run --rm -v $PWD:/data asciinema/asciicast2gif malw.cast malw.gif`  (Docker asciicast2gif)