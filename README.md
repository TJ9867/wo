# wo
A simple utility designed to aid in RE of large-ish firmware dumps. There are three main utilties, all of which are binary-scraping type tools. The main things this projects let you do are:
- Quickly look for the use of 'interesting' functions
- Find users of specific libraries
- List all of the libraries loaded by a given binary


## Installation
Installation is easy:
```bash
python3 -m venv venv
. ./venv/bin/activate
pip install -e <this repo>
```

This will install the `wo` command. 

## Usage
See `wo -h` and the associated subcommand helps: `wo findlib -h`, `wo lslib -h`, `wo fun -h` for detailed help.
