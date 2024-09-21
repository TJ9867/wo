import argparse
import lief
import logging
import pathlib
import sys

from pathlib import Path

from . import CustomFormatter
from .fun import process_fun, parse_fun
from .lslib import process_lslib, parse_lslib
from .findlib import process_findlib, parse_findlib

logger = None


def generate_parser():
    parser = argparse.ArgumentParser(
        description="A tool to find interesting things in binaries"
    )
    # General options
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Make output verbose"
    )

    # Sub command parsing
    sub_parsers = parser.add_subparsers(help="Commands", dest="command")
    fun_desc = "Search a folder of binaries for 'interesting' functions"
    parser_fun = sub_parsers.add_parser("fun", help=fun_desc, description=fun_desc)
    parse_fun(parser_fun)

    lslib_desc = "Recursively list the imported libraries of a binary"
    parser_lslib = sub_parsers.add_parser(
        "lslib", help=lslib_desc, description=lslib_desc
    )
    parse_lslib(parser_lslib)

    findlib_desc = "Recursively search for imports of a specific library"
    parser_findlib = sub_parsers.add_parser(
        "findlib", help=findlib_desc, description=findlib_desc
    )
    parse_findlib(parser_findlib)

    return parser


def parse_args():
    return generate_parser().parse_args()


def main(args):
    global logger

    logger = logging.getLogger(__name__)
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(CustomFormatter(datefmt="%m/%d/%Y %I:%M:%S %p"))
    stream.setLevel(logging.DEBUG)
    logger.addHandler(stream)

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.command is None:
        logger.error("A command value is required!")
        generate_parser().print_usage()
        return
    elif args.command == "fun":
        process_fun(logger, args)
    elif args.command == "lslib":
        process_lslib(logger, args)
    elif args.command == "findlib":
        process_findlib(logger, args)


def main_cli():
    args = parse_args()
    main(args)


if __name__ == "__main__":
    main_cli()
