import argparse
import lief
import logging
import os
import re

from pathlib import Path
from logging import Logger
from typing import List

from . import stdout_redirected, merged_stderr_stdout, ASCII_COLORS, write_output
from .lslib import recursive_find_libs


def parse_findlib(parser):
    parser.add_argument(
        "-l",
        "--lib-name",
        type=str,
        default=None,
        nargs="+",
        required=True,
        help="Library name(s) to search for (regex)",
    )
    parser.add_argument(
        "-t",
        "--filetype",
        type=str,
        choices=["so", "exe", "any"],
        default="any",
        help="Restrict results to only specific file types (uses filepath heuristic as executables and libs are often both shared objects with entrypoints)",
    )
    parser.add_argument(
        "-o",
        "--output-format",
        type=str,
        choices=["text", "csv", "md"],
        default="text",
        help="Output format. text is nice for CLI and csv is easier for tracking large numbers of hits.",
    )
    parser.add_argument(
        "-d",
        "--directory",
        nargs="+",
        type=Path,
        required=True,
        help="Directory(s) to search",
    )


def process_findlib(logger: Logger, args: argparse.Namespace):
    if args.output_format in ["csv", "md"]:
        write_output(
            logger,
            "{} {} {}",
            args.output_format,
            True,
            "Binary with Library",
            "Matching Library",
        )

    for dirent in args.directory:
        if not dirent.exists():
            logger.warn(f"No such directory {dirent}. Skipping...")
            continue

        process_findlib_dir(
            logger, dirent, args.lib_name, args.filetype, args.output_format
        )


def process_findlib_dir(
    logger: Logger,
    dirent: Path,
    library_name: str,
    filetype: str,
    output_format: str,
):
    logger.debug(f"Processing directory {dirent}")

    library_res = []
    if type(library_name) is str:
        library_res = [re.compile(library_name)]
    elif type(library_name) is list:
        library_res = [re.compile(s) for s in library_name]

    logger.debug(f"Using libraries {library_res}")

    for f in dirent.rglob("*/*"):
        if not f.is_file():
            continue
        if filetype == "so":
            if "lib" not in str(f):
                continue
        elif filetype == "exe":
            if "bin" not in str(f):
                continue
        with stdout_redirected(to=os.devnull), merged_stderr_stdout():
            binary = lief.parse(f)
        if not binary:
            logger.debug(f"Unable to process binary {f}")
            continue

        libraries = recursive_find_libs(logger, dirent, binary)
        for library in libraries:
            for library_re in library_res:
                match = library_re.search(library)
                if match:
                    if output_format == "text":
                        logger.info(f"Found file {f} with lib {library}")
                    elif output_format in ["csv", "md"]:
                        # logger.info(f"{f}, {library}")
                        write_output(
                            logger, "{}, {}", output_format, False, str(f), library
                        )
                break
