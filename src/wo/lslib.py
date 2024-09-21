import argparse
import lief
import logging
import os
import re

from pathlib import Path
from logging import Logger
from typing import List

from . import stdout_redirected, merged_stderr_stdout, ASCII_COLORS


def parse_lslib(parser):
    parser.add_argument(
        "-l",
        "--lib_dir",
        type=Path,
        required=True,
        help="Directory to search for libraries in",
    )
    parser.add_argument(
        "-o",
        "--output-format",
        type=str,
        choices=["text", "csv"],
        default="text",
        help="Output format. text is nice for CLI and csv is easier for tracking large numbers of hits.",
    )
    parser.add_argument(
        "binary", nargs="+", type=Path, help="Binary(s) to search through"
    )


def process_lslib(logger: Logger, args: argparse.Namespace):
    if not args.lib_dir.exists():
        logger.error(
            f"No such library directory {args.lib_dir}. Please double check the path provided."
        )
        return
    for binary in args.binary:
        if not binary.exists():
            logger.warn(f"No such binary {binary}. Skipping...")
            continue

        process_lslib_file(logger, binary, args.lib_dir, args.output_format)


def find_lib(dirent: Path, lib: str) -> lief._lief.ELF.Binary:
    for potential_hit in dirent.rglob(f"**/{lib}"):
        b = lief.parse(potential_hit)
        if b:
            return b, potential_hit
    return None, None


def recursive_find_libs(
    logger: Logger, search_dir: Path, binary: lief._lief.ELF.Binary, max_iterations=100
):
    """Recursively find all libraries loaded by a binary"""

    libraries_to_search = set(binary.libraries)
    libraries_found = set(binary.libraries)
    libraries_searched = set()

    iterations = 0
    while iterations < max_iterations:
        libraries_to_search = libraries_to_search.difference(libraries_searched)
        logger.debug(f"New libraries to search {libraries_to_search}")
        iterations += 1
        if len(libraries_to_search) == 0:
            break
        next_lib_to_search = libraries_to_search.pop()
        if next_lib_to_search not in libraries_searched:
            libraries_searched.add(next_lib_to_search)
            lib, lib_path = find_lib(search_dir, next_lib_to_search)
            if lib:
                logger.debug(f"Found lib at {lib_path}")
                libraries_to_search.update(lib.libraries)
            else:
                logger.debug(f"Unable to find library {next_lib_to_search}")
    return list(libraries_found)


def process_lslib_file(
    logger: Logger,
    binary: Path,
    rootfs: Path,
    output_format: str,
):
    logger.debug(f"Processing file {binary}")

    with stdout_redirected(to=os.devnull), merged_stderr_stdout():
        binary = lief.parse(binary)

    libraries = recursive_find_libs(logger, rootfs, binary)

    if output_format == "text":
        logger.info(", ".join(libraries))
    elif output_format == "csv":
        for library in libraries:
            logger.info(library)
