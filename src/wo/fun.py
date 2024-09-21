import argparse
import lief
import logging
import os
import re

from pathlib import Path
from logging import Logger
from typing import List

from . import stdout_redirected, merged_stderr_stdout, ASCII_COLORS

interesting_functions = {
    "exec-family": [
        "execl",
        "execlp",
        "execle",
        "execv",
        "execve",
        "execvp",
        "execvpe",
    ],
    "system-family": ["system", "sh", "popen", "posix_spawn", "posix_spawnp"],
    "none": [],
    "all": [],
}
for key, items in interesting_functions.items():
    if key != "all":
        interesting_functions["all"].extend(items)


def parse_fun(parser):
    parser.add_argument(
        "-l",
        "--function-list",
        type=str,
        choices=list(interesting_functions.keys()) + ["all"],
        default="none",
        help="List of functions to look for. Defaults to 'none'",
    )
    parser.add_argument(
        "-f",
        "--function-name",
        type=str,
        default=None,
        nargs="+",
        help="Custom function name(s) to search for",
    )
    parser.add_argument(
        "-p",
        "--partial-function-name",
        type=str,
        default=None,
        nargs="+",
        help="Custom partial function name(s) to search for",
    )
    parser.add_argument(
        "-r",
        "--regex-function-name",
        type=str,
        default=None,
        nargs="+",
        help="Custom regex function name(s) to search for",
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
        "directory", nargs="+", type=Path, help="Directory(s) to search"
    )


def process_fun(logger: Logger, args: argparse.Namespace):
    logger.debug(f"Got args.function_name: {args.function_name}")

    exact_fns = (
        args.function_name if type(args.function_name) is list else [args.function_name]
    )
    partial_fns = (
        args.partial_function_name
        if type(args.partial_function_name) is list
        else [args.partial_function_name]
    )
    regex_fns = (
        args.regex_function_name
        if type(args.regex_function_name) is list
        else [args.regex_function_name]
    )

    # Remove accidental commas (argparse just plops them into the values)
    exact_fns = [fn.replace(",", "").strip() for fn in exact_fns if fn is not None]
    partial_fns = [fn.replace(",", "").strip() for fn in partial_fns if fn is not None]
    regex_fns = [fn.replace(",", "").strip() for fn in regex_fns if fn is not None]

    for dirent in args.directory:
        if not dirent.exists():
            logger.warn(f"No such directory {dirent}. Skipping...")
            continue
        process_fun_directory(
            logger,
            dirent,
            interesting_functions[args.function_list],
            exact_fns,
            partial_fns,
            regex_fns,
            args.output_format,
        )


def process_exact_fns(logger, output_format, f, predefined_fns, bin_function_set):
    search_fn_set = set(predefined_fns)
    logger.debug(f"Matching set {search_fn_set} against binary dynamic functions")
    matching_fns = search_fn_set.intersection(bin_function_set)
    if len(matching_fns) > 0:
        if output_format == "text":
            logger.info(
                f"{ASCII_COLORS['green']}{matching_fns}{ASCII_COLORS['reset']} in {f}"
            )
        else:
            for matching_fn in matching_fns:
                logger.info(f"{f.name}, {matching_fn}, exact name match")


def process_regex_fns(logger, output_format, f, partial_fns, bin_function_set):
    search_fn_set = set(partial_fns)
    logger.debug(f"Matching set {search_fn_set} against binary dynamic functions")

    search_res = []
    for search_fn in search_fn_set:
        search_res.append(re.compile(search_fn))

    # TODO better datastructure/algo for this search
    for fn in bin_function_set:
        for search_re in search_res:
            # logger.debug(f"Looking for {search_fn} in {fn}")
            if search_re.search(fn):
                if output_format == "text":
                    logger.info(
                        f"{ASCII_COLORS['green']}{fn}{ASCII_COLORS['reset']} in {f}"
                    )
                else:
                    logger.info(f"{f.name}, {fn}, regex match")


def process_fun_directory(
    logger: Logger,
    dirent: Path,
    predefined_fns: List[str],
    exact_fns: List[str],
    partial_fns: List[str],
    regex_fns: List[str],
    output_format: str,
):
    logger.debug(
        f"Processing directory {dirent} with fns:\n\t-{'\n\t-'.join(predefined_fns)}\n"
    )

    logger.info(f"Binary Name, Function Name, Match Type")
    for f in dirent.rglob("*"):
        logger.debug(f"Found file {f}")

        devnull = open(os.devnull, "w")
        lvl = logger.getEffectiveLevel()
        logger.setLevel(logging.CRITICAL)

        with stdout_redirected(to=os.devnull), merged_stderr_stdout():
            binary = lief.parse(f)

        logger.setLevel(lvl)

        if not binary:
            logger.debug(f"Found file {f} that wasn't parsable")
            continue
        with stdout_redirected(to=os.devnull), merged_stderr_stdout():
            bin_function_set = set([fn.name for fn in binary.functions])
            bin_function_set = bin_function_set.union(
                set([dyn.name for dyn in binary.dynamic_symbols if dyn.is_function])
            )
        process_exact_fns(logger, output_format, f, predefined_fns, bin_function_set)
        process_exact_fns(logger, output_format, f, exact_fns, bin_function_set)
        process_regex_fns(logger, output_format, f, partial_fns, bin_function_set)
