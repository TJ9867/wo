import logging
import os
import pathlib
import sys

from contextlib import contextmanager

ASCII_COLORS = {
    "grey": "\x1b[38;20m",
    "green": "\x1b[32;20m",
    "orange": "\x1b[33;20m",
    "red": "\x1b[31;20m",
    "bold_red": "\x1b[31;1m",
    "reset": "\x1b[0m",
}


# Copied from https://stackoverflow.com/questions/384076/how-can-i-color-python-logging-output
class CustomFormatter(logging.Formatter):
    verbose_format = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    )

    basic_format = "%(message)s"

    FORMATS = {
        logging.DEBUG: ASCII_COLORS["green"] + verbose_format + ASCII_COLORS["reset"],
        logging.INFO: basic_format,
        logging.WARNING: ASCII_COLORS["orange"] + basic_format + ASCII_COLORS["reset"],
        logging.ERROR: ASCII_COLORS["red"] + basic_format + ASCII_COLORS["reset"],
        logging.CRITICAL: ASCII_COLORS["bold_red"]
        + verbose_format
        + ASCII_COLORS["reset"],
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%m/%d/%Y %I:%M:%S %p")
        return formatter.format(record)


# Copied from https://stackoverflow.com/questions/4675728/redirect-stdout-to-a-file-in-python/22434262#22434262
# We needed a means of stopping lief from producing output so as not to confuse CLI users
def fileno(file_or_fd):
    fd = getattr(file_or_fd, "fileno", lambda: file_or_fd)()
    if not isinstance(fd, int):
        raise ValueError("Expected a file (`.fileno()`) or a file descriptor")
    return fd


@contextmanager
def stdout_redirected(to=os.devnull, stdout=None):
    if stdout is None:
        stdout = sys.stdout

    stdout_fd = fileno(stdout)
    # copy stdout_fd before it is overwritten
    # NOTE: `copied` is inheritable on Windows when duplicating a standard stream
    with os.fdopen(os.dup(stdout_fd), "wb") as copied:
        stdout.flush()  # flush library buffers that dup2 knows nothing about
        try:
            os.dup2(fileno(to), stdout_fd)  # $ exec >&to
        except ValueError:  # filename
            with open(to, "wb") as to_file:
                os.dup2(to_file.fileno(), stdout_fd)  # $ exec > to
        try:
            yield stdout  # allow code to be run with the redirected stdout
        finally:
            # restore stdout to its previous value
            # NOTE: dup2 makes stdout_fd inheritable unconditionally
            stdout.flush()
            os.dup2(copied.fileno(), stdout_fd)  # $ exec >&copied


def merged_stderr_stdout():  # $ exec 2>&1
    return stdout_redirected(to=sys.stdout, stdout=sys.stderr)


def write_output(logger, pretty_fmt, output_format, is_header, *args):
    if output_format == "csv":
        logger.info(",".join(args))
    elif output_format == "md":
        logger.info("| " + "\t|".join(args) + " |")
        if is_header:
            logger.info("|" + "|".join(["-" for _ in args]) + "|")

    elif output_format == "text":
        logger.info(pretty_fmt.format(*args))
