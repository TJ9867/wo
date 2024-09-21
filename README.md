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
See `wo -h` and the associated subcommand helps: `wo findlib -h`, `wo lslib -h`, `wo fun -h` for the most up-to-date help.

```bash
usage: wo fun [-h] [-l {exec-family,system-family,none,all,all}] [-f FUNCTION_NAME [FUNCTION_NAME ...]] [-p PARTIAL_FUNCTION_NAME [PARTIAL_FUNCTION_NAME ...]] [-r REGEX_FUNCTION_NAME [REGEX_FUNCTION_NAME ...]] [-o {text,csv,md}] directory [directory ...]

Search a folder of binaries for 'interesting' functions

positional arguments:
  directory             Directory(s) to search

options:
  -h, --help            show this help message and exit
  -l {exec-family,system-family,none,all,all}, --function-list {exec-family,system-family,none,all,all}
                        List of functions to look for. Defaults to 'none'
  -f FUNCTION_NAME [FUNCTION_NAME ...], --function-name FUNCTION_NAME [FUNCTION_NAME ...]
                        Custom function name(s) to search for
  -p PARTIAL_FUNCTION_NAME [PARTIAL_FUNCTION_NAME ...], --partial-function-name PARTIAL_FUNCTION_NAME [PARTIAL_FUNCTION_NAME ...]
                        Custom partial function name(s) to search for
  -r REGEX_FUNCTION_NAME [REGEX_FUNCTION_NAME ...], --regex-function-name REGEX_FUNCTION_NAME [REGEX_FUNCTION_NAME ...]
                        Custom regex function name(s) to search for
  -o {text,csv,md}, --output-format {text,csv,md}
                        Output format. text is nice for CLI and csv is easier for tracking large numbers of hits.
```

```bash
usage: wo findlib [-h] -l LIB_NAME [LIB_NAME ...] [-t {so,exe,any}] [-o {text,csv}] -d DIRECTORY [DIRECTORY ...]

Recursively search for imports of a specific library

options:
  -h, --help            show this help message and exit
  -l LIB_NAME [LIB_NAME ...], --lib-name LIB_NAME [LIB_NAME ...]
                        Library name(s) to search for (regex)
  -t {so,exe,any}, --filetype {so,exe,any}
                        Restrict results to only specific file types (uses filepath heuristic as executables and libs are often both shared objects with entrypoints)
  -o {text,csv}, --output-format {text,csv}
                        Output format. text is nice for CLI and csv is easier for tracking large numbers of hits.
  -d DIRECTORY [DIRECTORY ...], --directory DIRECTORY [DIRECTORY ...]
                        Directory(s) to search
```

```bash
usage: wo lslib [-h] -l LIB_DIR [-o {text,csv}] binary [binary ...]

Recursively list the imported libraries of a binary

positional arguments:
  binary                Binary(s) to search through

options:
  -h, --help            show this help message and exit
  -l LIB_DIR, --lib_dir LIB_DIR
                        Directory to search for libraries in
  -o {text,csv}, --output-format {text,csv}
                        Output format. text is nice for CLI and csv is easier for tracking large numbers of hits.
```



## Examples

### Find Functions from a predefined list (execs, popen, etc)
```bash
wo fun test-directory/ -l all -o md
```

| Binary Name   |Function Name  |Match Type |
|-|-|-|
| libcutils.so  |popen  |exact name match |
| libdbus.so    |execve |exact name match |
| libdbus.so    |execvp |exact name match |
| libnspr4.so   |execv  |exact name match |
| libnspr4.so   |execve |exact name match |
| libutils.so   |popen  |exact name match |

### Find Functions matching a partial name
```bash
wo fun test-directory/ -p dbus -o md
```

| Binary Name   |Function Name  |Match Type |
|-|-|-|
| libdbus.so    |_dbus_header_set_serial        |regex match |
| libdbus.so    |dbus_error_has_name    |regex match |
| libdbus.so    |dbus_server_get_id     |regex match |
| libdbus.so    |_dbus_write_socket_two |regex match |
| libdbus.so    |_dbus_cmutex_unlock    |regex match |
| libdbus.so    |_dbus_user_info_fill_uid       |regex match |
| libdbus.so    |dbus_connection_register_fallback      |regex match |
| libdbus.so    |dbus_bus_remove_match  |regex match |
| libdbus.so    |_dbus_message_loader_get_unix_fds      |regex match |
| libdbus.so    |_dbus_pending_call_get_timeout_unlocked        |regex match |
| libdbus.so    |_dbus_message_loader_queue_messages    |regex match |
| libdbus.so    |_dbus_directory_get_next_file  |regex match |
| libdbus.so    |_dbus_auth_set_unix_fd_possible        |regex match |
| libdbus.so    |_dbus_file_exists      |regex match |
| libdbus.so    |_dbus_server_listen_socket     |regex match |
| libdbus.so    |_dbus_type_writer_init |regex match |
| libdbus.so    |_dbus_rmutex_free_at_location  |regex match |
| libdbus.so    |_dbus_transport_get_unix_process_id    |regex match |
| libdbus.so    |dbus_message_iter_append_fixed_array   |regex match |
| libdbus.so    |dbus_watch_get_flags   |regex match |
| libdbus.so    |dbus_timeout_set_data  |regex match |
| libdbus.so    |_dbus_connection_has_messages_to_send_unlocked |regex match |
| ...  | ... | ... |


### List all of the libraries imported by a given binary (recursive)
```bash
wo lslib test-directory/libbase.so -l ./test-directory/ -o csv
```

```
Libraries
libc.so.6
ld-linux-armhf.so.3
libglibc_bridge.so
libc++.so.1
librt.so.1
libpthread.so.0
libc++abi.so.1
liblog.so
libdl.so.2
libm.so.6
```
