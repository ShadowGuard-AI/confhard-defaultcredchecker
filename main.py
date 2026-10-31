import argparse
import logging
import os
import re
import sys
import yaml
from schema import Schema, SchemaError, Use, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default credentials dictionary
DEFAULT_CREDENTIALS = {
    "username": ["admin", "user", "root", "test"],
    "password": ["password", "123456", "admin", "test", "password123", "changeme"]
}

# Configuration file schema
CONFIG_SCHEMA = Schema({
    'files': [Use(str)],
    Optional('processes'): [Use(str)],
    Optional('credentials'): {
        Optional('username'): [Use(str)],
        Optional('password'): [Use(str)]
    },
    Optional('regex'): [Use(str)]
})


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Checks configuration files and processes for default/weak credentials."
    )
    parser.add_argument(
        "-c", "--config", help="Path to the YAML configuration file.", required=True
    )
    parser.add_argument(
        "-v", "--verbose", help="Enable verbose output (debug logging).", action="store_true"
    )
    return parser.parse_args()


def load_config(config_file):
    """
    Loads the configuration from a YAML file.
    Validates the configuration file.
    Handles file not found and invalid YAML errors.

    Args:
        config_file (str): Path to the YAML configuration file.

    Returns:
        dict: The configuration data as a dictionary, or None if an error occurred.
    """
    try:
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)

        # Validate the config using the schema
        CONFIG_SCHEMA.validate(config)
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML in {config_file}: {e}")
        return None
    except SchemaError as e:
        logging.error(f"Invalid configuration file: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred loading the config: {e}")
        return None


def _credential_hits(line, credentials):
    # Whole-token matching, not substring matching. The substring
    # version flagged the word "test" inside "latest" on an ordinary
    # line, and flagged a "db_password" key name as a password value.
    # Config values sit next to =, : or whitespace, so token edges
    # are the right test for this file shape.
    hits = []
    lowered = line.lower()
    for credential_type, credential_values in credentials.items():
        for credential in credential_values:
            pattern = r"(?<![A-Za-z0-9_])" + re.escape(credential.lower()) + r"(?![A-Za-z0-9_])"
            if re.search(pattern, lowered):
                hits.append((credential_type, credential))
    return hits


def _mask_value_tokens(text, keep_values=()):
    """Mask value shaped tokens in a line before it is printed.

    The matched default credential itself is public dictionary
    material and stays visible in the Value field. Anything else
    that sits in a value position (after an = or : sign, inside
    quotes, or after a password style flag on a command line) is
    replaced with ***, because a non-default password sharing the
    line used to print in clear, once per hit.
    """
    keep = {str(value).lower() for value in keep_values}

    def _mask_token(token):
        return token if token.lower() in keep else "***"

    def _after_sign(match):
        prefix, quote, token = match.group(1), match.group(2) or "", match.group(3)
        return f"{prefix}{quote}{_mask_token(token)}{quote}"

    masked = re.sub(r"([=:]\s*)([\"']?)([^\s\"',;]+)\2", _after_sign, text)

    def _quoted(match):
        quote, token = match.group(1), match.group(2)
        return f"{quote}{_mask_token(token)}{quote}"

    masked = re.sub(r"([\"'])([^\s\"']+)\1", _quoted, masked)

    def _after_flag(match):
        return f"{match.group(1)} ***"

    masked = re.sub(
        r"((?:--?(?:password|passwd|pwd|secret|token|api[-_]?key))\s+)[^\s]+",
        _after_flag, masked, flags=re.IGNORECASE)
    return masked


def check_file_for_credentials(file_path, credentials, regex_patterns):
    """
    Checks a file for default/weak credentials.

    Args:
        file_path (str): The path to the file to check.
        credentials (dict): A dictionary of default credentials to check for.
        regex_patterns (list): A list of regex patterns to search for.

    Returns:
        list: A list of findings (lines containing potential credentials).
    """
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, 1):
                for credential_type, credential in _credential_hits(line, credentials):
                    findings.append(
                        f"File: {file_path}, Line: {line_number}, Credential Type: {credential_type}, Value: {credential.strip()}, Line Content: {_mask_value_tokens(line.strip(), keep_values=[credential])}"
                    )
                for regex in regex_patterns:
                    if regex.search(line):
                        findings.append(
                            f"File: {file_path}, Line: {line_number}, Regex Match: {regex.pattern}, Line Content: {_mask_value_tokens(line.strip())}"
                        )
    except FileNotFoundError:
        logging.warning(f"File not found: {file_path}")
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
    return findings


def check_process_for_credentials(process_name, credentials, regex_patterns):
    """
    Checks for the existence of a process by name and if found,
    searches its command line arguments (if accessible) for sensitive information.
    """
    try:
        import psutil
    except ImportError:
        logging.error("psutil is required to check processes.  Please install it with 'pip install psutil'")
        return []

    findings = []
    for proc in psutil.process_iter(['name', 'cmdline']):
        if proc.info['name'] == process_name:
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                for credential_type, credential in _credential_hits(cmdline, credentials):
                    findings.append(f"Process: {process_name}, Credential Type: {credential_type}, Value: {credential.strip()}, Command Line: {_mask_value_tokens(cmdline.strip(), keep_values=[credential])}")

                for regex in regex_patterns:
                    if regex.search(cmdline):
                        findings.append(f"Process: {process_name}, Regex Match: {regex.pattern}, Command Line: {_mask_value_tokens(cmdline.strip())}")

            except psutil.AccessDenied:
                logging.warning(f"Access denied when trying to read command line for process: {process_name}")
            except Exception as e:
                logging.error(f"Error processing process {process_name}: {e}")

    return findings


def main():
    """
    Main function to execute the credential checking tool.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    config = load_config(args.config)
    if not config:
        sys.exit(1)

    files_to_check = config.get("files", [])
    processes_to_check = config.get("processes", [])
    custom_credentials = config.get("credentials", {})
    raw_patterns = config.get("regex", [])

    # Compile the custom patterns once, before any scanning. Compiled
    # per line, an invalid pattern raised inside the per-file loop,
    # aborted that file at its first line, and the run then reported
    # "no exposures" for a file it had barely opened.
    regex_patterns = []
    for pattern in raw_patterns:
        try:
            regex_patterns.append(re.compile(pattern, re.IGNORECASE))
        except re.error as e:
            logging.error(f"Invalid regex in configuration: {pattern!r}: {e}")
            sys.exit(1)

    # Merge default credentials with custom credentials, if provided.
    # Copy the lists, not just the dict: a shallow copy shares the
    # default lists, and extend() would then mutate the module level
    # defaults for every later call in the same process.
    merged_credentials = {key: list(values) for key, values in DEFAULT_CREDENTIALS.items()}
    for cred_type, cred_values in custom_credentials.items():
        if cred_type in merged_credentials:
            merged_credentials[cred_type].extend(cred_values)
        else:
            merged_credentials[cred_type] = list(cred_values)

    all_findings = []
    scan_failed = False

    # Check files
    for file_path in files_to_check:
        logging.info(f"Checking file: {file_path}")
        if not os.path.isfile(file_path):
            # A configured file that is not there was never scanned.
            # It used to be a warning under a "no exposures" result
            # and exit 0, so a mistyped path passed as a clean check.
            scan_failed = True
        findings = check_file_for_credentials(file_path, merged_credentials, regex_patterns)
        all_findings.extend(findings)

    # Check processes
    for process_name in processes_to_check:
        logging.info(f"Checking process: {process_name}")
        findings = check_process_for_credentials(process_name, merged_credentials, regex_patterns)
        all_findings.extend(findings)

    if all_findings:
        print("Potential credential exposures found:")
        for finding in all_findings:
            print(finding)
    else:
        print("No potential credential exposures found.")

    if scan_failed:
        logging.error("One or more configured files could not be checked.")
        sys.exit(1)

    if all_findings:
        sys.exit(1)  # Exit with an error code if findings were found
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()