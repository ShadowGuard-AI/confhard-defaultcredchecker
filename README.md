![One skeleton key turned in the lock of a panelled oak door close up, the rest of the bunch soft behind in the hand, candle warm light on iron and brass](intro-banner.png)

# confhard-DefaultCredChecker

Title block: the name above is set in BhuTuka Expanded One in deep green on a pale mud plate, as a depth marker on a sounding line. The cone mark below stands beside this first heading only. No credential value appears anywhere in this document; credential type names and behaviours only.

![One heavy iron ring of old skeleton keys with varied bits hanging against a plain oak door, brass and iron keys overlapping in a bunch](logo.png)

![A hand working through a heavy ring of skeleton keys at a panelled oak door in a dim hall, one key turned in the lock and the rest of the bunch waiting in the fist, candle warm light on iron and brass](banner.png)

![The seep field in three bands: the trench edge still, bubbles rising from the cone vents and fading, clam shells opening a fraction and closing, and one crab crossing the near band at walking pace](scene.svg)

![Major separator](sep-heavy.svg)

# confhard-DefaultCredChecker

Checks common configuration files (e.g., `config.ini`, `.env`, common database connection files) and running processes for default or weak credentials. Uses a built-in dictionary of common credentials and regular expressions to identify potential vulnerabilities. Findings name the matched default credential, which is public dictionary material, but the Line Content and Command Line fields are shown with every other value shaped token masked, so a non-default password sharing the line does not print in clear. - Focused on Automates the hardening of system and application configurations based on defined policies. Reads configuration files (e.g., YAML, JSON) and uses predefined rules (e.g., CIS benchmarks) to identify and remediate insecure settings. Provides tools to validate configuration changes and generate reports on compliance. It focuses on automation, not vulnerability detection. It should not alter the system or application without confirmation.

## Install

> Field log note: the masking rule. A matched dictionary value stays visible in the Value field of its own finding; every other value shaped token on that line is masked.

![Minor separator](sep-light.svg)

`git clone https://github.com/ShadowStrikeHQ/confhard-defaultcredchecker`

## Usage

> Field log note: A Missing File Fails the Scan. A configured file that does not exist marks the scan as failed and the run ends at exit 1.

![Minor separator](sep-light.svg)

`./confhard-defaultcredchecker [params]`

## Parameters

> Field log note: the exact case rule. A process listed under a different capitalisation is not checked.

![Minor separator](sep-light.svg)

- `-h`: Show help message and exit

- `-c`: Path to the YAML configuration file.

- `-v`: No description provided

## License

> Field log note: an invalid pattern ends the run at exit 1 before any file is scanned.

![Minor separator](sep-light.svg)

Copyright (c) ShadowStrikeHQ

![Major separator](sep-heavy.svg)

## Facts from the code, stated in the prose

This record names: username and password, YAML, files list, whole token, psutil, UTF 8, masked, exit 1, exit 0, verbose.
