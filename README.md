# SPF2IP-Go

A Go implementation designed to resolve a domain's SPF (Sender Policy Framework) records into a list of IP addresses and CIDR blocks. This project is a remake of and inspired by the original Python-based [SPF2IP by Nathan Dines](https://github.com/nathandines/SPF2IP).

This tool recursively processes SPF records, handling `include` and `redirect` mechanisms, and extracts all authorized IP networks.

## Features

- Resolves SPF records for a given domain.
- Supports both IPv4 and IPv6 resolution (`ip4`, `ip6`, `a`, `mx` mechanisms).
- Handles `include` and `redirect` mechanisms recursively.
- Implements strict redirect logic (a `redirect` overrides preceding mechanisms in the same record).
- Detects and prevents resolution loops and excessive lookups (via include depth limit).
- Outputs all IPs and networks in canonical CIDR notation (e.g., `1.2.3.4/32`, `10.0.0.0/24`), sorted and unique.

## Acknowledgements

This project is a Go remake of the original [SPF2IP (Python) by Nathan Dines](https://github.com/nathandines/SPF2IP). Full credit and thanks to Nathan Dines for the original concept and implementation.

## Installation

### Building from Source
To build the `spf2ip-go` executable from source, follow these steps:

1.  Clone the repository:
    ```bash
    git clone https://github.com/HENNGE/spf2ip-go.git
    cd spf2ip-go
    ```
    
2.  Build the executable:
    ```bash
    go build -o spf2ip-go ./cmd/spf2ip-go/main.go
    ```
    This will create an executable named `spf2ip-go` in the current directory.

### Using Go Modules
If you prefer to use Go modules, you can run the following command to install the package:

```bash
go install github.com/HENNGE/spf2ip-go/cmd/spf2ip-go@latest
```

## CLI Usage

```bash
spf2ip-go --domain <domain_name> [--ip-version <4|6>] [--debug]
```

### Flags

* `--domain <string>`: (Required) The domain for which the SPF records should be resolved.
* `--ip-version <int>`: (Optional) The IP version to extract. Accepts `4` for IPv4 or `6` for IPv6. Defaults to `4`.
* `--debug`: (Optional) Enable debug logging output to stderr. Defaults to `false`.

### Examples

1.  **Get IPv4 addresses for `example.com`:**
    ```bash
    spf2ip-go --domain example.com
    ```

1.  **Get IPv6 addresses for `example.com`:**
    ```bash
    spf2ip-go --domain example.com --ip-version 6
    ```

1.  **Get IPv4 addresses for `example.com` with debug output:**
    ```bash
    spf2ip-go --domain example.com --debug
    ```
