# FindSAN - Find Subject Alternative Names (SANs)

FindSAN is a Python tool that helps you discover Subject Alternative Names (SANs) for a given list of domains. It can be useful for identifying additional subdomains associated with a domain.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Options](#options)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Installation

To use FindSAN, you'll need Python 3.7 or later installed on your system.

1. Clone the repository:

```sh
   git clone https://github.com/richabehl/findsan.git
```

2. Navigate to the project directory:

```sh
cd findsan
```

3. Install the required dependencies:

```sh
pip3 install -r requirements.txt
```


## Usage

Run the FindSAN tool from the command line with the following command:

```sh
python3 findsan.py [options]
```


## Options

- `-u`, `--url`: Single URL to check.
- `-l`, `--list`: Path to a file containing a list of URLs.
- `-o`, `--output`: Path to save the plain output.
- `-a`, `--all`: Enable 'all' mode, which finds all SANs.
- `-s`, `--same`: Enable 'same' mode, which finds SANs with the same parent domain.
- `--max-retries`: Maximum retries for failed connections (default: 3).
- `--timeout`: Socket timeout in seconds (default: 5).
- `--custom-port`: Custom port for checking SSL certificates (default: 443).
- `--verbose`: Enable verbose mode.

## Examples

1. Find all SANs for a single URL:

```sh
python3 findsan.py -u example.com -a
```

2. Find SANs with the same parent domain for a list of URLs:

```sh
python3 findsan.py -l domains.txt -s
```

3. Save the results to a file:

```sh
python3 findsan.py -u example.com -o output.txt
```

## Contributing

Contributions are welcome! If you have any improvements or bug fixes, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
