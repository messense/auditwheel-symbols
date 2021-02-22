# auditwheel-symbols

[![GitHub Actions](https://github.com/messense/auditwheel-symbols/workflows/CI/badge.svg)](https://github.com/messense/auditwheel-symbols/actions?query=workflow%3ACI)
[![PyPI](https://img.shields.io/pypi/v/auditwheel-symbols.svg)](https://pypi.org/project/auditwheel-symbols)

Find out which symbols are causing auditwheel too-recent versioned symbols error, resolves [pypa/auditwheel#36](https://github.com/pypa/auditwheel/issues/36) .

## Installation

```bash
pip install auditwheel-symbols
```

## Usage

```bash
auditwheel-symbols 0.1.1

USAGE:
    auditwheel-symbols [OPTIONS] <FILE>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -m, --manylinux <manylinux>     [possible values: 1, 2010, 2014, 2_24]

ARGS:
    <FILE>
```

## License

This work is released under the MIT license. A copy of the license is provided in the [LICENSE](../LICENSE) file.
