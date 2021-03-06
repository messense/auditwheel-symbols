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
❯ auditwheel-symbols --help
auditwheel-symbols 0.1.4

USAGE:
    auditwheel-symbols [OPTIONS] <FILE>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -m, --manylinux <manylinux>     [possible values: 1, 2010, 2014, 2_24]

ARGS:
    <FILE>

❯ auditwheel-symbols --manylinux 2014 ~/Downloads/rjieba-0.1.5-cp36-abi3-manylinux2010_x86_64.whl
rjieba/rjieba.abi3.so is manylinux2014 compliant.

❯ auditwheel-symbols --manylinux 1 ~/Downloads/rjieba-0.1.5-cp36-abi3-manylinux2010_x86_64.whl
rjieba/rjieba.abi3.so is not manylinux1 compliant because it links the following forbidden libraries:
libc.so.6	offending symbols:  memcpy@@GLIBC_2.14
```

## License

This work is released under the MIT license. A copy of the license is provided in the [LICENSE](../LICENSE) file.
