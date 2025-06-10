# Duplicate Function Finder

A Python tool to find and report duplicate function definitions across Python and C# projects. 

## Features

- Finds functions with identical code/names across your project
- Supports both Python and C# code files
- Supports recursive directory scanning
- Detailed reports showing exactly where duplications occur
- Option to ignore function names when finding duplicates
- Saves reports to file or displays on console
- Can be used as a Python module or command-line tool

## Installation

### Using pip (recommended)

```bash
pip install git+https://github.com/selodesigns/DuplicateFinder.git
```

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/selodesigns/DuplicateFinder.git
   cd DuplicateFinder
   ```

2. Install the package:
   ```bash
   pip install -e .
   ```

## Usage

### Command Line

After installing, you can use the tool from anywhere:

```bash
# Basic usage - scan current directory
findduplicates

# Scan a specific directory
findduplicates /path/to/your/project

# Save report to a file in the scanned directory
findduplicates /path/to/your/project -o duplicate_report.txt

# Find functions with identical code but different names too
findduplicates /path/to/your/project -i

# Get more verbose output
findduplicates /path/to/your/project -v

# Scan only Python files
findduplicates /path/to/your/project --python-only

# Scan only C# files
findduplicates /path/to/your/project --csharp-only
```

### Options

- `directory`: Directory to scan (default: current directory)
- `-o, --output`: Output file to save report (defaults to stdout)
- `-i, --ignore-names`: Consider functions with identical code but different names as duplicates
- `-v, --verbose`: Print verbose information
- `--python-only`: Only scan Python (.py) files
- `--csharp-only`: Only scan C# (.cs) files

## Example Output

```
Found 3 sets of duplicate functions:

--------------------------------------------------------------------------------
Duplicate #1: 'process_data'
Found in 2 locations:
  - module1/utils.py (lines 10-25)
  - module2/processor.py (lines 45-60)

Function code:
```python
def process_data(data):
    # Function implementation
    return processed_data
```
--------------------------------------------------------------------------------
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
