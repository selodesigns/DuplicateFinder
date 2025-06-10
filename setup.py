from setuptools import setup

setup(
    name="duplicatefinder",
    version="1.0.0",
    description="Find duplicate functions across Python files",
    author="Duplicate Function Finder",
    py_modules=["findduplicates"],
    entry_points={
        "console_scripts": [
            "findduplicates=findduplicates:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.6",
)
