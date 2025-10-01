from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="ipds-py",
    version="0.1.0dev",
    author="Juan Lee",
    author_email="juan.lee@sigmd.com",
    description="IP Describe Library - Comprehensive IP information lookup tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sigmd-com/ipds-py",
    packages=find_packages(),
    python_requires=">=3.12",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
    },
    entry_points={
        "console_scripts": [
            "ipds=ipds.cli:main",
        ],
    },
)
