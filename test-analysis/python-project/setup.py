from setuptools import setup, find_packages

setup(
    name="test-python-project",
    version="1.0.0",
    description="Test Python project for TypoSentinel multi-language analysis",
    author="Test Author",
    author_email="test@example.com",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "numpy>=1.24.3",
        "django>=4.2.0",
        "pandas>=2.0.3",
        "reqeusts>=2.30.0",  # Suspicious typosquatting
        "numpyy>=1.24.0",    # Suspicious typosquatting
        "djnago>=4.1.0",     # Suspicious typosquatting
    ],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)