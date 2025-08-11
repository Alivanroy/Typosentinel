from setuptools import setup, find_packages

setup(
    name="reqeusts",  # Typo in 'requests'
    version="2.28.1",
    description="HTTP library for Python - FAKE VERSION",
    long_description="A fake version of the popular requests library",
    author="Unknown Author",
    author_email="fake@example.com",
    url="https://github.com/fake-repo/reqeusts",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.7",
    install_requires=[
        "urllib3>=1.21.1,<1.27",
        "certifi>=2017.4.17",
        "charset-normalizer>=2,<3",
        "idna>=2.5,<4",
    ],
    extras_require={
        "security": ["pyOpenSSL>=0.14", "cryptography>=1.3.4"],
        "socks": ["PySocks>=1.5.6,!=1.5.7"],
    },
)