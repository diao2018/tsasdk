"""
tsasdk-python - RFC 3161 compliant TSA client with SM3 support
"""

from setuptools import setup, find_packages

setup(
    name="tsasdk",
    version="1.0.0",
    description="RFC 3161 compliant HTTP client for trusted timestamp authority, with SM3 support",
    author="Rick Diao",
    author_email="rickxy@qq.com",
    url="https://github.com/diao2018/tsasdk",
    license="Apache-2.0",
    packages=find_packages(),
    python_requires=">=3.6",
    install_requires=[],
    extras_require={
        "sm3": ["gmssl"],
    },
    keywords=["timestamp", "rfc3161", "tsa", "sm3", "signature"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
    ],
)
