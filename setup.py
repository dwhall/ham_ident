import setuptools

with open("README.rst", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="ham_ident",
    version="0.0.1",
    author="Dean Hall",
    author_email="dean.kc4ksu@gmail.com",
    description="amateur radio operator cryptographic identity and addressing.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/dwhall/ham_ident",
    packages=setuptools.find_packages(),
    python_requires=">=3.5",
    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Topic :: Communications :: Ham Radio",
    ],
)
