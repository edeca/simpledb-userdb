import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="simpledb_userdb",
    version="0.0.1",
    author="David Cannings",
    author_email="david@edeca.net",
    description="A simple user database, built on AWS SimpleDB",
    license="Apache Software License",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/edeca/simpledb_userdb",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
    ],
)
