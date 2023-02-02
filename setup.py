from setuptools import setup

packages = ["tronpy", "tronpy.keys", "tronpy.providers"]

package_data = {"": ["*"]}

install_requires = [
    "base58",
    "coincurve",
    "eth_abi>=4.0.0a,<5.0.0",
    "httpx",
    "pycryptodome<4",
    "requests",
]

setup_kwargs = {
    "name": "tronpy",
    "version": "0.2.6",
    "description": "TRON Python client library",
    "long_description": open("README.md").read(),
    "long_description_content_type": "text/markdown",
    "author": "andelf",
    "author_email": "andelf@gmail.com",
    "maintainer": None,
    "maintainer_email": None,
    "url": "https://github.com/andelf/tronpy",
    "packages": packages,
    "package_data": package_data,
    "install_requires": install_requires,
    "python_requires": ">=3.7",
}


setup(**setup_kwargs)
