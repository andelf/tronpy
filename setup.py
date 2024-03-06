import importlib

from setuptools import setup

spec = importlib.util.spec_from_file_location("version", "tronpy/version.py")
version_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(version_module)

packages = ["tronpy", "tronpy.keys", "tronpy.providers", "tronpy.hdwallet"]

package_data = {"": ["*"]}

install_requires = [
    "base58",
    "coincurve",
    "eth-abi>=5.0.0,<6.0.0",
    "httpx",
    "pycryptodome<4",
    "requests",
]

extras_hdwallet = {"mnemonic": ["mnemonic==0.20"]}

setup_kwargs = {
    "name": "tronpy",
    "version": version_module.VERSION,
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
    "extras_require": extras_hdwallet,
    "python_requires": ">=3.8",
}


setup(**setup_kwargs)
