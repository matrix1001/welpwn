from setuptools import setup, find_packages

setup(
    name="pwnContext",
    version="0.1",
    packages=find_packages(exclude=['tests', 'expired']),
    install_requires=['pwntools'],
    include_package_data=True,
)
