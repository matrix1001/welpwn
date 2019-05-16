from setuptools import setup, find_packages

setup(
    name="welpwn",
    version="0.97",
    description='Designed for eliminating dull work while pwning',
    packages=find_packages(exclude=['tests', 'expired']),
    install_requires=['pwntools'],
    include_package_data=True,
    author='matrix1001',
    author_email='simplematrix1001@gmail.com',
    keywords=['pwn', 'pwntool'],
)
