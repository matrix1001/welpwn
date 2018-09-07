from setuptools import setup, find_packages

setup(
    name='welpwn',
    version='0.8',
    description='Designed for eliminating dull work while pwning',
    license='GPL',
    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),
    #install_requires=['pwntools'],
    author='matrix1001',
    author_email='simplematrix1001@gmail.com',
    keywords=['pwn', 'pwntool'],
    url=''
)
