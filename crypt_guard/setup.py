from setuptools import setup, find_packages

setup(
    name='crypt_guard',
    version='0.1.0',
    description='A Python module for cryptographic operations using crypt_guard_py.',
    author='Your Name',
    author_email='your.email@example.com',
    url='https://github.com/yourusername/crypt_guard',  # Update with your URL
    packages=find_packages(),
    install_requires=[
        'crypt_guard_py',  # Add any other dependencies your module requires
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.11',
)
