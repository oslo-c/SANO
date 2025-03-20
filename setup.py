from setuptools import setup

setup(
    name="SANO",
    version="1.0.0",
    description="A user-friendly OSINT tool",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="oslo-c4",
    author_email="oslo-c4@protonmail.com",
    url="https://github.com/oslo-c4/SANO",  # update as needed
    py_modules=["main"],
    entry_points={
        "console_scripts": [
            "sano=main:main",
        ],
    },
    install_requires=[
        "requests",
        "python-dotenv",
        "phonenumbers",
        "beautifulsoup4",
        "pystyle",
        # add any additional dependencies your project needs
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
