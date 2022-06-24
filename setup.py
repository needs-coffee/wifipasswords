import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as f:
    required = f.read().splitlines()

with open("wifipasswords/__init__.py", "r") as f:
    for line in f:
        if line.startswith("__version__"):
            ver = line.split("=")[1].strip(' "')


setuptools.setup(
    name="wifipasswords",
    version=ver,
    author="Joe Campbell",
    description="Retrieve and save all WiFi networks and passwords on the device. Cross platform windows, linux, macOS",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/needs-coffee/wifipasswords",
    project_urls={
        "Bug Tracker": "https://github.com/needs-coffee/wifipasswords/issues",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Natural Language :: English",
        "Topic :: Utilities",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Networking",
    ],
    packages=["wifipasswords"],
    install_requires=required,
    licence="GPLv3",
    keywords=["wifipasswords", "passwords", "wifi", "networks", "dns", "wpasupplicant"],
    python_requires=">=3.6",
    entry_points={"console_scripts": ["wifipasswords = wifipasswords.__main__:cli"]},
)
