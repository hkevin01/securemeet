from setuptools import find_packages, setup

setup(
    name="securemeet",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "cryptography",
        "sounddevice",
        "soundfile",
    ],
    python_requires=">=3.9",
    description="Local-only secure meeting recorder",
    long_description=(
        "SecureMeet is a tiny auditable Python package that records from a local "
        "microphone, encrypts timestamped WAV payloads, and stores protected "
        "metadata in SQLite."
    ),
    long_description_content_type="text/plain",
    license="MIT",
)
