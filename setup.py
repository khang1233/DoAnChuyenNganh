from setuptools import setup, find_packages

setup(
    name="cti-defense",
    version="1.0.0",
    description="Autonomous CTI & Agentic Defense Framework",
    packages=find_packages(),
    py_modules=["apply_to_project"],
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.20.0",
        "requests>=2.28.0",
        "pydantic>=2.0.0",
        "python-docx>=1.0.0",
        "pyyaml>=6.0"
    ],
    entry_points={
        "console_scripts": [
            "cti = cti_core.system_ctl:cli_entrypoint",
            "cti-defense = cti_core.system_ctl:cli_entrypoint",
        ],
    },
    python_requires=">=3.10",
)
