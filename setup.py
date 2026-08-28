from setuptools import setup, find_packages

setup(
    name="solidity-audit-agent",
    version="0.1.0",
    description="Static analysis, fuzzing harness generation, and audit reporting for Solidity smart contracts",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/OffcierCia/tips-solidity-code-auditors",
    python_requires=">=3.10",
    py_modules=["audit_agent"],
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "audit-agent=audit_agent:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
)
