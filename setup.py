from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="neonguard",
    version="1.0.0",
    author="NeonGuard Team",
    description="Lightweight Python security library — command blocking, process monitoring, AI prompt security, rate limiting, sandboxing, and anomaly detection.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/neonguard",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "psutil>=5.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords="security guard monitoring rate-limiting sandbox ai-safety prompt-injection",
)
