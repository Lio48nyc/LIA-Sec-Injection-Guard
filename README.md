
# LIA-Sec Injection Guard

## Overview

LIA-Sec Injection Guard is a Python-based security module designed to detect and defend against prompt injection attacks.

It implements layered input screening, security checks, and detection mechanisms to help protect AI applications from malicious or manipulated instructions.

## Features

- Prompt injection detection
- Input normalization
- Layered security screening
- Risk scoring and verdict classification
- Security findings and audit logging

## Project Structure

```text
LIA-Sec-Injection-Guard/
├── injection_guard_v2.py
├── main.py
├── requirements.txt
├── README.md
└── LICENSE
```

## Requirements

- Python 3.10 or later
- No external dependencies required if using Python standard-library modules only.

## Installation

Clone the repository:

```bash
git clone https://github.com/Lio48nyc/LIA-Sec-Injection-Guard.git
```

Navigate into the project directory:

```bash
cd LIA-Sec-Injection-Guard
```

## Usage

Run the interactive demonstration:

```bash
python main.py
```

Enter text to screen for potential prompt injection indicators.

Type `exit` to close the application.

## Security Notice

Detection mechanisms are defensive screening layers, not a complete guarantee against prompt injection.

Production deployments should also implement least-privilege tool access, provenance tracking, egress controls, and human approval for sensitive actions.

## License

See the LICENSE file for usage and distribution terms.
