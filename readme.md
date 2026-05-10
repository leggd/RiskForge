# RiskForge

RiskForge is a full-stack vulnerability management and security operations platform designed to help organisations identify, prioritise and remediate security vulnerabilities across enterprise environments.

The platform integrates asset management, vulnerability scanning, risk scoring, ticketing workflows and AI-assisted analysis into a unified web interface. RiskForge was designed as a modular system using a dedicated remote scanner host for distributed vulnerability assessment operations.

---

# Project Overview

This project was developed as part of a university enterprise team project.

## My Primary Contributions

* Full-stack application development
* Backend Flask development
* Database integration and query logic
* Authentication and RBAC implementation
* Vulnerability scanning integration
* AI-assisted remediation functionality
* Ticketing workflow implementation
* System architecture and debugging
* Scanner host integration and automation
* Frontend feature integration and UI functionality

---

# Demonstration Videos

The following narrated demonstrations showcase the core functionality and architecture of the RiskForge platform.

## 1. Vulnerability Scanning Demo

[![Scan Demo](https://img.youtube.com/vi/He8pirDpnNY/0.jpg)](https://www.youtube.com/watch?v=He8pirDpnNY)

## 2. AI Analysis Demo

[![AI Analysis Demo](https://img.youtube.com/vi/9RPTM5JoL04/0.jpg)](https://www.youtube.com/watch?v=9RPTM5JoL04)

## 3. Ticket Management Demo

[![Ticket Demo](https://img.youtube.com/vi/v8bhIYwOegM/0.jpg)](https://www.youtube.com/watch?v=v8bhIYwOegM)

## 4. Asset Management Demo

[![Asset Management Demo](https://img.youtube.com/vi/PoDzsIuP4c4/0.jpg)](https://www.youtube.com/watch?v=PoDzsIuP4c4)

## 5. Authentication & RBAC Demo

[![Authentication Demo](https://img.youtube.com/vi/j2OBDMN9C8M/0.jpg)](https://www.youtube.com/watch?v=j2OBDMN9C8M)

## 6. Audit Logging Demo

[![Audit Log Demo](https://img.youtube.com/vi/lqW68M0Yxks/0.jpg)](https://www.youtube.com/watch?v=lqW68M0Yxks)

---

# Documentation

Additional project documentation is available in the `/docs` directory.

## Included Documentation

* Technical report
* Industry presentation
* UML diagrams
* System design documentation

---

# Features

* Asset discovery and management
* Vulnerability scanning orchestration
* Risk-based vulnerability prioritisation
* Automatic ticket generation from findings
* Role-Based Access Control (RBAC)
* AI-powered vulnerability explanation and remediation guidance
* System health monitoring
* Dashboard with real-time security posture overview
* Remote scanner host integration
* Audit logging and activity tracking

---

# Technology Stack

## Backend

* Flask (Python)

## Database

* MySQL / MariaDB

## Frontend

* Jinja2
* HTML/CSS
* JavaScript

## Security & Scanning Tools

* GVM (OpenVAS)
* Nmap
* Nikto
* Nuclei
* testssl.sh
* Gobuster
* sqlmap
* enum4linux

## AI Integration

* Groq API

---

# System Architecture

RiskForge operates using a distributed scanning architecture:

1. Flask application handles orchestration and frontend logic
2. SSH communication connects to a dedicated scanner host
3. Remote scanning tools execute on the scanner system
4. Results are processed and normalised
5. Findings are converted into actionable tickets
6. AI-assisted analysis provides remediation guidance

---

# Project Structure

```text
/services     -> AI, scanning and authentication logic
/templates    -> HTML templates
/static       -> CSS, JavaScript and frontend assets
/routes       -> Flask route handlers
/docs         -> Reports, presentations and UML diagrams
db.py         -> Database integration
app.py        -> Application entry point
```

---

# Requirements

* Python 3.10+
* MySQL / MariaDB
* Linux environment (recommended)
* Dedicated scanner host (Kali Linux recommended)
* Network connectivity between application and scanner host

---

# Installation

## Clone Repository

```bash
git clone https://github.com/leggd/riskforge.git
cd riskforge
```

## Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Environment Configuration

Create a `.env` file in the project root:

```env
SECRET_KEY=your_secret_key

DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=riskforge
DB_PORT=3306

GROQ_API_KEY=your_groq_api_key

SCANNER_HOST=10.0.96.x

GVM_PORT=9390
GVM_USERNAME=your_gvm_username
GVM_PASSWORD=your_gvm_password

KALI_USER=your_kali_username
KALI_PASS=your_kali_password
REMOTE_SCRIPT=/home/kali/scanner.py
```

---

# Database Setup

## Create Database

```sql
CREATE DATABASE riskforge;
```

## Import Database

### Recommended

```bash
mysql -u root -p riskforge < db_dump.txt
```

### Alternative

```bash
mysql -u root -p riskforge < db_schema.txt
```

---

# Running the Application

```bash
flask run --host=0.0.0.0
```

Application available at:

```text
http://localhost:5000
```

---

# Scanner Host Setup

RiskForge requires a dedicated remote scanner host.

## Recommended Environment

* Kali Linux
* SSH enabled
* Same network accessibility as Flask host

## Required Tools

```bash
sudo apt update

sudo apt install -y \
nmap \
nikto \
gobuster \
sqlmap \
enum4linux \
nuclei
```

---

# GVM (OpenVAS) Setup

Ensure:

* `gvmd` is running
* OpenVAS scanner operational
* GMP accessible on port 9390

Verify setup:

```bash
gvm-check-setup
```

---

# Common Issues

## No Scan Results

* Verify scanner host connectivity
* Confirm required tools installed
* Check SSH credentials

## GVM Issues

* Ensure port 9390 accessible
* Verify `gvmd` service status

## Login Problems

* Ensure bcrypt hashes used
* Plain-text passwords are unsupported

## AI Integration Issues

* Verify `GROQ_API_KEY`
* Confirm internet connectivity

---

# Notes

* Flask server is intended for development use only
* Production deployments should use Gunicorn + Nginx
* SSL verification may be disabled for internal testing environments
* This repository contains a redacted version of the project with sensitive information removed
