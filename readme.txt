RiskForge Platform

RiskForge is a vulnerability management platform designed to help organisations identify, prioritise, and remediate security vulnerabilities across their systems.

The platform integrates asset management, vulnerability scanning, risk scoring, ticketing, and AI-assisted analysis into a single web-based interface. It is designed as a modular system and relies on an external scanner host for vulnerability detection.

Features:
Asset discovery and management
Vulnerability scanning using multiple tools
Risk-based prioritisation (custom RiskForge scoring)
Automatic ticket generation from findings
Role-Based Access Control (RBAC)
AI-powered vulnerability explanation and remediation guidance
System health monitoring
Dashboard with real-time security posture overview

Technology Stack:
Backend: Flask (Python)
Database: MySQL / MariaDB
Scanning Tools: GVM (OpenVAS), Nmap, Nikto, Nuclei, testssl.sh, Gobuster, sqlmap, enum4linux
AI Integration: Groq API
Frontend: Jinja2 + custom CSS

Requirements:
Python 3.10+
MySQL / MariaDB
Linux environment (recommended)
Scanner host (Kali Linux recommended)
Network connectivity between app and scanner

Installation:
Clone repository

git clone https://github.com/leggd/riskforge.git

cd riskforge

Create virtual environment

python -m venv venv
source venv/bin/activate

Install dependencies

pip install -r requirements.txt

Environment Configuration:
Create a .env file in the project root:

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

Database Setup:
Create database:
mysql -u root -p
CREATE DATABASE riskforge;

Option 1 (Recommended):

mysql -u root -p riskforge < db_dump.txt

Option 2:

mysql -u root -p riskforge < db_schema.txt

Password Setup (Important):
Passwords are stored using bcrypt.

Generate hash:

python

import bcrypt
bcrypt.hashpw(b"password", bcrypt.gensalt())

Insert into database:

INSERT INTO users (username, password_hash, role)
VALUES ('admin', '<bcrypt_hash>', 'ADMIN');

Running the Application

flask run --host=0.0.0.0

Access:

http://localhost:5000

Scanner Host Setup (CRITICAL):
RiskForge requires a dedicated scanner host (recommended: Kali Linux).

The scanner host must:
Be on the same network as the application
Have SSH access enabled
Have all required tools installed
Be reachable from the application
Required Tools (Scanner Host)

Install:

sudo apt update

sudo apt install -y
nmap
nikto
gobuster
sqlmap
enum4linux
nuclei

Nuclei Setup

nuclei -update-templates

testssl.sh Setup

git clone https://github.com/drwetter/testssl.sh.git

chmod +x testssl.sh/testssl.sh

Ensure script path is accessible.

GVM (OpenVAS) Setup:
Install and configure GVM on the scanner host.

Ensure:
gvmd is running
OpenVAS scanner is operational
API (GMP) is accessible
Default port: 9390

Verify:
gvm-check-setup

Remote Scanner Script

The system uses a remote Python script (defined by REMOTE_SCRIPT).

Ensure:
Script exists on scanner host
Correct permissions (executable)
SSH user can execute it
Example Network Setup

RiskForge App: 10.0.96.x
Scanner Host: 10.0.96.x

Both systems must be reachable.

Scanner Behaviour
Flask app triggers scans
SSH connects to scanner host
Remote script executes tools
Results are returned and processed
Findings converted into tickets
Project Structure

/services - AI, scanning, auth logic
/templates - HTML templates
/static - CSS
/routes - Flask routes
db.py - Database logic
app.py - Entry point

Common Issues:
No scan results:
Check scanner host connectivity
Verify tools installed
Check SSH credentials

GVM not working:
Ensure port 9390 accessible
Check gvmd running

Login fails:
Ensure bcrypt hash used
Plain passwords will not work

AI not working:
Verify GROQ_API_KEY set
Check internet connectivity

Notes:
Flask server is for development only
Production requires Gunicorn + Nginx
SSL verification disabled for internal use