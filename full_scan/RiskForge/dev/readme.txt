DEPLOYMENT_GUIDE.txt

Everything is step-by-step, assuming:

Ubuntu Server = RiskForge

Kali Linux = GVM

Same internal network

No prior experience

RISKFORGE FULL DEPLOYMENT GUIDE
Ubuntu Server (RiskForge) + Kali Linux (GVM)
ARCHITECTURE OVERVIEW

You need TWO machines:

Ubuntu Server 22.04 → Runs RiskForge Flask application

Kali Linux → Runs GVM (Greenbone Vulnerability Manager)

Both machines MUST:

Be on the same network (e.g. 10.0.96.x)

Be able to ping each other

=====================================================================
PART 1 — SETUP KALI LINUX (GVM SERVER)

Login to Kali.

Update system:

sudo apt update
sudo apt upgrade -y

Install GVM:

sudo apt install gvm -y

Run initial setup (this takes time):

sudo gvm-setup

IMPORTANT:
At the end it will show:

Admin username

Admin password

SAVE THESE. YOU NEED THEM FOR RISKFORGE.

Start GVM:

sudo gvm-start

Check everything is OK:

sudo gvm-check-setup

All checks should say OK.

Allow GVM to listen on network (not just localhost):

Edit config:

sudo nano /etc/gvm/gsad.conf

Find:
--listen=127.0.0.1

Change to:
--listen=0.0.0.0

Save file.

Restart GVM:

sudo gvm-stop
sudo gvm-start

Get Kali IP address:

ip a

Look for something like:
inet 10.0.96.32

WRITE THIS DOWN.
This is your GVM IP.

GVM should now be running on:

10.0.96.32:9390

=====================================================================
PART 2 — SETUP UBUNTU SERVER (RISKFORGE)

Login to Ubuntu server.

Update system:

sudo apt update
sudo apt upgrade -y

Install required software:

sudo apt install python3 python3-venv python3-pip mysql-server git -y

Secure MySQL:

sudo mysql_secure_installation

Set a root password.

Create database and user:

sudo mysql -u root -p

Inside MySQL:

CREATE DATABASE riskforge;

CREATE USER 'riskforge_user'@'localhost' IDENTIFIED BY 'password123';

GRANT ALL PRIVILEGES ON riskforge.* TO 'riskforge_user'@'localhost';

FLUSH PRIVILEGES;

EXIT;

Import your database schema:

sudo mysql -u root -p
USE riskforge;

Now paste your full schema SQL (users, assets, audit_log, scans).

EXIT;

Create project directory:

sudo mkdir -p /opt/riskforge
sudo chown $USER:$USER /opt/riskforge
cd /opt/riskforge

Clone project:

git clone https://github.com/leggd/RiskForge.git
 .
cd dev

Create Python virtual environment:

python3 -m venv venv
source venv/bin/activate

Install dependencies:

pip install flask pymysql python-dotenv bcrypt gvm-tools cryptography

Create .env file:

nano .env

Paste:

SECRET_KEY=supersecretkey123
DB_HOST=localhost
DB_USER=riskforge_user
DB_PASSWORD=password123
DB_NAME=riskforge
DB_PORT=3306

Save file.

Configure GVM connection in app.py

nano app.py

Find:

HOST = "10.0.96.32"
USERNAME = "admin"
PASSWORD = "your_password_here"

Replace:

HOST with Kali IP

USERNAME and PASSWORD with values from gvm-setup

Save file.

Create admin user

Activate venv if not already:

source venv/bin/activate

Start Python:

python3

Run:

import bcrypt
print(bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode())

Copy the output hash.

Exit Python.

Now insert into MySQL:

sudo mysql -u root -p
USE riskforge;

INSERT INTO users (username, password_hash, role)
VALUES ('admin', 'PASTE_HASH_HERE', 'ADMIN');

EXIT;

=====================================================================
PART 3 — RUN RISKFORGE

Inside /opt/riskforge/dev:

source venv/bin/activate
python3 app.py

You should see:

Running on http://0.0.0.0:5000

Open browser:

http://<ubuntu_server_ip>:5000/login

Login with:

username: admin
password: admin123

=====================================================================
PART 4 — TEST FULL SYSTEM

Login

Add an asset (e.g. metasploitable IP)

Go to Scans

Click Start Scan

Refresh page

Watch progress update

When finished → Status becomes Done

=====================================================================
NETWORK TROUBLESHOOTING

From Ubuntu server:

ping <kali_ip>

Test port:

nc -zv <kali_ip> 9390

If connection fails:

Check firewall on Kali

Check GVM running

Check IP address

=====================================================================
OPTIONAL — RUN WITH GUNICORN (MORE PROFESSIONAL)

Inside project folder:

pip install gunicorn

Run:

gunicorn -w 3 -b 0.0.0.0:8000 app:app

Access:

http://<ubuntu_ip>:8000

=====================================================================
FINAL CHECKLIST

[ ] Kali GVM installed and running
[ ] Kali listening on 0.0.0.0
[ ] Ubuntu can ping Kali
[ ] MySQL database created
[ ] Tables imported
[ ] .env configured
[ ] Admin user created
[ ] GVM credentials correct
[ ] Start Scan works
[ ] Progress updates