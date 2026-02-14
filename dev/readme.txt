# Riskforge – Ubuntu Server Deployment Guide

This guide explains how to deploy the Riskforge development build
to an Ubuntu Server (22.04 recommended).

---

note: There is already a database created 'riskforge_dev', username: 'riskforge_dev' and password: 'dbadmin' this is just if you want to recreate it in your own environment

## 1. System Requirements

- Ubuntu Server 22.04
- Python 3.10+
- MySQL Server
- Git

---

## 2. Install Required System Packages

Update system:

```bash
sudo apt update && sudo apt upgrade -y

Install Python and MySQL:

sudo apt install python3 python3-venv python3-pip mysql-server git -y

3. Clone the Repository
git clone <your-repo-url>
cd riskforge

4. Create Python Virtual Environment
python3 -m venv venv
source venv/bin/activate

5. Install Python Dependencies
pip install -r requirements.txt

6. Configure Environment Variables
Create a .env file in the project root:

nano .env

Example .env file:
SECRET_KEY=change_this_to_a_random_secure_string
DB_HOST=127.0.0.1
DB_USER=riskforge_user
DB_PASSWORD=strongpassword
DB_NAME=riskforge
DB_PORT=3306
Save and exit.

⚠ Do NOT commit .env to Git.

7. Setup MySQL Database
Login to MySQL:

sudo mysql
Create database and user:

CREATE DATABASE riskforge;

CREATE USER 'riskforge_user'@'localhost' IDENTIFIED BY 'strongpassword';

GRANT ALL PRIVILEGES ON riskforge.* TO 'riskforge_user'@'localhost';

FLUSH PRIVILEGES;
EXIT;

8. Create Users Table
Start Flask temporarily:

python app.py

Visit in browser:

http://<server-ip>:5000/setup_users_table
Then create admin user:

http://<server-ip>:5000/seed_admin
After admin is created, remove or comment out those routes.

9. Run Application (Development Mode)
python app.py
Application will run on:

http://<server-ip>:5000
10. Production (Recommended)
For production, use Gunicorn:

Install:

pip install gunicorn
Run:

gunicorn -w 4 -b 0.0.0.0:8000 app:app
Access via:

http://<server-ip>:8000
For full production setup, use:

Nginx reverse proxy

HTTPS (Let's Encrypt)

Systemd service

Security Notes
Remove /setup_users_table and /seed_admin routes after use.

Never expose development mode publicly.

Ensure firewall allows required ports only.

Always use strong SECRET_KEY and database password.

© Riskforge Enterprise Project


---

# Example `.env.example` (Commit This One)

Create a file called:
# Riskforge – Ubuntu Server Deployment Guide

This guide explains how to deploy the Riskforge development build
to an Ubuntu Server (22.04 recommended).

---

## 1. System Requirements

- Ubuntu Server 22.04
- Python 3.10+
- MySQL Server
- Git

---

## 2. Install Required System Packages

Update system:

```bash
sudo apt update && sudo apt upgrade -y
Install Python and MySQL:

sudo apt install python3 python3-venv python3-pip mysql-server git -y
3. Clone the Repository
git clone <your-repo-url>
cd riskforge
4. Create Python Virtual Environment
python3 -m venv venv
source venv/bin/activate
5. Install Python Dependencies
pip install -r requirements.txt
6. Configure Environment Variables
Create a .env file in the project root:

nano .env
Example .env file:

SECRET_KEY=your_secret_key_here
DB_HOST=127.0.0.1
DB_USER=riskforge_dev
DB_PASSWORD=dbadmin
DB_NAME=riskforge_dev
DB_PORT=3306

Save and exit.

⚠ Do NOT commit .env to Git.

7. Setup MySQL Database
Login to MySQL:

sudo mysql
Create database and user:

CREATE DATABASE riskforge;

CREATE USER 'riskforge_user'@'localhost' IDENTIFIED BY 'strongpassword';

GRANT ALL PRIVILEGES ON riskforge.* TO 'riskforge_user'@'localhost';

FLUSH PRIVILEGES;
EXIT;

8. Create Users Table
Start Flask temporarily:

python app.py
Visit in browser:

http://<server-ip>:5000/setup_users_table
Then create admin user:

http://<server-ip>:5000/seed_admin
After admin is created, remove or comment out those routes.

9. Run Application (Development Mode)
python app.py

Application will run on:
http://<server-ip>:5000



