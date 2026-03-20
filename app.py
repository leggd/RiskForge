import os
from flask import Flask
from dotenv import load_dotenv
from services.scanner_worker import start_worker
from routes import auth_bp, dashboard_bp, assets_bp, scans_bp, tickets_bp

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Set flask secret key for secure signed in sessions
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# Register login and logout routes
app.register_blueprint(auth_bp)

# Register dashboard route
app.register_blueprint(dashboard_bp)

# Register asset list, individual detail, update and retire routes
app.register_blueprint(assets_bp)

# Register scan page get and post routes, scan detail, scan starting routes
app.register_blueprint(scans_bp)

# Register ticket list, detail and update routes
app.register_blueprint(tickets_bp)

if __name__ == "__main__":
    # Start scan findings parsing worker in the background
    start_worker()
    app.run(debug=False)