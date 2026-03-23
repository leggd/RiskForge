import os
from flask import Flask
from dotenv import load_dotenv
from services.scanner_worker import start_worker
from routes import auth_bp, dashboard_bp, assets_bp, scans_bp, tickets_bp

# Load environment variables from .env file
load_dotenv()

# Initialise Flask instance
app = Flask(__name__)

# Configure secret key for session management
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# Register authentication routes (login, logout)
app.register_blueprint(auth_bp)

# Register dashboard routes
app.register_blueprint(dashboard_bp)

# Register asset management routes (list, detail, update, retire)
app.register_blueprint(assets_bp)

# Register scan routes (list, start, detail, status)
app.register_blueprint(scans_bp)

# Register ticket routes (list, detail, update)
app.register_blueprint(tickets_bp)

if __name__ == "__main__":
    # Start background worker for scan processing
    start_worker()

    # Run Flask application
    app.run(debug=False)