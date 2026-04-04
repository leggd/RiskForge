import os
from flask import Flask, render_template, session, redirect
from dotenv import load_dotenv
from services.scanner_worker import start_worker
from routes import auth_bp, dashboard_bp, assets_bp, scans_bp, tickets_bp, users_bp, audit_bp

# Load environment variables from .env file
load_dotenv()

# Initialise Flask instance
app = Flask(__name__)

# Configure secret key for session management
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# Redirect to login page if user visits '/' root or dashboard if logged in
@app.route("/")
def index():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")

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

# Register users routes (list, add)
app.register_blueprint(users_bp)

# Register audit route
app.register_blueprint(audit_bp)

# Define 403 error page route
@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html", error=error.description), 403

# Define 404 error page route
@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404

# Define 500 error page route
@app.errorhandler(500)
def server_error(error):
    return render_template("500.html", error=error.description), 500

if __name__ == "__main__":
    # Start background worker for scan processing
    start_worker()

    # Run Flask application
    app.run(
    host="127.0.0.1",
    port=5000,
    debug=True,
    ssl_context=("cert.pem", "key.pem")
)