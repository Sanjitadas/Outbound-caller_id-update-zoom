# auth.py

from flask import Blueprint, request, render_template, redirect, url_for, session, flash
from models import User, SessionLocal
from functools import wraps

auth_bp = Blueprint("auth", __name__)

# ------------------ Helpers ------------------
def login_required(admin_only=False):
    """Decorator for routes that require login. Set admin_only=True for admin routes."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("auth.login"))
            if admin_only and not session.get("is_admin"):
                flash("Admin access required.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapper
    return decorator


def log_login_event(user, success=True, ip=None):
    db = SessionLocal()
    try:
        from models import LoginLog
        log = LoginLog(user_id=user.id, email=user.email, success=success, ip_address=ip)
        db.add(log)
        db.commit()
    finally:
        db.close()


# ------------------ Routes ------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == email).first()
            if user and user.password == password:
                # login success
                session["user_id"] = user.id
                session["email"] = user.email
                session["is_admin"] = user.is_admin
                log_login_event(user, success=True, ip=request.remote_addr)
                return redirect(url_for("dashboard.dashboard_home"))
            else:
                flash("Invalid email or password.", "danger")
                if user:
                    log_login_event(user, success=False, ip=request.remote_addr)
        finally:
            db.close()
    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("auth.login"))









































