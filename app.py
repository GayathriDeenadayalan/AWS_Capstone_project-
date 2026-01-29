from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import boto3
import os

app = Flask(__name__)

# --- Config & AWS Setup ---
app.secret_key = os.getenv("FLASK_SECRET_KEY", "aws-ai-marketing-secret")

# AWS region & clients
REGION = os.getenv("AWS_REGION", "us-east-1")
dynamodb = boto3.resource('dynamodb', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)

# DynamoDB tables (must exist)
u_table = dynamodb.Table('Users')
c_table = dynamodb.Table('Campaigns')
a_table = dynamodb.Table('Admin')

# Optional SNS Topic ARN (set in environment)
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:539247489202:aws_ai_marketing_platform")

def send_sns_notification(subject, message):
    if not SNS_TOPIC_ARN:
        return
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    except Exception as e:
        print("SNS Publish failed:", e)


# --- Helper Functions ---
def get_user(email):
    response = users_table.get_item(Key={'email': email})
    return response.get('Item')

def add_user(email, password, name):
    users_table.put_item(Item={
        'email': email,
        'password': password,
        'name': name,
        'created_at': datetime.utcnow().isoformat(),
        'role': 'user'
    })


# --- Auth Decorators ---
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('user_email'):
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get('role') != 'admin':
            return redirect(url_for('admin_login'))
        return view(*args, **kwargs)
    return wrapped


# --- Public Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email'].lower()
        password = request.form['password']
        user = get_user(email)
        # Admin login check
        admin = admin_table.get_item(Key={'email': email}).get('Item')

        # Check user
        if user and check_password_hash(user.get('password', ''), password):
            session['user_email'] = email
            session['role'] = user.get('role', 'user')
            session['user_name'] = user.get('name')
            return redirect(url_for('home'))

        # Check admin
        if admin and check_password_hash(admin.get('password', ''), password):
            session['user_email'] = email
            session['role'] = 'admin'
            session['user_name'] = admin.get('name', 'Admin')
            return redirect(url_for('admin_home'))

        flash("Invalid credentials", "error")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form['signupEmail'].lower()
        password = request.form['signupPassword']
        confirm = request.form['confirmPassword']

        if password != confirm:
            flash("Passwords do not match", "error")
            return redirect(url_for("signup"))

        if get_user(email):
            flash("User already exists!", "error")
            return redirect(url_for("signup"))

        hashed = generate_password_hash(password)
        name = request.form.get("fullName", email.split("@")[0])
        add_user(email, hashed, name)

        send_sns_notification("New User Signup", f"{name} ({email}) signed up!")
        flash("Signup successful! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out!", "success")
    return redirect(url_for("login"))


# --- User Pages ---
@app.route("/home")
@login_required
def home():
    return render_template("home.html", user=session.get("user_name"))

@app.route("/dashboard")
@login_required
def dashboard():
    # Fetch campaigns for this user
    items = campaigns_table.scan().get('Items', [])
    user_campaigns = [c for c in items if c.get('created_by') == session.get('user_email')]
    return render_template("dashboard.html", campaigns=user_campaigns)

@app.route("/campaign_history")
@login_required
def campaign_history():
    items = campaigns_table.scan().get('Items', [])
    user_campaigns = [c for c in items if c.get('created_by') == session.get('user_email')]
    return render_template("campaign_history.html", campaigns=user_campaigns)


# --- Campaign Routes ---
@app.route("/create_campaign", methods=["POST"])
@login_required
def create_campaign():
    data = request.form
    campaign_id = f"camp_{int(datetime.utcnow().timestamp())}"
    campaign = {
        "campaign_id": campaign_id,
        "name": data.get("name"),
        "created_by": session.get("user_email"),
        "created_at": datetime.utcnow().isoformat(),
        "status": "active",
        "details": data.get("details", "")
    }
    campaigns_table.put_item(Item=campaign)

    send_sns_notification("Campaign Created", f"{session.get('user_email')} created {data.get('name')}")
    flash("Campaign created!", "success")
    return redirect(url_for("dashboard"))


# --- Admin Pages ---
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form['email'].lower()
        password = request.form['password']
        admin = admin_table.get_item(Key={'email': email}).get('Item')
        if admin and check_password_hash(admin.get('password',''), password):
            session['user_email'] = email
            session['role'] = 'admin'
            session['user_name'] = admin.get('name', 'Admin')
            return redirect(url_for("admin_home"))
        flash("Invalid admin login!", "error")
    return render_template("admin_login.html")

@app.route("/admin_home")
@admin_required
def admin_home():
    users = users_table.scan().get('Items', [])
    campaigns = campaigns_table.scan().get('Items', [])
    return render_template("admin_home.html", users=users, campaigns=campaigns)


# --- Run Server ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


