import boto3
from botocore.exceptions import ClientError

# 📌 Configure AWS Region here
REGION = "us-east-1"  # e.g., "us‑east‑1"

# Initialize the DynamoDB resource
dynamodb = boto3.resource("dynamodb", region_name= REGION)

# DynamoDB table name for users
USERS_TABLE = "Users"  # Make sure this matches your actual table name

def get_users_table():
    """
    Return the DynamoDB Users table resource.
    """
    return dynamodb.Table(USERS_TABLE)

def save_user(email: str, hashed_password: str, full_name: str = None, contact: str = None):
    """
    Save a user to the DynamoDB Users table.
    - email: Primary key for the user (must be unique)
    - hashed_password: password hash
    - full_name: optional full name
    - contact: optional contact number
    """
    table = get_users_table()

    # Item to save
    item = {
        "email": email,
        "password": hashed_password
    }

    # Optional additional fields
    if full_name:
        item["fullName"] = full_name
    if contact:
        item["contact"] = contact

    try:
        table.put_item(Item=item)
        return True
    except ClientError as e:
        print(f"[DynamoDB] Error saving user: {e}")
        return False

def fetch_user(email: str):
    """
    Fetch a user by email from the Users table.
    Returns the user item (dict) if found, else None.
    """
    table = get_users_table()

    try:
        response = table.get_item(Key={"email": email})
        return response.get("Item")
    except ClientError as e:
        print(f"[DynamoDB] Error fetching user: {e}")
        return None
