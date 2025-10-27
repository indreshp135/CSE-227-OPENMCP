from fastmcp import FastMCP
from pydantic import BaseModel
from typing import List, Optional
import requests
import json

mcp = FastMCP("gmail")

class Email(BaseModel):
    to: str
    subject: str
    body: str

@mcp.tool()
def send_email(email: Email):
    """
    Sends an email by making a POST request to the gmail_fastapi_server.
    """
    response = requests.post("http://127.0.0.1:8000/send-email", json=email.dict())
    return response.json()

@mcp.tool()
def read_emails(sender: str, last_n: int, time_limit_days: Optional[int] = None):
    """
    Reads emails by making a POST request to the gmail_fastapi_server.
    """
    response = requests.post("http://127.0.0.1:8000/read-emails", json={
        "sender": sender,
        "last_n": last_n,
        "time_limit_days": time_limit_days
    })
    return response.json()

if __name__ == "__main__":
    mcp.run()