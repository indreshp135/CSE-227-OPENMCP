
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone

# For Gmail API
import os.path
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Load environment variables from .env file
load_dotenv()

# Define the scopes for the Gmail API
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

app = FastAPI()

class Email(BaseModel):
    to: str
    subject: str
    body: str

class ReadEmailResponse(BaseModel):
    subject: str
    body: str
    attachments: List[str]
    timestamp: datetime

def get_gmail_service():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            print("Credentials refreshed")
        else:
            credentials_path = os.getenv("CREDENTIALS_PATH")
            if not credentials_path or not os.path.exists(credentials_path):
                raise FileNotFoundError(
                    "credentials.json not found. Please follow these steps to get it:"
                    "1. Go to https://console.developers.google.com/ and create a new project."
                    "2. Enable the Gmail API for your project."
                    "3. Create OAuth 2.0 credentials for a 'Desktop app'."
                    "4. Download the credentials.json file and place it in the root directory of this project."
                )
            flow = InstalledAppFlow.from_client_secrets_file(
                credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    service = build('gmail', 'v1', credentials=creds)
    return service

@app.post("/send-email")
async def send_email(email: Email):
    """
    Sends an email using the Gmail API.
    """
    try:
        service = get_gmail_service()
        message = (service.users().messages().send(
            userId="me",
            body=create_message(email.to, email.subject, email.body)
        ))
        message.execute()
        return {"message": "Email sent successfully!"}
    except HttpError as error:
        raise HTTPException(status_code=500, detail=f"An error occurred: {error}")

def create_message(to, subject, message_text):
    """Create a message for an email.

    Args:
      to: Email address of the receiver.
      subject: The subject of the email message.
      message_text: The text of the email message.

    Returns:
      An object containing a base64url encoded email object.
    """
    message = {
        'raw': base64.urlsafe_b64encode(
            f"To: {to}\r\n"
            f"Subject: {subject}\r\n"
            f"\r\n"
            f"{message_text}".encode()
        ).decode()
    }
    return message

class ReadEmailRequest(BaseModel):
    sender: str
    last_n: int
    time_limit_days: Optional[int] = None

@app.post("/read-emails", response_model=List[ReadEmailResponse])
async def read_emails(request: ReadEmailRequest):
    sender = request.sender
    last_n = request.last_n
    time_limit_days = request.time_limit_days
    """
    Reads the last N emails from a particular sender.
    """
    try:
        service = get_gmail_service()
        # Call the Gmail API
        query = f'from:{sender}'
        if time_limit_days:
            after_date = (datetime.now() - timedelta(days=time_limit_days)).strftime('%Y/%m/%d')
            query += f' after:{after_date}'

        results = service.users().messages().list(userId='me', q=query, maxResults=last_n).execute()
        messages = results.get('messages', [])

        if not messages:
            return []

        emails = []
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            payload = msg['payload']
            headers = payload['headers']
            subject = next(header['value'] for header in headers if header['name'] == 'Subject')
            date_str = next(header['value'] for header in headers if header['name'] == 'Date')
            # Parsing the date string can be complex due to different formats.
            # This is a simplified example and might need a more robust solution.
            try:
                timestamp = datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S %z')
            except ValueError:
                timestamp = datetime.strptime(date_str, '%d %b %Y %H:%M:%S %z') # another common format

            if 'parts' in payload:
                parts = payload['parts']
                body = ""
                attachments = []
                for part in parts:
                    if part['mimeType'] == 'text/plain':
                        body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    elif 'attachmentId' in part['body']:
                        attachment = service.users().messages().attachments().get(userId='me', messageId=message['id'], id=part['body']['attachmentId']).execute()
                        attachments.append({
                            'filename': part['filename'],
                            'data': attachment['data']
                        })
            else:
                body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')
                attachments = []

            emails.append(ReadEmailResponse(subject=subject, body=body, attachments=[att['filename'] for att in attachments], timestamp=timestamp))
        
        return emails

    except HttpError as error:
        raise HTTPException(status_code=500, detail=f"An error occurred: {error}")

