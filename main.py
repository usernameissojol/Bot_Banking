import logging
import random
import string
import sqlite3
import os
import re
from telethon import TelegramClient, events, Button
from telethon.tl.functions.channels import GetParticipantsRequest
from telethon.tl.types import ChannelParticipantsSearch
import hashlib

# Setup logging
logging.basicConfig(level=logging.INFO)

# Your API ID and hash from my.telegram.org
api_id = "26887272"  # Replace with your API ID
api_hash = 'eb04e1a500856df3405d58964197e29a'  # Replace with your API hash
bot_token = '8172592311:AAHB84xXTD2Odh5ODhWN7Pqg2_YrW72Sy5M'  # Replace with your actual bot token

# Create the client and connect
client = TelegramClient('bot', api_id, api_hash).start(bot_token=bot_token)

# Connect to SQLite database (create if it doesn't exist)
conn = sqlite3.connect('banking_system.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users 
             (uid TEXT PRIMARY KEY, name TEXT, email TEXT UNIQUE, phone TEXT UNIQUE, password TEXT)''')
conn.commit()

def generate_uid():
    """Generates a unique 10-digit UID for users."""
    return ''.join(random.choices(string.digits, k=10))

def hash_password(password):
    """Hashes the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def validate_email(email):
    """Validates the email format."""
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def validate_phone(phone):
    """Validates the phone format (10 digits)."""
    return re.match(r"^\d{10}$", phone)

# User states to keep track of where they are in the process
user_states = {}

# Define the required channel username (replace with your actual channel's username)
required_channel = 'DNAFARM_BOT'  # For example: 'my_channel'

# Helper function to check if the user has joined the required channel
async def is_user_in_channel(client, user_id):
    try:
        # Get the participants from the required channel
        participants = await client(GetParticipantsRequest(
            channel=required_channel,
            filter=ChannelParticipantsSearch(''),
            offset=0,
            limit=100,
            hash=0
        ))

        # Check if the user is in the list of participants
        for participant in participants.users:
            if participant.id == user_id:
                return True
        return False
    except Exception as e:
        logging.error(f"Error checking channel membership: {e}")
        return False

# Handler for the /start command
@client.on(events.NewMessage(pattern='/start'))
async def start(event):
    user_id = event.sender_id

    # Check if the user has joined the required channel
    if await is_user_in_channel(client, user_id):
        # If the user is in the channel, show registration and login options
        buttons = [
            [Button.text('💻 Register', resize=True)],
            [Button.text('🔑 Login', resize=True)]
        ]
        await event.respond('Welcome to the Banking Bot! Please choose an option:', buttons=buttons)
        logging.info(f'Start command received from {user_id}')
    else:
        # If the user hasn't joined the channel, show the prompt with a button to re-check
        await event.respond(f'🚫 You need to join the [DNA Farm](https://t.me/{required_channel}) before registering.',
                            buttons=[Button.text('Check if Joined', resize=True)], parse_mode='markdown')
        logging.info(f'User {user_id} prompted to join the required channel')

# Handle registration and joined check
@client.on(events.NewMessage)
async def handle_registration(event):
    sender_id = event.sender_id

    # Handle the "Check if Joined" button
    if event.raw_text == "Check if Joined":
        if await is_user_in_channel(client, sender_id):
            # User has now joined the channel, show the main menu
            buttons = [
                [Button.text('💻 Register', resize=True)],
                [Button.text('🔑 Login', resize=True)]
            ]
            await event.respond('🎉 You have successfully joined the channel! Please choose an option:', buttons=buttons)
        else:
            # User still hasn't joined the channel
            await event.respond(f'🚫 You still need to join the [official channel](https://t.me/{required_channel}) before registering.',
                                buttons=[Button.text('Check if Joined', resize=True)], parse_mode='markdown')

    # Start the registration process
    if event.raw_text == "💻 Register":
        if await is_user_in_channel(client, sender_id):
            user_states[sender_id] = {"step": "name"}
            await event.respond('📝 Please provide your full name:')
            logging.info(f'Registration started by {sender_id}')
        else:
            await event.respond(f'🚫 You need to join the [official channel](https://t.me/{required_channel}) before registering.', parse_mode='markdown')

    # Collect user's name
    elif sender_id in user_states and user_states[sender_id]["step"] == "name":
        name = event.raw_text.strip()
        if not name:
            await event.respond("🚫 This is not valid. Please provide your full name:")
            return

        user_states[sender_id]["name"] = name
        user_states[sender_id]["step"] = "email"
        await event.respond('📧 Please provide your email:')

    # Collect user's email
    elif sender_id in user_states and user_states[sender_id]["step"] == "email":
        email = event.raw_text.strip()
        if not validate_email(email):
            await event.respond("🚫 Invalid email format. Please provide a valid email:")
            return
        
        # Check for existing email
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        if c.fetchone() is not None:
            await event.respond("🚫 Email already exists. Please use a different email:")
            return

        user_states[sender_id]["email"] = email
        user_states[sender_id]["step"] = "phone"
        await event.respond('📞 Please provide your phone number (10 digits):')

    # Collect user's phone number
    elif sender_id in user_states and user_states[sender_id]["step"] == "phone":
        phone = event.raw_text.strip()
        if not validate_phone(phone):
            await event.respond("🚫 Invalid phone number. Please provide a valid 10-digit phone number:")
            return
        
        # Check for existing phone
        c.execute('SELECT * FROM users WHERE phone = ?', (phone,))
        if c.fetchone() is not None:
            await event.respond("🚫 Phone number already exists. Please use a different number:")
            return

        user_states[sender_id]["phone"] = phone
        user_states[sender_id]["step"] = "password"
        await event.respond('🔒 Please provide a password (minimum 6 characters):')

    # Collect user's password
    elif sender_id in user_states and user_states[sender_id]["step"] == "password":
        password = event.raw_text.strip()
        if len(password) < 6:
            await event.respond("🚫 Password too short. Please provide a password with at least 6 characters:")
            return

        # Store the password in user states for confirmation
        user_states[sender_id]["password"] = password
        await event.respond(f'📋 Please confirm your details:\n'
                            f'🗒️ Name: {user_states[sender_id]["name"]}\n'
                            f'📧 Email: {user_states[sender_id]["email"]}\n'
                            f'📞 Phone: {user_states[sender_id]["phone"]}\n'
                            f'🔒 Password: {password}\n'
                            f'Please choose an option:',
                            buttons=[
                                [Button.text('✅ Confirm', resize=True), Button.text('❌ Cancel', resize=True)]
                            ])

        user_states[sender_id]["step"] = "confirm"

    # Handle confirmation
    elif sender_id in user_states and user_states[sender_id]["step"] == "confirm":
        if event.raw_text == "✅ Confirm":
            hashed_password = hash_password(user_states[sender_id]["password"])
            uid = generate_uid()

            # Store user data in the database
            try:
                with conn:
                    c.execute("INSERT INTO users (uid, name, email, phone, password) VALUES (?, ?, ?, ?, ?)",
                              (uid, user_states[sender_id]["name"], user_states[sender_id]["email"],
                               user_states[sender_id]["phone"], hashed_password))
                await event.respond(f'🎉 Registration successful! Your UID is: {uid}\n\n'
                                    '🔔 **Read This Notice Attentively:**\n\n'
                                    f'🚨 This is Your Account Number: {uid}\n'
                                    '🚫 Don\'t share your Account Number or password with anyone.\n'
                                    '💾 Secretly save this and don\'t forget it.\n'
                                    '🆘 If you face any problem or need any help, contact Support Team. (@DNAFARM_BOT).\n',
                                    buttons=[ [Button.text('OK', resize=True)] ],
                                    parse_mode='markdown')
                logging.info(f'User registered: {user_states[sender_id]["name"]}, UID: {uid}')
            except sqlite3.Error as e:
                logging.error(f"Database error: {e}")
                await event.respond("🚫 An error occurred during registration. Please try again later.")
            finally:
                user_states.pop(sender_id, None)  # Clear the user's registration state

        elif event.raw_text == "❌ Cancel":
            await event.respond("❌ Registration cancelled. You can start again by typing /start.")
            user_states.pop(sender_id, None)  # Clear the user's registration state

   # Handle OK button
    # Handle OK button
    if sender_id in user_states and event.raw_text == "OK":
    # Get the bot's ID
        bot_id = (await client.get_me()).id

    # Fetch all messages sent by the bot in the chat
    bot_messages = await client.get_messages(event.chat_id, from_user=bot_id)

    # Delete all messages sent by the bot
    if bot_messages:
        await client.delete_messages(event.chat_id, [msg.id for msg in bot_messages])

    # Clear the user's state to reset the bot for the user
    user_states.pop(sender_id, None)

    # Go back to the login page
    buttons = [
        [Button.text('💻 Register', resize=True)],
        [Button.text('🔑 Login', resize=True)]
    ]
    await event.respond('Please choose an option to proceed:', buttons=buttons)



# Start the bot
client.run_until_disconnected()
