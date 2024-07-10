#otp.py
import random

def generate_otp():
    return str(random.randint(100000, 999999))

def verify_otp(user_input_otp, generated_otp):
    return user_input_otp == generated_otp
