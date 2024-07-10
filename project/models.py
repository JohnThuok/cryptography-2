#models.py
from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Initialize SQLAlchemy and Migrate
db = SQLAlchemy()
migrate = Migrate()

# Define contacts table for many-to-many relationship
contacts = db.Table('contacts',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('contact_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    extend_existing=True  # Prevents redefinition error
)

# Define User model
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    public_key = db.Column(db.String(500))  # Adding public_key field for encryption
    private_key = db.Column(db.String(500))  # Adding private_key field for decryption

    # Relationships for messages sent and received
    sent_messages = db.relationship('Message', back_populates='sender', lazy=True, foreign_keys='Message.sender_id')
    received_messages = db.relationship('Message', back_populates='recipient', lazy=True, foreign_keys='Message.recipient_id')

    # Define contacts relationship for many-to-many
    contacts = db.relationship(
        'User',
        secondary=contacts,
        primaryjoin='User.id == contacts.c.user_id',
        secondaryjoin='User.id == contacts.c.contact_id',
        backref=db.backref('contacted_by', lazy='dynamic'),
        lazy=True
    )

# Define Message model
class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    plaintext_content = db.Column(db.Text)  # Adding plaintext_content field for storing unencrypted message
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationships with back_populates
    sender = db.relationship('User', back_populates='sent_messages', foreign_keys=[sender_id])
    recipient = db.relationship('User', back_populates='received_messages', foreign_keys=[recipient_id])
