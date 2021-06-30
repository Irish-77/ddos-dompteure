from app import db
from .ip_log import IPLog

class IPEntry(db.Model):
    __tablename__ = 'ip_entries'
    ip = db.Column(db.String(15), primary_key=True)
    status = db.Column(db.Enum('whitelist', 'blacklist', 'unclassified', name='ip_status'), nullable=False)
    log_entries = db.relationship('IPLog', backref='ip_entry', lazy='dynamic')