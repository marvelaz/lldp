from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional

class Settings(BaseSettings):
    """Simple flat settings class - no nested structures or attribute assignments"""

    # === Database Settings ===
    database_path: str = Field(default="./data/topology.db", env="DATABASE_PATH")

    # === Monitoring Settings ===
    monitor_interval_minutes: int = Field(default=15, env="MONITOR_INTERVAL_MINUTES")
    alert_threshold: int = Field(default=3, env="ALERT_THRESHOLD")

    # === FortiGate/FortiSwitch Device Settings ===
    fgt_devices: str = Field(..., env="FGT_DEVICES")
    fgt_username: str = Field(..., env="FGT_USERNAME")
    fgt_password: str = Field(..., env="FGT_PASSWORD")
    fgt_port: int = Field(default=22, env="FGT_PORT")

    # === Email Notification Settings ===
    email_enabled: bool = Field(default=False, env="EMAIL_ENABLED")
    email_host: str = Field(default="", env="EMAIL_HOST")
    email_port: int = Field(default=587, env="EMAIL_PORT")
    email_username: str = Field(default="", env="EMAIL_USERNAME")
    email_password: str = Field(default="", env="EMAIL_PASSWORD")
    email_from: str = Field(default="", env="EMAIL_FROM")
    email_to: str = Field(default="", env="EMAIL_TO")

    # === NetBox Integration (Optional) ===
    netbox_url: Optional[str] = Field(default="", env="NETBOX_URL")
    netbox_token: Optional[str] = Field(default="", env="NETBOX_TOKEN")

    # === Logging Settings ===
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: str = Field(default="./logs/topology_monitor.log", env="LOG_FILE")

    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()

# Helper functions for backward compatibility (if needed)
def get_database_path():
    return settings.database_path

def get_email_config():
    return {
        'enabled': settings.email_enabled,
        'host': settings.email_host,
        'port': settings.email_port,
        'username': settings.email_username,
        'password': settings.email_password,
        'from_email': settings.email_from,
        'to_emails': settings.email_to
    }

def get_fortigate_devices():
    device_ips = settings.fgt_devices.split(',')
    devices = []
    for ip in device_ips:
        devices.append({
            'ip': ip.strip(),
            'username': settings.fgt_username,
            'password': settings.fgt_password,
            'port': settings.fgt_port,
            'name': f'device-{ip.strip().replace(".", "-")}'
        })
    return devices
