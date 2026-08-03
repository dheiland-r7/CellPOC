"""Cinterion-specific CatSocks driver configuration."""

PROFILE_IDS = tuple(range(9))  # profiles 0..8; profile 9 reserved
CONNECTION_PROFILE = 1
MAX_PARALLEL_OPENS = 2
TCP_READ_CHUNK = 1500
TCP_WRITE_CHUNK = 1024
UDP_MAX_PAYLOAD = 1024
ACK_TIMEOUT = 8.0
OPEN_TIMEOUT = 12.0
COMMAND_TIMEOUT = 12.0
