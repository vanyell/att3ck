import socket
import threading
import logging

from kinetix.outputs.base import OutputProvider
from kinetix.schemas.base import BaseLogEvent

logger = logging.getLogger(__name__)

# RFC 3164 syslog is line-oriented; frame each message with a trailing
# newline so a stream listener (TCP) can delimit messages the way rsyslog's
# imtcp / Wazuh's remote syslog collector expect.
_MSG_TERMINATOR = b"\n"


class SyslogOutput(OutputProvider):
    """
    Sends each event's existing RFC 3164 representation (BaseLogEvent.to_syslog())
    over the network to a real syslog listener - e.g. a Wazuh manager's
    <remote> syslog collector, or a local rsyslog/syslog-ng instance that a
    Wazuh agent is already tailing.

    This intentionally does not reformat or relabel messages: the Linux
    schemas (sshd/sudo/cron/auditd) already emit text that matches Wazuh's
    default decoders, so no custom ruleset is required on the receiving end.
    """

    def __init__(self, host: str, port: int = 514, protocol: str = "udp"):
        protocol = protocol.lower()
        if protocol not in ("udp", "tcp"):
            raise ValueError(f"Unsupported syslog protocol: {protocol}")

        self.host = host
        self.port = port
        self.protocol = protocol
        self._lock = threading.Lock()
        self._sock = None
        self._connect()

    def _connect(self):
        if self.protocol == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            self._sock = sock

    def write(self, event: BaseLogEvent):
        line = event.to_syslog().encode("utf-8", errors="replace") + _MSG_TERMINATOR
        with self._lock:
            try:
                if self.protocol == "udp":
                    self._sock.sendto(line, (self.host, self.port))
                else:
                    self._sock.sendall(line)
            except OSError as e:
                logger.warning(f"Syslog send to {self.host}:{self.port}/{self.protocol} failed: {e}")
                if self.protocol == "tcp":
                    # Best-effort single reconnect; drop the message on repeated failure.
                    try:
                        self._sock.close()
                    except OSError:
                        pass
                    try:
                        self._connect()
                        self._sock.sendall(line)
                    except OSError as retry_err:
                        logger.warning(f"Syslog reconnect to {self.host}:{self.port} failed: {retry_err}")

    def flush(self):
        pass

    def close(self):
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
