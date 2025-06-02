import re
from dateutil import parser as date_parser
from django.utils import timezone
from typing import Optional, Dict, Any


class BaseLogParser:
    """Abstract base class for log parsers"""

    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse a log line into a structured dictionary

        Args:
            log_line: Raw log line to parse

        Returns:
            Dictionary with parsed fields or None if parsing fails
        """
        raise NotImplementedError


class AuthLogParser(BaseLogParser):
    """Parser for SSH/auth logs with timezone awareness"""

    # Compiled regex pattern for SSH auth logs
    pattern = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        r'\s+\w+\s+sshd\[(?P<pid>\d+)\]:\s+'
        r'(?P<action>\w+)\s+(?P<status>\w+)\s+'
        r'for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse an SSH authentication log line

        Handles:
        - Timezone conversion (naive to aware)
        - Field extraction
        - Data validation
        """
        match = self.pattern.match(log_line.strip())
        if not match:
            return None

        try:
            # Parse timestamp and make it timezone-aware
            naive_datetime = date_parser.parse(match.group('timestamp'))
            aware_datetime = timezone.make_aware(naive_datetime)

            return {
                'timestamp': aware_datetime,
                'source': 'auth',
                'user': match.group('user'),
                'ip_address': match.group('ip'),
                'action': match.group('action').lower(),  # Normalize to lowercase
                'status': match.group('status').lower(),  # Normalize to lowercase
                'details': {
                    'pid': int(match.group('pid')),
                    'raw_log': log_line.strip()  # Keep original for reference
                }
            }
        except (ValueError, TypeError) as e:
            # Log parsing errors if needed
            return None


class ParserFactory:
    """Factory for creating and managing log parsers"""

    # Registry of available parsers
    parsers = {
        'auth': AuthLogParser(),
        # Add more parsers here as needed
        # 'apache': ApacheLogParser(),
        # 'syslog': SyslogParser(),
    }

    @classmethod
    def get_parser(cls, log_type: str) -> Optional[BaseLogParser]:
        """Get a parser instance by log type

        Args:
            log_type: Type of log to parse (e.g., 'auth', 'apache')

        Returns:
            Configured parser instance or None if not found
        """
        return cls.parsers.get(log_type.lower())  # Case-insensitive lookup

    @classmethod
    def register_parser(cls, log_type: str, parser: BaseLogParser):
        """Register a new parser type"""
        cls.parsers[log_type.lower()] = parser