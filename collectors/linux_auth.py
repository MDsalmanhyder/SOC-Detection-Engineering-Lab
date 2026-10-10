"""
Linux Authentication Log Collector.
Reads /var/log/auth.log or synthetic auth streams and yields normalized events.
"""

import os
from typing import Generator, List, Union
from normalizer.parsers import LinuxAuthParser
from normalizer.schema import NormalizedEvent


class LinuxAuthCollector:
    def __init__(self, parser: LinuxAuthParser = None):
        self.parser = parser or LinuxAuthParser()

    def collect_from_file(self, filepath: str) -> Generator[NormalizedEvent, None, None]:
        """Stream events from an auth.log file on disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Auth log file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                event = self.parser.parse(line)
                if event:
                    yield event

    def collect_from_lines(self, lines: List[str]) -> List[NormalizedEvent]:
        """Parse an in-memory list of auth log lines."""
        events = []
        for line in lines:
            event = self.parser.parse(line)
            if event:
                events.append(event)
        return events
