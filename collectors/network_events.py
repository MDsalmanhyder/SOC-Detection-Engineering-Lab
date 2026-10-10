"""
Network Telemetry Collector.
Collects Zeek, Suricata, and network flow security telemetry.
"""

import os
from typing import Generator, List, Union, Dict, Any
from normalizer.parsers import NetworkLogParser
from normalizer.schema import NormalizedEvent


class NetworkEventCollector:
    def __init__(self, parser: NetworkLogParser = None):
        self.parser = parser or NetworkLogParser()

    def collect_from_file(self, filepath: str) -> Generator[NormalizedEvent, None, None]:
        """Stream events from a network log file (JSONL or Zeek TSV)."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Network log file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                event = self.parser.parse(line)
                if event:
                    yield event

    def collect_from_records(self, records: List[Union[str, Dict[str, Any]]]) -> List[NormalizedEvent]:
        events = []
        for record in records:
            event = self.parser.parse(record if isinstance(record, str) else str(record))
            if event:
                events.append(event)
        return events
