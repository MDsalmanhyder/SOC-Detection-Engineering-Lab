"""
Windows & Sysmon Telemetry Collector.
Collects process creation, registry modifications, network events, and security audit logs.
"""

import os
import json
from typing import Generator, List, Union, Dict, Any
from normalizer.parsers import WindowsSysmonParser
from normalizer.schema import NormalizedEvent


class SysmonCollector:
    def __init__(self, parser: WindowsSysmonParser = None):
        self.parser = parser or WindowsSysmonParser()

    def collect_from_jsonl(self, filepath: str) -> Generator[NormalizedEvent, None, None]:
        """Stream events from a JSONL file."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Sysmon JSONL file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                event = self.parser.parse(line_str)
                if event:
                    yield event

    def collect_from_records(self, records: List[Union[str, Dict[str, Any]]]) -> List[NormalizedEvent]:
        """Parse in-memory raw records."""
        events = []
        for record in records:
            raw_str = json.dumps(record) if isinstance(record, dict) else str(record)
            event = self.parser.parse(raw_str)
            if event:
                events.append(event)
        return events
