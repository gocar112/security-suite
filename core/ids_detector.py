"""
IDS detector placeholder.

Live packet capture is intentionally not implemented. This module returns a
structured result so the CLI boots and can be tested without sniffing traffic.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from .logger import get_logger

logger = get_logger(__name__)


class IDSDetector:
    """Threat-detection stub. No live capture, no pcap parsing yet."""

    def detect(
        self,
        interface: Optional[str] = None,
        duration: int = 60,
        pcap_file: Optional[str] = None,
    ) -> Dict[str, Any]:
        logger.info("IDS detect called; live capture is disabled in this build")
        reason = "Live packet capture is not implemented."
        if pcap_file:
            reason = "PCAP path recorded but not parsed: " + str(pcap_file)
        elif interface:
            reason = "Interface " + str(interface) + " requested; live capture is disabled."

        return {
            "timestamp": datetime.now().isoformat(),
            "status": "skipped",
            "interface": interface,
            "duration": duration,
            "pcap_file": pcap_file,
            "detections": [],
            "reason": reason,
        }
