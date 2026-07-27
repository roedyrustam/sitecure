import httpx
from typing import List, Dict, Any

class WebhookNotifier:
    """
    Automated Security Webhook Notifier: Sends instant alert notifications to Slack,
    Discord, or custom webhooks when Critical or High severity vulnerabilities are detected.
    """
    @staticmethod
    async def send_vulnerability_alert(webhook_url: str, target_name: str, target_url: str, findings: List[Dict[str, Any]]):
        if not webhook_url or not findings:
            return

        critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")

        payload = {
            "text": f"🚨 *SiteCure Security Alert!* 🚨\n"
                    f"*Target Asset:* {target_name} ({target_url})\n"
                    f"*Summary:* Found {len(findings)} total vulnerabilities ({critical_count} CRITICAL, {high_count} HIGH).\n"
                    f"Visit SiteCure Dashboard to view PoC evidence & AI code patches."
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(webhook_url, json=payload)
        except Exception:
            pass
