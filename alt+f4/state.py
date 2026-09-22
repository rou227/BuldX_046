"""
state.py - Persistent state container for VantaCore cybersecurity framework.
Thread-safe singleton state holding scan results, threat level metrics, events,
recon details, system key health, and firewall block rules.
"""

import threading
import time

_lock = threading.Lock()

DEFAULT_STATE = {
    "status": "SECURE",
    "severity": 0.0,
    "target": "192.168.1.100",
    "active_threats": [],
    "events": [
        {
            "epoch": int(time.time()),
            "time": time.strftime("%H:%M:%S"),
            "message": "VantaCore engine initialized. Real-time telemetry online.",
            "level": "info",
            "threat_type": "SYSTEM"
        }
    ],
    "categories": [
        {"name": "Port Scanning", "threat_count": 0, "status": "NOMINAL"},
        {"name": "Malware & Engines", "threat_count": 0, "status": "NOMINAL"},
        {"name": "Reputation & Abuse", "threat_count": 0, "status": "NOMINAL"},
        {"name": "Threat Feeds (OTX)", "threat_count": 0, "status": "NOMINAL"},
        {"name": "Geolocation & Org", "threat_count": 0, "status": "NOMINAL"},
        {"name": "Vulnerabilities (NVD)", "threat_count": 0, "status": "NOMINAL"}
    ],
    "system": {
        "demo_mode": True,
        "missing_keys": ["SHODAN_API_KEY", "VT_API_KEY", "ABUSEIPDB_API_KEY"]
    },
    "recon": None,
    "blocked_ips": [
        {
            "rule_id": "RULE-1001",
            "ip": "198.51.100.42",
            "reason": "Suspicious Port Sweep",
            "action_time": "11:20:14",
            "dry_run": True
        }
    ]
}

_state = dict(DEFAULT_STATE)

def get_state():
    with _lock:
        return dict(_state)

def get_status_summary():
    with _lock:
        return {
            "status": _state["status"],
            "severity": _state["severity"],
            "target": _state["target"],
            "active_threats": list(_state["active_threats"]),
            "events": list(_state["events"]),
            "categories": [dict(c) for c in _state["categories"]],
            "system": dict(_state["system"])
        }

def get_recon():
    with _lock:
        if _state["recon"] is None:
            return {"status": "no_scan_yet", "target": _state["target"], "recon": None}
        return {
            "status": "ok",
            "target": _state["target"],
            "recon": _state["recon"]
        }

def get_firewall():
    with _lock:
        return {"blocked_ips": list(_state["blocked_ips"])}

def add_firewall_block(ip, reason, dry_run=True):
    with _lock:
        rule_id = f"RULE-{len(_state['blocked_ips']) + 1001}"
        action_time = time.strftime("%H:%M:%S")
        rule = {
            "rule_id": rule_id,
            "ip": ip,
            "reason": reason,
            "action_time": action_time,
            "dry_run": dry_run
        }
        _state["blocked_ips"].insert(0, rule)
        event_msg = f"Firewall Rule {rule_id}: Blocked {ip} ({'DRY-RUN' if dry_run else 'ACTIVE ENFORCEMENT'}). Reason: {reason}"
        _state["events"].insert(0, {
            "epoch": int(time.time()),
            "time": action_time,
            "message": event_msg,
            "level": "info" if dry_run else "alert",
            "threat_type": "FIREWALL"
        })
        return rule

def update_from_scan(target, verdict, results):
    """
    Persists scan results into state.
    results expected keys: shodan, virustotal, abuseipdb, otx, ipinfo, nvd
    """
    with _lock:
        _state["target"] = target
        _state["recon"] = results
        _state["status"] = verdict.upper() if verdict else "SECURE"
        
        active_threats = []
        
        # Shodan
        shodan = results.get("shodan", {})
        open_ports = shodan.get("open_ports", [])
        vulns = shodan.get("vulns", [])
        port_threats = len(open_ports)
        if vulns:
            active_threats.extend(vulns)

        # VT
        vt = results.get("virustotal", {})
        vt_mal = vt.get("malicious_engines", 0)
        
        # AbuseIPDB
        abuse = results.get("abuseipdb", {})
        abuse_score = abuse.get("abuse_score", 0)
        
        # OTX
        otx = results.get("otx", {})
        pulse_count = otx.get("pulse_count", 0)
        
        # NVD
        nvd = results.get("nvd", {})
        nvd_cve = nvd.get("cve_id", "")
        nvd_score = nvd.get("cvss_score", 0.0)
        if nvd_cve and nvd_cve not in active_threats:
            active_threats.append(nvd_cve)

        # Compute severity (0.0 to 10.0)
        raw_sev = (port_threats * 0.4) + (vt_mal * 1.5) + (abuse_score * 0.06) + (pulse_count * 1.2) + (nvd_score * 0.7)
        severity = round(min(max(raw_sev, 0.0), 10.0), 1)

        _state["severity"] = severity
        _state["active_threats"] = active_threats

        _state["categories"] = [
            {
                "name": "Port Scanning",
                "threat_count": port_threats,
                "status": "ALERT" if port_threats > 3 else ("WARN" if port_threats > 0 else "NOMINAL")
            },
            {
                "name": "Malware & Engines",
                "threat_count": vt_mal,
                "status": "ALERT" if vt_mal > 2 else ("WARN" if vt_mal > 0 else "NOMINAL")
            },
            {
                "name": "Reputation & Abuse",
                "threat_count": abuse_score,
                "status": "ALERT" if abuse_score > 50 else ("WARN" if abuse_score > 10 else "NOMINAL")
            },
            {
                "name": "Threat Feeds (OTX)",
                "threat_count": pulse_count,
                "status": "ALERT" if pulse_count > 3 else ("WARN" if pulse_count > 0 else "NOMINAL")
            },
            {
                "name": "Geolocation & Org",
                "threat_count": 0,
                "status": "NOMINAL"
            },
            {
                "name": "Vulnerabilities (NVD)",
                "threat_count": 1 if nvd_cve else 0,
                "status": "ALERT" if nvd_score >= 7.0 else ("WARN" if nvd_cve else "NOMINAL")
            }
        ]

        now_str = time.strftime("%H:%M:%S")
        _state["events"].insert(0, {
            "epoch": int(time.time()),
            "time": now_str,
            "message": f"Scan completed for target {target}. Severity: {severity}/10.0 — Status: {_state['status']}",
            "level": "alert" if severity >= 5.0 else "info",
            "threat_type": "SCAN"
        })
