#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Eagle Eye Cloud Detector

Run:
  python3 eagle_eye.py -t example.com
  python3 eagle_eye.py -t example.com --timeout 1800
  python3 eagle_eye.py -t example.com --timeout 7200 -o output.json

Notes:
- This script has ZERO pip dependencies (standard library only).
- It relies on an external backend collector command (default: "spiderfoot")
  that must support:  <collector> -s <target> -o json
- Backend stderr is suppressed and errors are user-friendly (no traceback).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set


# -------------------------
# Internal event container
# -------------------------

@dataclass(frozen=True)
class BackendEvent:
    event_type: str
    data: str
    source: str = ""
    module: str = ""
    raw: Optional[Dict[str, Any]] = None


# -------------------------
# EagleEye Extractor Engine
# -------------------------

class EagleEyeEngine:
    # IP / ASN
    RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
    RE_IPV6 = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b|\b::1\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b")
    RE_ASN  = re.compile(r"\bAS(?:N)?\s*([0-9]{1,10})\b", re.IGNORECASE)

    # CDN keywords (heuristic)
    CDN_PROVIDERS = [
        "cloudflare", "akamai", "fastly", "incapsula", "imperva",
        "stackpath", "sucuri", "edgesuite", "edgekey",
        "cloudfront", "azure front door", "azure cdn", "azureedge",
        "bunnycdn", "gcore", "cdnetworks", "cloudinary"
    ]

    # Cloud indicators
    RE_AWS_S3 = re.compile(
        r"\b(?:s3[.-][a-z0-9-]+\.amazonaws\.com/[a-z0-9.\-_]{3,63}"
        r"|[a-z0-9.\-_]{3,63}\.s3[.-][a-z0-9-]+\.amazonaws\.com"
        r"|s3\.amazonaws\.com/[a-z0-9.\-_]{3,63})\b",
        re.IGNORECASE
    )
    RE_AWS_CLOUDFRONT = re.compile(r"\b[a-z0-9]{6,}\.cloudfront\.net\b", re.IGNORECASE)
    RE_AWS_ELB = re.compile(r"\b[a-z0-9-]{6,}\.(?:elb|elb\.amazonaws)\.[a-z0-9-]+\.amazonaws\.com\b", re.IGNORECASE)

    RE_AZURE_BLOB = re.compile(r"\b[a-z0-9-]{3,24}\.blob\.core\.windows\.net\b", re.IGNORECASE)
    RE_AZURE_WEBAPP = re.compile(r"\b[a-z0-9-]+\.azurewebsites\.net\b", re.IGNORECASE)
    RE_AZURE_CDN = re.compile(r"\b[a-z0-9-]+\.azureedge\.net\b|\b[a-z0-9-]+\.trafficmanager\.net\b", re.IGNORECASE)

    RE_GCS = re.compile(r"\bstorage\.googleapis\.com/[a-z0-9.\-_]{3,63}\b|\b[a-z0-9.\-_]{3,63}\.storage\.googleapis\.com\b", re.IGNORECASE)
    RE_FIREBASE = re.compile(r"\b[a-z0-9-]+\.web\.app\b|\b[a-z0-9-]+\.firebaseapp\.com\b", re.IGNORECASE)

    RE_OCI_OBJECT = re.compile(r"\bobjectstorage\.[a-z0-9-]+\.oraclecloud\.com\b", re.IGNORECASE)

    RE_CF_PAGES = re.compile(r"\bpages\.dev\b", re.IGNORECASE)
    RE_CF_R2 = re.compile(r"\b[rR]2\.cloudflarestorage\.com\b", re.IGNORECASE)
    RE_CF_WORKERS = re.compile(r"\bworkers\.dev\b", re.IGNORECASE)

    RE_DO_SPACES = re.compile(r"\b[a-z0-9-]{3,63}\.(?:nyc3|sfo3|ams3|sgp1|fra1|lon1|blr1|tor1|syd1)\.digitaloceanspaces\.com\b", re.IGNORECASE)
    RE_ALI_OSS = re.compile(r"\b[a-z0-9.\-_]{3,63}\.oss-[a-z0-9-]+\.aliyuncs\.com\b", re.IGNORECASE)

    OTHER_CLOUD_KEYS = ["herokuapp.com", "vercel.app", "netlify.app", "github.io"]

    # Data Lake / Lakehouse
    RE_AZURE_DATALAKE_DFS = re.compile(r"\b[a-z0-9-]{3,24}\.dfs\.core\.windows\.net\b", re.IGNORECASE)
    RE_AZURE_ABFSS = re.compile(r"\babfss?://[a-z0-9-]{3,63}@[a-z0-9-]{3,24}\.dfs\.core\.windows\.net/[^\s'\"<>]{1,300}", re.IGNORECASE)
    RE_AZURE_SYNAPSE = re.compile(r"\b[a-z0-9-]+\.dev\.azuresynapse\.net\b", re.IGNORECASE)

    RE_AWS_ATHENA = re.compile(r"\bathena\.[a-z0-9-]+\.amazonaws\.com\b", re.IGNORECASE)
    RE_AWS_GLUE = re.compile(r"\bglue\.[a-z0-9-]+\.amazonaws\.com\b", re.IGNORECASE)
    RE_AWS_LAKEFORMATION = re.compile(r"\blakeformation\.[a-z0-9-]+\.amazonaws\.com\b", re.IGNORECASE)
    RE_AWS_EMR = re.compile(r"\belasticmapreduce\.[a-z0-9-]+\.amazonaws\.com\b", re.IGNORECASE)

    RE_GCP_BIGQUERY = re.compile(r"\bbigquery\.googleapis\.com\b", re.IGNORECASE)
    RE_GCP_DATAFLOW = re.compile(r"\bdataflow\.googleapis\.com\b", re.IGNORECASE)
    RE_GCP_DATAPROC = re.compile(r"\bdataproc\.googleapis\.com\b", re.IGNORECASE)

    RE_DATABRICKS_AZ = re.compile(r"\b[a-z0-9-]+\.azuredatabricks\.net\b", re.IGNORECASE)
    RE_DATABRICKS_CLOUD = re.compile(r"\b[a-z0-9-]+\.cloud\.databricks\.com\b", re.IGNORECASE)

    def __init__(self) -> None:
        self.ipv4: Set[str] = set()
        self.ipv6: Set[str] = set()
        self.asns: Dict[str, Dict[str, Any]] = {}
        self.cdns: Set[str] = set()

        self.cloud: Dict[str, Set[str]] = {
            "AWS": set(),
            "Azure": set(),
            "GCP": set(),
            "Firebase": set(),
            "OracleOCI": set(),
            "Cloudflare": set(),
            "DigitalOcean": set(),
            "Alibaba": set(),
            "OtherCloud": set(),
        }

        self.datalakes: Dict[str, Set[str]] = {
            "AzureADLS": set(),
            "AWSDataLakeEcosystem": set(),
            "GCPDataLakeEcosystem": set(),
            "Databricks": set(),
        }

    def ingest(self, events: Iterable[BackendEvent]) -> None:
        for ev in events:
            et = (ev.event_type or "").strip()
            data = (ev.data or "").strip()
            if not et and not data:
                continue
            self._extract_all(et, data)

    def _extract_all(self, event_type: str, data: str) -> None:
        blob = f"{event_type}\n{data}"
        low = blob.lower()

        # IPs
        for ip in self.RE_IPV4.findall(blob):
            self._try_add_ip(ip)
        for ip in self.RE_IPV6.findall(blob):
            self._try_add_ip(ip)

        # ASN (+ best-effort org)
        for m in self.RE_ASN.finditer(blob):
            asn = f"AS{m.group(1)}"
            key = asn.upper()
            tail = blob[m.end():].strip(" -|,;\t")
            org = ""
            if tail:
                org = tail.splitlines()[0].split("|")[0].split(";")[0].strip()
                if len(org) > 120:
                    org = org[:120].strip()
            if key not in self.asns:
                self.asns[key] = {"asn": asn, "org": org}
            else:
                if org and not self.asns[key].get("org"):
                    self.asns[key]["org"] = org

        # CDN
        for p in self.CDN_PROVIDERS:
            if p in low:
                self.cdns.add(p)

        # Cloud
        self._add_cloud("AWS", self.RE_AWS_S3.findall(blob))
        self._add_cloud("AWS", self.RE_AWS_CLOUDFRONT.findall(blob))
        self._add_cloud("AWS", self.RE_AWS_ELB.findall(blob))

        self._add_cloud("Azure", self.RE_AZURE_BLOB.findall(blob))
        self._add_cloud("Azure", self.RE_AZURE_WEBAPP.findall(blob))
        self._add_cloud("Azure", self.RE_AZURE_CDN.findall(blob))

        self._add_cloud("GCP", self.RE_GCS.findall(blob))
        self._add_cloud("Firebase", self.RE_FIREBASE.findall(blob))
        self._add_cloud("OracleOCI", self.RE_OCI_OBJECT.findall(blob))

        self._add_cloud("Cloudflare", self.RE_CF_PAGES.findall(blob))
        self._add_cloud("Cloudflare", self.RE_CF_R2.findall(blob))
        self._add_cloud("Cloudflare", self.RE_CF_WORKERS.findall(blob))

        self._add_cloud("DigitalOcean", self.RE_DO_SPACES.findall(blob))
        self._add_cloud("Alibaba", self.RE_ALI_OSS.findall(blob))

        for kw in self.OTHER_CLOUD_KEYS:
            if kw in low:
                self.cloud["OtherCloud"].add(kw)

        # Data Lakes / Lakehouse
        self.datalakes["AzureADLS"].update(self.RE_AZURE_DATALAKE_DFS.findall(blob))
        self.datalakes["AzureADLS"].update(self.RE_AZURE_ABFSS.findall(blob))
        self.datalakes["AzureADLS"].update(self.RE_AZURE_SYNAPSE.findall(blob))

        self.datalakes["AWSDataLakeEcosystem"].update(self.RE_AWS_ATHENA.findall(blob))
        self.datalakes["AWSDataLakeEcosystem"].update(self.RE_AWS_GLUE.findall(blob))
        self.datalakes["AWSDataLakeEcosystem"].update(self.RE_AWS_LAKEFORMATION.findall(blob))
        self.datalakes["AWSDataLakeEcosystem"].update(self.RE_AWS_EMR.findall(blob))

        self.datalakes["GCPDataLakeEcosystem"].update(self.RE_GCP_BIGQUERY.findall(blob))
        self.datalakes["GCPDataLakeEcosystem"].update(self.RE_GCP_DATAFLOW.findall(blob))
        self.datalakes["GCPDataLakeEcosystem"].update(self.RE_GCP_DATAPROC.findall(blob))

        self.datalakes["Databricks"].update(self.RE_DATABRICKS_AZ.findall(blob))
        self.datalakes["Databricks"].update(self.RE_DATABRICKS_CLOUD.findall(blob))

    def _try_add_ip(self, s: str) -> None:
        s = s.strip(" ,;[](){}<>\"'")
        try:
            ip_obj = ipaddress.ip_address(s)
        except ValueError:
            return
        (self.ipv4 if ip_obj.version == 4 else self.ipv6).add(str(ip_obj))

    def _add_cloud(self, svc: str, matches: List[str]) -> None:
        for m in matches:
            ind = (m or "").strip()
            if ind:
                self.cloud[svc].add(ind)

    def to_result(self) -> Dict[str, Any]:
        return {
            "tool": "Eagle Eye Cloud Detector",
            "focus": ["ASN", "CDN", "IPv4", "IPv6", "CloudIndicators", "DataLakes"],
            "counts": {
                "asn": len(self.asns),
                "cdn": len(self.cdns),
                "ipv4": len(self.ipv4),
                "ipv6": len(self.ipv6),
                "cloud_total": sum(len(v) for v in self.cloud.values()),
                "datalake_total": sum(len(v) for v in self.datalakes.values()),
            },
            "asn": sorted(self.asns.values(), key=lambda x: x.get("asn", "")),
            "cdn": sorted(self.cdns),
            "ipv4": sorted(self.ipv4),
            "ipv6": sorted(self.ipv6),
            "cloud": {k: sorted(v) for k, v in self.cloud.items()},
            "datalakes": {k: sorted(v) for k, v in self.datalakes.items()},
        }

    def print_clean(self) -> None:
        r = self.to_result()

        print("\n==============================")
        print(" Eagle Eye Cloud Detector — Results")
        print("==============================\n")

        print(f"[ASN] ({r['counts']['asn']})")
        if r["asn"]:
            for a in r["asn"]:
                line = f"  - {a.get('asn','')}"
                if a.get("org"):
                    line += f" | {a['org']}"
                print(line)
        else:
            print("  (none observed)")
        print()

        def section(title: str, items: List[str]) -> None:
            print(f"[{title}] ({len(items)})")
            if items:
                for x in items:
                    print(f"  - {x}")
            else:
                print("  (none observed)")
            print()

        section("CDN", r["cdn"])
        section("IPv4", r["ipv4"])
        section("IPv6", r["ipv6"])

        print("[Cloud Indicators]")
        for svc in ["AWS", "Azure", "GCP", "Firebase", "OracleOCI", "Cloudflare", "DigitalOcean", "Alibaba", "OtherCloud"]:
            items = r["cloud"].get(svc, [])
            print(f"  {svc} ({len(items)})")
            if items:
                for it in items:
                    print(f"    - {it}")
            else:
                print("    (none observed)")
        print()

        print("[Data Lakes / Lakehouse]")
        for svc in ["AzureADLS", "AWSDataLakeEcosystem", "GCPDataLakeEcosystem", "Databricks"]:
            items = r["datalakes"].get(svc, [])
            print(f"  {svc} ({len(items)})")
            if items:
                for it in items:
                    print(f"    - {it}")
            else:
                print("    (none observed)")
        print("\nDone.\n")


# -------------------------
# Backend runner (hidden)
# -------------------------

def _load_events_from_json(path: str) -> List[BackendEvent]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    if isinstance(data, dict):
        raw_events = None
        for k in ("events", "data", "results", "items"):
            if k in data and isinstance(data[k], list):
                raw_events = data[k]
                break
        if raw_events is None:
            raw_events = []
    elif isinstance(data, list):
        raw_events = data
    else:
        raw_events = []

    events: List[BackendEvent] = []
    for e in raw_events:
        if not isinstance(e, dict):
            continue
        et = str(e.get("type") or e.get("eventType") or e.get("event_type") or e.get("category") or "UNKNOWN").strip()
        d = str(e.get("data") or e.get("eventData") or e.get("event_data") or e.get("value") or "").strip()
        src = str(e.get("source") or e.get("src") or e.get("parent") or "").strip()
        mod = str(e.get("module") or e.get("mod") or "").strip()
        events.append(BackendEvent(event_type=et, data=d, source=src, module=mod, raw=e))
    return events


def _find_backend_cmd(backend_cmd: str) -> List[str]:
    parts = backend_cmd.split()
    if len(parts) > 1:
        return parts
    if shutil.which(parts[0]):
        return [parts[0]]
    return [parts[0]]


def _run_backend_silently(backend_cmd: str, target: str, timeout: int, tmpdir: str) -> str:
    out_json = os.path.join(tmpdir, "collector_results.json")
    cmd = _find_backend_cmd(backend_cmd)
    attempt = cmd + ["-s", target, "-o", "json"]

    try:
        p = subprocess.run(
            attempt,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise RuntimeError("Backend collector not found. Install it or set --backend-cmd.") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"Backend collection timed out after {timeout} seconds. Try a higher --timeout.") from e

    if p.returncode == 0 and p.stdout.strip():
        with open(out_json, "w", encoding="utf-8") as f:
            f.write(p.stdout)
        return out_json

    raise RuntimeError("Backend collection failed. (Admin-only: check collector install/config.)")


# -------------------------
# CLI
# -------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="EagleEye", description="Eagle Eye Cloud Detector — focused infra extraction for a domain.")
    ap.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")
    ap.add_argument("--backend-cmd", default="spiderfoot",
                    help="Admin-only backend collector command (keep hidden from front-end users).")
    ap.add_argument("--timeout", type=int, default=7200, help="Timeout seconds (default: 7200)")
    ap.add_argument("-o", "--out", default="", help="Write JSON results to file (optional)")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    engine = EagleEyeEngine()

    try:
        with tempfile.TemporaryDirectory(prefix="eagleeye_") as tmpdir:
            json_path = _run_backend_silently(args.backend_cmd, args.target, args.timeout, tmpdir)
            events = _load_events_from_json(json_path)
            engine.ingest(events)
            engine.print_clean()

            if args.out:
                with open(args.out, "w", encoding="utf-8") as f:
                    json.dump(engine.to_result(), f, indent=2, ensure_ascii=False)
                print(f"[+] JSON written: {args.out}")

        return 0

    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
        return 130
    except Exception as e:
        print(f"[-] {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
