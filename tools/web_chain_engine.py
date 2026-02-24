#!/usr/bin/env python3
"""Web Exploit Chain Engine — Finding correlation and derived target generation.

Adapted from NeuroSploit v3 chain_engine.py for Terminator's Bug Bounty pipeline.
When a vulnerability is confirmed, this engine generates follow-up targets based
on 10 chain rules covering SSRF, SQLi, LFI, XSS, IDOR, open redirect, default
credentials, exposed admin panels, and subdomain takeover chains.

Zero external dependencies — Python 3.12 stdlib only.

Integration point:
    Terminator's `exploiter` agent calls `chain_engine.on_finding(finding)`
    when a vulnerability is confirmed, getting back `List[ChainableTarget]`
    for follow-up testing.

Original: NeuroSploit/backend/core/chain_engine.py (872 lines)
"""

import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class ChainableTarget:
    """A derived attack target generated from a confirmed finding."""

    url: str
    param: str
    vuln_type: str
    context: Dict[str, Any] = field(default_factory=dict)
    chain_depth: int = 1
    parent_finding_id: str = ""
    priority: int = 2  # 1=critical, 2=high, 3=medium
    method: str = "GET"
    injection_point: str = "parameter"
    payload_hint: Optional[str] = None
    description: str = ""

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(asdict(self), indent=2, default=str)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return asdict(self)


@dataclass
class ChainRule:
    """Defines how a finding triggers derived targets."""

    trigger_type: str  # Vuln type that triggers this rule
    derived_types: List[str]  # Types to test on derived targets
    extraction_fn: str  # Method name for target extraction
    priority: int = 2
    max_depth: int = 3
    description: str = ""


# 10 chain rules
CHAIN_RULES: List[ChainRule] = [
    ChainRule(
        trigger_type="ssrf",
        derived_types=["lfi", "xxe", "command_injection", "ssrf"],
        extraction_fn="_extract_internal_urls",
        priority=1,
        description="SSRF -> internal service attacks",
    ),
    ChainRule(
        trigger_type="sqli_error",
        derived_types=["sqli_union", "sqli_blind", "sqli_time"],
        extraction_fn="_extract_db_context",
        priority=1,
        description="SQLi error -> advanced SQLi techniques",
    ),
    ChainRule(
        trigger_type="information_disclosure",
        derived_types=["auth_bypass", "default_credentials"],
        extraction_fn="_extract_credentials",
        priority=1,
        description="Info disclosure -> credential-based attacks",
    ),
    ChainRule(
        trigger_type="idor",
        derived_types=["idor", "bola", "bfla"],
        extraction_fn="_extract_idor_patterns",
        priority=2,
        description="IDOR on one resource -> same pattern on sibling resources",
    ),
    ChainRule(
        trigger_type="lfi",
        derived_types=["sqli", "auth_bypass", "information_disclosure"],
        extraction_fn="_extract_config_paths",
        priority=1,
        description="LFI -> config file extraction -> credential discovery",
    ),
    ChainRule(
        trigger_type="xss_reflected",
        derived_types=["xss_stored", "cors_misconfiguration"],
        extraction_fn="_extract_xss_chain",
        priority=2,
        description="Reflected XSS -> stored XSS / CORS chain for session theft",
    ),
    ChainRule(
        trigger_type="open_redirect",
        derived_types=["ssrf", "oauth_misconfiguration"],
        extraction_fn="_extract_redirect_chain",
        priority=1,
        description="Open redirect -> OAuth token theft chain",
    ),
    ChainRule(
        trigger_type="default_credentials",
        derived_types=["auth_bypass", "privilege_escalation", "idor"],
        extraction_fn="_extract_auth_chain",
        priority=1,
        description="Default creds -> authenticated attacks",
    ),
    ChainRule(
        trigger_type="exposed_admin_panel",
        derived_types=["default_credentials", "auth_bypass", "brute_force"],
        extraction_fn="_extract_admin_chain",
        priority=1,
        description="Exposed admin -> credential attack on admin panel",
    ),
    ChainRule(
        trigger_type="subdomain_takeover",
        derived_types=["xss_reflected", "xss_stored", "ssrf"],
        extraction_fn="_extract_subdomain_targets",
        priority=3,
        description="Subdomain discovery -> new attack surface",
    ),
]


class ChainEngine:
    """Exploit chain engine for finding correlation and derived target generation.

    When a vulnerability is confirmed, this engine:
    1. Checks chain rules for matching trigger types
    2. Extracts derived targets using rule-specific extraction functions
    3. Generates ChainableTarget objects for the agent to test
    4. Tracks chain depth to prevent infinite recursion
    5. Builds an attack graph of finding -> finding relationships

    Usage:
        engine = ChainEngine()
        derived = engine.on_finding(finding)
        for target in derived:
            # Test target through normal vuln testing pipeline
            pass
    """

    MAX_CHAIN_DEPTH = 3
    MAX_DERIVED_PER_FINDING = 20

    def __init__(self) -> None:
        self._chain_graph: Dict[str, List[str]] = {}  # finding_id -> [derived keys]
        self._total_chains: int = 0
        self._chain_findings: List[str] = []  # finding IDs from chaining

    def on_finding(self, finding: Any) -> List[ChainableTarget]:
        """Process a confirmed finding and generate derived targets.

        Accepts any object with attributes: vulnerability_type, id, url,
        parameter, evidence, method, _chain_depth. Missing attributes
        are handled gracefully with defaults.

        Args:
            finding: The confirmed finding (object or dict).

        Returns:
            List of ChainableTarget objects to test.
        """
        vuln_type = self._get(finding, "vulnerability_type", "")
        finding_id = self._get(finding, "id", str(id(finding)))
        chain_depth = self._get(finding, "_chain_depth", 0)

        # Prevent infinite chaining
        if chain_depth >= self.MAX_CHAIN_DEPTH:
            return []

        derived_targets: List[ChainableTarget] = []

        for rule in CHAIN_RULES:
            if not self._matches_trigger(vuln_type, rule.trigger_type):
                continue

            extractor = getattr(self, rule.extraction_fn, None)
            if not extractor:
                continue

            try:
                targets = extractor(finding)
                for target in targets[: self.MAX_DERIVED_PER_FINDING]:
                    target.chain_depth = chain_depth + 1
                    target.parent_finding_id = finding_id
                    target.priority = rule.priority
                    derived_targets.append(target)
            except Exception as e:
                logger.debug(f"Chain extraction failed for {rule.extraction_fn}: {e}")

        # Track in graph
        if derived_targets:
            self._chain_graph[finding_id] = [
                f"{t.vuln_type}:{t.url}" for t in derived_targets
            ]
            self._total_chains += len(derived_targets)
            logger.debug(
                f"Chain engine: {vuln_type} -> {len(derived_targets)} derived targets"
            )

        return derived_targets[: self.MAX_DERIVED_PER_FINDING]

    def eager_chain_targets(self, signal: Dict[str, str]) -> List[ChainableTarget]:
        """Generate chain targets from intermediate signals (before full confirmation).

        Called DURING testing when a single signal is detected but before
        the full validation pipeline confirms it. Enables faster chain discovery.

        Args:
            signal: Dict with keys: vuln_type, url, param, evidence_snippet

        Returns:
            List of high-priority chain targets to test immediately.
        """
        vuln_type = signal.get("vuln_type", "")
        url = signal.get("url", "")
        param = signal.get("param", "")
        evidence = signal.get("evidence_snippet", "")
        targets: List[ChainableTarget] = []

        # SSRF signal -> immediately try cloud metadata
        if vuln_type in ("ssrf", "ssrf_cloud"):
            metadata_urls = [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/instance",
            ]
            for meta_url in metadata_urls:
                targets.append(
                    ChainableTarget(
                        url=url,
                        param=param,
                        vuln_type="ssrf_cloud",
                        payload_hint=meta_url,
                        priority=1,
                        description=f"Eager: SSRF -> cloud metadata ({meta_url})",
                        context={"source": "eager_chain", "target_url": meta_url},
                    )
                )

        # SQLi signal -> immediately try UNION-based extraction
        elif vuln_type.startswith("sqli"):
            targets.append(
                ChainableTarget(
                    url=url,
                    param=param,
                    vuln_type="sqli_union",
                    priority=1,
                    description="Eager: SQLi -> UNION extraction",
                    context={"source": "eager_chain", "db_evidence": evidence[:200]},
                )
            )

        # LFI signal -> immediately try sensitive files
        elif vuln_type in ("lfi", "path_traversal", "arbitrary_file_read"):
            sensitive_files = [
                "../../../../.env",
                "/etc/shadow",
                "/proc/self/environ",
            ]
            for fpath in sensitive_files:
                targets.append(
                    ChainableTarget(
                        url=url,
                        param=param,
                        vuln_type="lfi",
                        payload_hint=fpath,
                        priority=1,
                        description=f"Eager: LFI -> {fpath}",
                        context={"source": "eager_chain"},
                    )
                )

        # Info disclosure -> auth chain
        elif vuln_type == "information_disclosure":
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            targets.append(
                ChainableTarget(
                    url=f"{base}/admin",
                    param="",
                    vuln_type="auth_bypass",
                    priority=2,
                    description="Eager: Info disclosure -> admin auth bypass",
                    context={"source": "eager_chain"},
                )
            )

        return targets

    def get_attack_graph(self) -> Dict[str, List[str]]:
        """Get the attack chain graph."""
        return dict(self._chain_graph)

    def get_chain_stats(self) -> Dict[str, int]:
        """Get chain statistics for reporting."""
        return {
            "total_chains_generated": self._total_chains,
            "graph_nodes": len(self._chain_graph),
            "chain_findings": len(self._chain_findings),
        }

    # --- Helpers ----------------------------------------------------------------

    @staticmethod
    def _get(obj: Any, attr: str, default: Any = "") -> Any:
        """Get attribute from object or dict, with default."""
        if isinstance(obj, dict):
            return obj.get(attr, default)
        return getattr(obj, attr, default)

    @staticmethod
    def _matches_trigger(vuln_type: str, trigger: str) -> bool:
        """Check if vuln_type matches a trigger rule."""
        if vuln_type == trigger:
            return True
        if vuln_type.startswith(trigger + "_") or trigger.startswith(vuln_type + "_"):
            return True
        # Any sqli variant triggers sqli_error rule
        if trigger == "sqli_error" and vuln_type.startswith("sqli"):
            return True
        return False

    # --- Extraction Functions ---------------------------------------------------

    def _extract_internal_urls(self, finding: Any) -> List[ChainableTarget]:
        """From SSRF: extract internal URLs for further attack."""
        targets: List[ChainableTarget] = []
        evidence = self._get(finding, "evidence", "")
        url = self._get(finding, "url", "")

        internal_patterns = [
            r'(?:https?://)?(?:127\.\d+\.\d+\.\d+)(?::\d+)?(?:/[^\s"<>]*)?',
            r'(?:https?://)?(?:10\.\d+\.\d+\.\d+)(?::\d+)?(?:/[^\s"<>]*)?',
            r'(?:https?://)?(?:192\.168\.\d+\.\d+)(?::\d+)?(?:/[^\s"<>]*)?',
            r'(?:https?://)?(?:172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?(?:/[^\s"<>]*)?',
            r'(?:https?://)?localhost(?::\d+)?(?:/[^\s"<>]*)?',
        ]

        found_urls: set[str] = set()
        for pattern in internal_patterns:
            for match in re.finditer(pattern, evidence):
                internal_url = match.group(0)
                if not internal_url.startswith("http"):
                    internal_url = f"http://{internal_url}"
                found_urls.add(internal_url)

        # Fallback: common internal service ports
        if not found_urls and url:
            base_ips = ["127.0.0.1", "localhost"]
            ports = [80, 8080, 8443, 3000, 5000, 8000, 9200, 6379, 27017]
            for ip in base_ips:
                for port in ports[:4]:
                    found_urls.add(f"http://{ip}:{port}/")

        for internal_url in list(found_urls)[:10]:
            for vuln_type in ["lfi", "command_injection", "ssrf"]:
                targets.append(
                    ChainableTarget(
                        url=internal_url,
                        param="url",
                        vuln_type=vuln_type,
                        context={"source": "ssrf_chain", "internal": True},
                        description=f"SSRF chain: {vuln_type} on internal {internal_url}",
                    )
                )

        return targets

    def _extract_db_context(self, finding: Any) -> List[ChainableTarget]:
        """From SQLi error: extract DB type and generate advanced payloads."""
        targets: List[ChainableTarget] = []
        evidence = self._get(finding, "evidence", "")
        url = self._get(finding, "url", "")
        param = self._get(finding, "parameter", "")

        db_type = "unknown"
        db_indicators: Dict[str, List[str]] = {
            "mysql": ["mysql", "mariadb", "you have an error in your sql syntax"],
            "postgresql": ["postgresql", "pg_", "unterminated quoted string"],
            "mssql": ["microsoft sql", "mssql", "unclosed quotation mark", "sqlserver"],
            "oracle": ["ora-", "oracle", "quoted string not properly terminated"],
            "sqlite": ["sqlite", "sqlite3"],
        }

        evidence_lower = evidence.lower()
        for db, indicators in db_indicators.items():
            if any(i in evidence_lower for i in indicators):
                db_type = db
                break

        advanced_types = ["sqli_union", "sqli_blind", "sqli_time"]
        for vuln_type in advanced_types:
            targets.append(
                ChainableTarget(
                    url=url,
                    param=param,
                    vuln_type=vuln_type,
                    context={"db_type": db_type, "source": "sqli_chain"},
                    description=f"SQLi chain: {vuln_type} ({db_type}) on {param}",
                    payload_hint=f"db_type={db_type}",
                )
            )

        return targets

    def _extract_credentials(self, finding: Any) -> List[ChainableTarget]:
        """From info disclosure: extract credentials for auth attacks."""
        targets: List[ChainableTarget] = []
        evidence = self._get(finding, "evidence", "")
        url = self._get(finding, "url", "")

        cred_patterns = [
            r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'<>&]+)',
            r'(?:api_key|apikey|api-key)\s*[=:]\s*["\']?([^\s"\'<>&]+)',
            r'(?:token|secret|auth)\s*[=:]\s*["\']?([^\s"\'<>&]+)',
            r'(?:username|user|login)\s*[=:]\s*["\']?([^\s"\'<>&]+)',
        ]

        found_creds: Dict[str, str] = {}
        for pattern in cred_patterns:
            matches = re.findall(pattern, evidence, re.I)
            for match in matches:
                if len(match) > 3:
                    key_match = re.search(r'\?:([^|)]+)', pattern)
                    key = key_match.group(1) if key_match else "credential"
                    found_creds[key] = match

        if url:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            admin_paths = ["/admin", "/api/admin", "/dashboard", "/management"]

            for path in admin_paths:
                targets.append(
                    ChainableTarget(
                        url=f"{base}{path}",
                        param="",
                        vuln_type="auth_bypass",
                        context={
                            "discovered_creds": found_creds,
                            "source": "info_disclosure_chain",
                        },
                        description=f"Credential chain: auth bypass at {path}",
                    )
                )

        return targets

    def _extract_idor_patterns(self, finding: Any) -> List[ChainableTarget]:
        """From IDOR: apply same pattern to sibling resources."""
        targets: List[ChainableTarget] = []
        url = self._get(finding, "url", "")
        param = self._get(finding, "parameter", "")

        parsed = urlparse(url)
        path = parsed.path

        sibling_resources = [
            "users",
            "orders",
            "profiles",
            "accounts",
            "invoices",
            "documents",
            "messages",
            "transactions",
            "settings",
            "notifications",
            "payments",
            "subscriptions",
        ]

        path_parts = [p for p in path.split("/") if p]
        if len(path_parts) >= 2:
            original_resource = (
                path_parts[-2] if path_parts[-1].isdigit() else path_parts[-1]
            )

            base = f"{parsed.scheme}://{parsed.netloc}"
            for sibling in sibling_resources:
                if sibling != original_resource:
                    new_path = path.replace(original_resource, sibling)
                    targets.append(
                        ChainableTarget(
                            url=f"{base}{new_path}",
                            param=param or "id",
                            vuln_type="idor",
                            context={
                                "source": "idor_pattern_chain",
                                "original_resource": original_resource,
                            },
                            description=f"IDOR chain: {sibling} (from {original_resource})",
                            method=self._get(finding, "method", "GET"),
                        )
                    )

        return targets[:10]

    def _extract_config_paths(self, finding: Any) -> List[ChainableTarget]:
        """From LFI: generate config file read targets."""
        targets: List[ChainableTarget] = []
        url = self._get(finding, "url", "")
        param = self._get(finding, "parameter", "")

        config_files = [
            "/etc/passwd",
            "/etc/shadow",
            "../../../../.env",
            "../../../../config/database.yml",
            "../../../../wp-config.php",
            "../../../../config.php",
            "../../../../.git/config",
            "../../../../config/secrets.yml",
            "/proc/self/environ",
            "../../../../application.properties",
            "../../../../appsettings.json",
            "../../../../web.config",
        ]

        for config_path in config_files:
            targets.append(
                ChainableTarget(
                    url=url,
                    param=param,
                    vuln_type="lfi",
                    context={"config_file": config_path, "source": "lfi_chain"},
                    description=f"LFI chain: read {config_path}",
                    payload_hint=config_path,
                )
            )

        return targets

    def _extract_xss_chain(self, finding: Any) -> List[ChainableTarget]:
        """From reflected XSS: look for stored XSS and CORS chain opportunities."""
        targets: List[ChainableTarget] = []
        url = self._get(finding, "url", "")
        param = self._get(finding, "parameter", "")

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Check for CORS misconfiguration chain
        targets.append(
            ChainableTarget(
                url=base + "/api/",
                param="",
                vuln_type="cors_misconfiguration",
                context={"source": "xss_cors_chain"},
                description="XSS+CORS chain: check CORS for session theft scenario",
            )
        )

        # Potential stored XSS via common form endpoints
        form_paths = ["/contact", "/comment", "/feedback", "/profile", "/settings"]
        for form_path in form_paths:
            targets.append(
                ChainableTarget(
                    url=f"{base}{form_path}",
                    param=param,
                    vuln_type="xss_stored",
                    context={"source": "xss_chain"},
                    description=f"XSS chain: stored XSS via form at {form_path}",
                    method="POST",
                )
            )

        return targets

    def _extract_redirect_chain(self, finding: Any) -> List[ChainableTarget]:
        """From open redirect: chain to OAuth token theft."""
        targets: List[ChainableTarget] = []
        url = self._get(finding, "url", "")
        param = self._get(finding, "parameter", "")

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        oauth_paths = [
            "/oauth/authorize",
            "/auth/authorize",
            "/oauth2/authorize",
            "/connect/authorize",
            "/.well-known/openid-configuration",
            "/api/oauth/callback",
        ]

        for path in oauth_paths:
            targets.append(
                ChainableTarget(
                    url=f"{base}{path}",
                    param="redirect_uri",
                    vuln_type="open_redirect",
                    context={"source": "redirect_oauth_chain"},
                    description=f"Redirect chain: OAuth token theft via {path}",
                )
            )

        # SSRF via redirect
        targets.append(
            ChainableTarget(
                url=url,
                param=param,
                vuln_type="ssrf",
                context={"source": "redirect_ssrf_chain"},
                description="Redirect -> SSRF chain",
            )
        )

        return targets

    def _extract_auth_chain(self, finding: Any) -> List[ChainableTarget]:
        """From default credentials: test all endpoints as authenticated user."""
        targets: List[ChainableTarget] = []
        url = self._get(finding, "url", "")

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        privileged_paths = [
            "/admin",
            "/admin/users",
            "/admin/settings",
            "/api/admin",
            "/api/users",
            "/api/v1/admin",
            "/management",
            "/internal",
            "/debug",
        ]

        for path in privileged_paths:
            targets.append(
                ChainableTarget(
                    url=f"{base}{path}",
                    param="",
                    vuln_type="privilege_escalation",
                    context={"source": "auth_chain", "authenticated": True},
                    description=f"Auth chain: privilege escalation at {path}",
                )
            )

        return targets

    def _extract_admin_chain(self, finding: Any) -> List[ChainableTarget]:
        """From exposed admin panel: try default credentials and auth bypass."""
        targets: List[ChainableTarget] = []
        url = self._get(finding, "url", "")

        targets.append(
            ChainableTarget(
                url=url,
                param="",
                vuln_type="default_credentials",
                context={"source": "admin_chain"},
                description=f"Admin chain: default credentials at {url}",
            )
        )

        targets.append(
            ChainableTarget(
                url=url,
                param="",
                vuln_type="auth_bypass",
                context={"source": "admin_chain"},
                description=f"Admin chain: auth bypass at {url}",
            )
        )

        return targets

    def _extract_subdomain_targets(self, finding: Any) -> List[ChainableTarget]:
        """From subdomain discovery: add as new attack targets."""
        targets: List[ChainableTarget] = []
        evidence = self._get(finding, "evidence", "")

        subdomain_pattern = r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[-a-zA-Z0-9.]+)"
        found_domains: set[str] = set(re.findall(subdomain_pattern, evidence))

        for domain in list(found_domains)[:5]:
            if not domain.startswith("http"):
                domain_url = f"https://{domain}"
            else:
                domain_url = domain

            targets.append(
                ChainableTarget(
                    url=domain_url,
                    param="",
                    vuln_type="xss_reflected",
                    context={"source": "subdomain_chain"},
                    description=f"Subdomain chain: test {domain}",
                    priority=3,
                )
            )

        return targets


# --- CLI demo ---------------------------------------------------------------


def _demo() -> None:
    """Show example chain from an SSRF finding."""
    engine = ChainEngine()

    # Simulate an SSRF finding
    ssrf_finding = {
        "id": "FINDING-001",
        "vulnerability_type": "ssrf",
        "url": "https://target.example.com/api/fetch",
        "parameter": "url",
        "method": "POST",
        "evidence": (
            "Response contains internal content from http://10.0.0.5:8080/status "
            "and http://192.168.1.100:3000/admin. Also leaked "
            "http://localhost:9200/_cluster/health with Elasticsearch data."
        ),
        "_chain_depth": 0,
    }

    print("=" * 70)
    print("Web Chain Engine Demo")
    print("=" * 70)
    print(f"\nInput finding: SSRF at {ssrf_finding['url']}")
    print(f"  param: {ssrf_finding['parameter']}")
    print(f"  evidence snippet: {ssrf_finding['evidence'][:80]}...")

    # Run chain engine
    derived = engine.on_finding(ssrf_finding)

    print(f"\nDerived targets: {len(derived)}")
    print("-" * 70)
    for i, target in enumerate(derived, 1):
        print(f"  [{i}] {target.vuln_type:20s} | {target.url}")
        print(f"       param={target.param} priority={target.priority} depth={target.chain_depth}")
        if target.description:
            print(f"       {target.description}")

    # Eager chain from signal
    print("\n" + "=" * 70)
    print("Eager chain from SQLi signal (pre-confirmation)")
    print("=" * 70)

    sqli_signal = {
        "vuln_type": "sqli_error",
        "url": "https://target.example.com/search",
        "param": "q",
        "evidence_snippet": "mysql error: you have an error in your sql syntax",
    }

    eager = engine.eager_chain_targets(sqli_signal)
    print(f"\nEager targets: {len(eager)}")
    for i, target in enumerate(eager, 1):
        print(f"  [{i}] {target.vuln_type:20s} | {target.url} (param={target.param})")

    # Stats
    print("\n" + "=" * 70)
    print("Chain stats:")
    stats = engine.get_chain_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")

    graph = engine.get_attack_graph()
    print(f"\nAttack graph ({len(graph)} nodes):")
    for finding_id, derived_keys in graph.items():
        print(f"  {finding_id} -> {len(derived_keys)} targets")
        for key in derived_keys[:3]:
            print(f"    - {key}")
        if len(derived_keys) > 3:
            print(f"    ... and {len(derived_keys) - 3} more")

    # JSON serialization demo
    if derived:
        print("\n" + "=" * 70)
        print("JSON serialization (first target):")
        print(derived[0].to_json())


def main() -> None:
    """CLI entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        _demo()
    elif len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print("Usage: python3 web_chain_engine.py [demo]")
        print()
        print("Web Exploit Chain Engine for Terminator Bug Bounty pipeline.")
        print("Adapted from NeuroSploit v3 chain_engine.py.")
        print()
        print("Commands:")
        print("  demo    Run interactive demo with example SSRF finding")
        print()
        print("Programmatic usage:")
        print("  from tools.web_chain_engine import ChainEngine, ChainableTarget")
        print('  engine = ChainEngine()')
        print('  targets = engine.on_finding({"vulnerability_type": "ssrf", ...})')
    else:
        print("Usage: python3 web_chain_engine.py [demo]")
        print("Run with 'demo' to see example chain generation.")


if __name__ == "__main__":
    main()
