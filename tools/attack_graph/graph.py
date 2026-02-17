"""
AttackGraph: Core Neo4j interface for attack surface modeling.
"""
import os
import json
import uuid
from typing import Optional
from neo4j import GraphDatabase
from .schema import CONSTRAINTS, INDEXES


NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "terminator")


class AttackGraph:
    def __init__(self, uri=None, user=None, password=None):
        self.uri = uri or NEO4J_URI
        self.user = user or NEO4J_USER
        self.password = password or NEO4J_PASSWORD
        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))

    def close(self):
        self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def initialize_schema(self):
        """Apply constraints and indexes."""
        with self.driver.session() as session:
            for constraint in CONSTRAINTS:
                session.run(constraint)
            for index in INDEXES:
                session.run(index)
        print("[AttackGraph] Schema initialized.")

    def _run(self, query: str, **params):
        with self.driver.session() as session:
            result = session.run(query, **params)
            return [dict(r) for r in result]

    # --- Node ingestion ---

    def add_target(self, name: str, program_url: str = None, scope: str = None):
        return self._run(
            "MERGE (n:Target {name: $name}) "
            "SET n.program_url = $program_url, n.scope = $scope "
            "RETURN n",
            name=name, program_url=program_url, scope=scope
        )

    def add_host(self, address: str, hostname: str = None, os: str = None, target_name: str = None):
        self._run(
            "MERGE (n:Host {address: $address}) "
            "SET n.hostname = $hostname, n.os = $os "
            "RETURN n",
            address=address, hostname=hostname, os=os
        )
        if target_name:
            self._run(
                "MATCH (t:Target {name: $target_name}), (h:Host {address: $address}) "
                "MERGE (t)-[:CONTAINS]->(h)",
                target_name=target_name, address=address
            )

    def add_service(self, host_address: str, name: str, port: int, protocol: str = "tcp", version: str = None):
        self._run(
            "MATCH (h:Host {address: $host_address}) "
            "MERGE (s:Service {name: $name, port: $port, host: $host_address}) "
            "SET s.protocol = $protocol, s.version = $version "
            "MERGE (h)-[:RUNS]->(s)",
            host_address=host_address, name=name, port=port, protocol=protocol, version=version
        )

    def add_endpoint(self, service_key: str, url: str, method: str = "GET", auth_required: bool = False):
        self._run(
            "MATCH (s:Service {name: $service_key}) "
            "MERGE (e:Endpoint {url: $url, method: $method}) "
            "SET e.auth_required = $auth_required "
            "MERGE (s)-[:EXPOSES]->(e)",
            service_key=service_key, url=url, method=method, auth_required=auth_required
        )

    def add_vulnerability(self, cve_id: str, description: str, severity: str, cvss: float = 0.0,
                          service_name: str = None, technology_name: str = None):
        self._run(
            "MERGE (v:Vulnerability {cve_id: $cve_id}) "
            "SET v.description = $description, v.severity = $severity, v.cvss = $cvss",
            cve_id=cve_id, description=description, severity=severity, cvss=cvss
        )
        if service_name:
            self._run(
                "MATCH (s:Service {name: $service_name}), (v:Vulnerability {cve_id: $cve_id}) "
                "MERGE (s)-[:HAS]->(v)",
                service_name=service_name, cve_id=cve_id
            )
        if technology_name:
            self._run(
                "MATCH (t:Technology {name: $technology_name}), (v:Vulnerability {cve_id: $cve_id}) "
                "MERGE (t)-[:HAS]->(v)",
                technology_name=technology_name, cve_id=cve_id
            )

    def add_exploit(self, vuln_cve: str, source_url: str, technique: str = None, reliability: str = "unknown"):
        exploit_id = str(uuid.uuid4())[:8]
        self._run(
            "MATCH (v:Vulnerability {cve_id: $cve_id}) "
            "MERGE (e:Exploit {id: $exploit_id}) "
            "SET e.source_url = $source_url, e.technique = $technique, e.reliability = $reliability "
            "MERGE (v)-[:HAS_EXPLOIT]->(e)",
            cve_id=vuln_cve, exploit_id=exploit_id, source_url=source_url,
            technique=technique, reliability=reliability
        )

    def add_finding(self, title: str, severity: str, description: str,
                    vuln_cve: str = None, affected_asset: str = None):
        finding_id = str(uuid.uuid4())[:8]
        self._run(
            "MERGE (f:Finding {id: $finding_id}) "
            "SET f.title = $title, f.severity = $severity, f.description = $description",
            finding_id=finding_id, title=title, severity=severity, description=description
        )
        if vuln_cve:
            self._run(
                "MATCH (f:Finding {id: $finding_id}), (v:Vulnerability {cve_id: $vuln_cve}) "
                "MERGE (f)-[:EXPLOITS]->(v)",
                finding_id=finding_id, vuln_cve=vuln_cve
            )
        return finding_id

    def add_technology(self, name: str, version: str, service_name: str = None):
        self._run(
            "MERGE (t:Technology {name: $name, version: $version})",
            name=name, version=version
        )
        if service_name:
            self._run(
                "MATCH (s:Service {name: $service_name}), (t:Technology {name: $name}) "
                "MERGE (s)-[:USES]->(t)",
                service_name=service_name, name=name
            )

    # --- Query methods ---

    def get_attack_paths(self, target_name: str, max_hops: int = 5):
        """Find all paths from Target to high-severity Findings."""
        return self._run(
            "MATCH path = (t:Target {name: $target_name})-[*1..$max_hops]->(f:Finding) "
            "WHERE f.severity IN ['critical', 'high'] "
            "RETURN path, length(path) as hops "
            "ORDER BY hops ASC LIMIT 20",
            target_name=target_name, max_hops=max_hops
        )

    def get_critical_vulns(self, target_name: str = None):
        """Get all critical/high vulnerabilities."""
        if target_name:
            return self._run(
                "MATCH (t:Target {name: $target_name})-[*]->(v:Vulnerability) "
                "WHERE v.severity IN ['CRITICAL', 'HIGH'] "
                "RETURN v.cve_id, v.description, v.severity, v.cvss "
                "ORDER BY v.cvss DESC",
                target_name=target_name
            )
        return self._run(
            "MATCH (v:Vulnerability) WHERE v.severity IN ['CRITICAL', 'HIGH'] "
            "RETURN v.cve_id, v.description, v.severity, v.cvss ORDER BY v.cvss DESC"
        )

    def get_exploitable_services(self, target_name: str):
        """Find services with known exploits."""
        return self._run(
            "MATCH (t:Target {name: $target_name})-[*]->(s:Service)-[:HAS]->(v:Vulnerability)-[:HAS_EXPLOIT]->(e:Exploit) "
            "RETURN s.name, s.port, v.cve_id, v.severity, e.source_url, e.reliability "
            "ORDER BY v.cvss DESC",
            target_name=target_name
        )

    def get_unauthenticated_endpoints(self, target_name: str):
        """Find endpoints not requiring authentication."""
        return self._run(
            "MATCH (t:Target {name: $target_name})-[*]->(e:Endpoint) "
            "WHERE e.auth_required = false "
            "RETURN e.url, e.method ORDER BY e.url",
            target_name=target_name
        )

    def get_attack_surface_summary(self, target_name: str):
        """Get summary stats for a target."""
        return self._run(
            "MATCH (t:Target {name: $target_name}) "
            "OPTIONAL MATCH (t)-[*]->(h:Host) "
            "OPTIONAL MATCH (t)-[*]->(s:Service) "
            "OPTIONAL MATCH (t)-[*]->(e:Endpoint) "
            "OPTIONAL MATCH (t)-[*]->(v:Vulnerability) "
            "OPTIONAL MATCH (t)-[*]->(f:Finding) "
            "RETURN "
            "count(DISTINCT h) as hosts, "
            "count(DISTINCT s) as services, "
            "count(DISTINCT e) as endpoints, "
            "count(DISTINCT v) as vulnerabilities, "
            "count(DISTINCT f) as findings",
            target_name=target_name
        )

    def get_technology_risks(self, target_name: str):
        """Find technologies with known vulnerabilities."""
        return self._run(
            "MATCH (t:Target {name: $target_name})-[*]->(tech:Technology)-[:HAS]->(v:Vulnerability) "
            "RETURN tech.name, tech.version, count(v) as vuln_count, "
            "collect(v.cve_id)[..5] as sample_cves "
            "ORDER BY vuln_count DESC",
            target_name=target_name
        )

    def ingest_from_json(self, data: dict):
        """Bulk ingest from structured JSON (recon report format)."""
        target = data.get("target")
        if not target:
            raise ValueError("JSON must have 'target' field")

        self.add_target(target, data.get("program_url"), data.get("scope"))

        for host in data.get("hosts", []):
            self.add_host(host["address"], host.get("hostname"), host.get("os"), target)
            for svc in host.get("services", []):
                self.add_service(host["address"], svc["name"], svc["port"],
                                 svc.get("protocol", "tcp"), svc.get("version"))
                for tech in svc.get("technologies", []):
                    self.add_technology(tech["name"], tech.get("version", "unknown"), svc["name"])
                for vuln in svc.get("vulnerabilities", []):
                    self.add_vulnerability(vuln["cve_id"], vuln.get("description", ""),
                                           vuln.get("severity", "UNKNOWN"), vuln.get("cvss", 0.0),
                                           service_name=svc["name"])

        for finding in data.get("findings", []):
            self.add_finding(finding["title"], finding["severity"],
                             finding.get("description", ""), finding.get("cve_id"),
                             finding.get("asset"))

    def export_to_json(self, target_name: str) -> dict:
        """Export attack graph as JSON."""
        summary = self.get_attack_surface_summary(target_name)
        vulns = self.get_critical_vulns(target_name)
        services = self.get_exploitable_services(target_name)
        endpoints = self.get_unauthenticated_endpoints(target_name)
        techs = self.get_technology_risks(target_name)

        return {
            "target": target_name,
            "summary": summary[0] if summary else {},
            "critical_vulnerabilities": vulns,
            "exploitable_services": services,
            "unauthenticated_endpoints": endpoints,
            "technology_risks": techs,
        }
