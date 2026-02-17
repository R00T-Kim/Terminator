"""
Pre-built Cypher queries for common attack surface analysis patterns.
"""

QUERIES = {
    # ── Discovery ──────────────────────────────────────────────────────────
    "all_targets": """
        MATCH (t:Target)
        RETURN t.name AS target, t.scope AS scope, t.program_url AS program_url
        ORDER BY t.name
    """,

    "attack_surface_summary": """
        MATCH (t:Target {name: $target_name})
        OPTIONAL MATCH (t)-[*]->(h:Host)
        OPTIONAL MATCH (t)-[*]->(s:Service)
        OPTIONAL MATCH (t)-[*]->(e:Endpoint)
        OPTIONAL MATCH (t)-[*]->(v:Vulnerability)
        OPTIONAL MATCH (t)-[*]->(f:Finding)
        RETURN
            count(DISTINCT h) AS hosts,
            count(DISTINCT s) AS services,
            count(DISTINCT e) AS endpoints,
            count(DISTINCT v) AS vulnerabilities,
            count(DISTINCT f) AS findings
    """,

    # ── Vulnerability Analysis ──────────────────────────────────────────────
    "critical_vulns": """
        MATCH (v:Vulnerability)
        WHERE v.severity IN ['CRITICAL', 'HIGH']
        RETURN v.cve_id AS cve_id, v.description AS description,
               v.severity AS severity, v.cvss AS cvss
        ORDER BY v.cvss DESC
    """,

    "vulns_with_exploits": """
        MATCH (v:Vulnerability)-[:HAS_EXPLOIT]->(e:Exploit)
        RETURN v.cve_id AS cve_id, v.severity AS severity,
               e.source_url AS exploit_url, e.reliability AS reliability
        ORDER BY v.cvss DESC
    """,

    "exploitable_services": """
        MATCH (t:Target {name: $target_name})-[*]->(s:Service)
              -[:HAS]->(v:Vulnerability)-[:HAS_EXPLOIT]->(e:Exploit)
        RETURN s.name AS service, s.port AS port, s.host AS host,
               v.cve_id AS cve_id, v.severity AS severity,
               e.source_url AS exploit_url
        ORDER BY v.cvss DESC
    """,

    # ── Access Control ──────────────────────────────────────────────────────
    "unauthenticated_endpoints": """
        MATCH (t:Target {name: $target_name})-[*]->(e:Endpoint)
        WHERE e.auth_required = false
        RETURN e.url AS url, e.method AS method
        ORDER BY e.url
    """,

    "privileged_credentials": """
        MATCH (u:User)-[:HAS]->(c:Credential)-[:GRANTS]->(p:Permission)
        WHERE p.level IN ['admin', 'root', 'superuser']
        RETURN u.name AS user, c.type AS cred_type, p.level AS permission
    """,

    # ── Attack Path ─────────────────────────────────────────────────────────
    "shortest_attack_path": """
        MATCH (t:Target {name: $target_name}), (f:Finding {severity: 'critical'})
        MATCH path = shortestPath((t)-[*..10]->(f))
        RETURN path, length(path) AS hops
        ORDER BY hops ASC
        LIMIT 5
    """,

    "paths_to_critical_assets": """
        MATCH path = (e:Endpoint)-[*1..6]->(a:Asset)
        WHERE e.auth_required = false
        RETURN path, length(path) AS hops
        ORDER BY hops ASC
        LIMIT 10
    """,

    # ── Technology Risk ─────────────────────────────────────────────────────
    "outdated_technologies": """
        MATCH (t:Technology)-[:HAS]->(v:Vulnerability)
        WITH t, count(v) AS vuln_count, collect(v.cve_id)[..5] AS sample_cves
        WHERE vuln_count > 0
        RETURN t.name AS tech, t.version AS version,
               vuln_count, sample_cves
        ORDER BY vuln_count DESC
    """,

    "technology_attack_surface": """
        MATCH (t:Target {name: $target_name})-[*]->(tech:Technology)
        OPTIONAL MATCH (tech)-[:HAS]->(v:Vulnerability)
        RETURN tech.name AS tech, tech.version AS version,
               count(DISTINCT v) AS vuln_count
        ORDER BY vuln_count DESC
    """,

    # ── Network ─────────────────────────────────────────────────────────────
    "exposed_services": """
        MATCH (t:Target {name: $target_name})-[*]->(s:Service)
        RETURN s.host AS host, s.port AS port, s.name AS service,
               s.version AS version, s.protocol AS protocol
        ORDER BY s.host, s.port
    """,

    "network_segments": """
        MATCH (n:Network)<-[:BELONGS_TO]-(h:Host)
        RETURN n.cidr AS network, collect(h.address) AS hosts,
               count(h) AS host_count
        ORDER BY host_count DESC
    """,

    # ── Findings ────────────────────────────────────────────────────────────
    "all_findings": """
        MATCH (f:Finding)
        RETURN f.id AS id, f.title AS title, f.severity AS severity,
               f.description AS description
        ORDER BY
            CASE f.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
    """,

    "findings_by_severity": """
        MATCH (f:Finding)
        WHERE f.severity = $severity
        RETURN f.id AS id, f.title AS title, f.description AS description
    """,

    # ── MITRE ATT&CK ────────────────────────────────────────────────────────
    "mitre_technique_coverage": """
        MATCH (v:Vulnerability)-[:MAPS_TO]->(t:Technique)
        RETURN t.technique_id AS technique_id, t.name AS name,
               count(DISTINCT v) AS vuln_count
        ORDER BY vuln_count DESC
    """,
}
