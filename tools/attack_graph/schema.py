"""
Neo4j schema: 15 node types, 20+ relationship types for attack surface modeling.
"""

# 15 Node Types
NODE_TYPES = [
    "Target",        # Top-level target (domain, IP, program)
    "Host",          # Individual host/server
    "Service",       # Running service (HTTP, SSH, etc.)
    "Endpoint",      # API/URL endpoint
    "Parameter",     # Input parameter
    "Vulnerability", # CVE/CWE vulnerability
    "Exploit",       # Known exploit/PoC
    "Credential",    # Username, password, token
    "Technology",    # Framework, library, version
    "Asset",         # File, database, S3 bucket
    "Network",       # Network segment/CIDR
    "User",          # User/account
    "Permission",    # ACL/IAM permission
    "Finding",       # Security finding
    "Technique",     # MITRE ATT&CK technique
]

# 20+ Relationship Types
RELATIONSHIP_TYPES = [
    ("Target",        "CONTAINS",        "Host"),
    ("Target",        "CONTAINS",        "Network"),
    ("Host",          "RUNS",            "Service"),
    ("Host",          "BELONGS_TO",      "Network"),
    ("Service",       "EXPOSES",         "Endpoint"),
    ("Service",       "USES",            "Technology"),
    ("Service",       "HAS",             "Vulnerability"),
    ("Endpoint",      "ACCEPTS",         "Parameter"),
    ("Endpoint",      "REQUIRES",        "Credential"),
    ("Endpoint",      "LEADS_TO",        "Asset"),
    ("Parameter",     "TRIGGERS",        "Vulnerability"),
    ("Vulnerability", "HAS_EXPLOIT",     "Exploit"),
    ("Vulnerability", "MAPS_TO",         "Technique"),
    ("Exploit",       "GRANTS",          "Permission"),
    ("Exploit",       "YIELDS",          "Finding"),
    ("Credential",    "AUTHENTICATES",   "Service"),
    ("Credential",    "GRANTS",          "Permission"),
    ("Technology",    "HAS",             "Vulnerability"),
    ("User",          "HAS",             "Credential"),
    ("User",          "HAS",             "Permission"),
    ("Permission",    "ALLOWS_ACCESS",   "Asset"),
    ("Finding",       "EXPLOITS",        "Vulnerability"),
    ("Finding",       "AFFECTS",         "Asset"),
]

# Cypher constraints for uniqueness
CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Target) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Host) REQUIRE n.address IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.cve_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Exploit) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Finding) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Technique) REQUIRE n.technique_id IS UNIQUE",
]

# Indexes for performance
INDEXES = [
    "CREATE INDEX IF NOT EXISTS FOR (n:Service) ON (n.name)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Endpoint) ON (n.url)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Technology) ON (n.name, n.version)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Vulnerability) ON (n.severity)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Finding) ON (n.severity)",
]
