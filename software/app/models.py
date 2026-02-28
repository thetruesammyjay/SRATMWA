from app import db
from datetime import datetime


# ─────────────────────────────────────────────────────────
#  ASSET
# ─────────────────────────────────────────────────────────
class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    layer = db.Column(db.String(100), nullable=False)   # e.g. Client, API, Auth, Data
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    threats = db.relationship("Threat", backref="asset", lazy=True, cascade="all, delete-orphan")
    risks = db.relationship("RiskEntry", backref="asset", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "layer": self.layer,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────
#  THREAT
# ─────────────────────────────────────────────────────────

STRIDE_CATEGORIES = ["Spoofing", "Tampering", "Repudiation",
                     "Information Disclosure", "Denial of Service",
                     "Elevation of Privilege"]

class Threat(db.Model):
    __tablename__ = "threats"

    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(db.String(50), unique=True, nullable=False)  # THREAT-S-AUTH-001
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=True)
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text)

    # STRIDE classification
    stride_category = db.Column(db.String(50), nullable=False)  # one of STRIDE_CATEGORIES

    # DREAD scores (1–10 each)
    dread_damage = db.Column(db.Integer, default=5)
    dread_reproducibility = db.Column(db.Integer, default=5)
    dread_exploitability = db.Column(db.Integer, default=5)
    dread_affected_users = db.Column(db.Integer, default=5)
    dread_discoverability = db.Column(db.Integer, default=5)

    # PASTA stage (1–7)
    pasta_stage = db.Column(db.Integer, default=1)

    # Attack vector / entry point
    entry_point = db.Column(db.String(200))
    attack_vector = db.Column(db.String(100))   # Network, Adjacent, Local, Physical

    mitigations = db.Column(db.Text)
    status = db.Column(db.String(50), default="Open")   # Open, Mitigated, Accepted, Transferred
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    risk_entries = db.relationship("RiskEntry", backref="threat", lazy=True, cascade="all, delete-orphan")

    @property
    def dread_score(self):
        return round(
            (self.dread_damage + self.dread_reproducibility +
             self.dread_exploitability + self.dread_affected_users +
             self.dread_discoverability) / 5, 2
        )

    def to_dict(self):
        return {
            "id": self.id,
            "threat_id": self.threat_id,
            "asset_id": self.asset_id,
            "title": self.title,
            "description": self.description,
            "stride_category": self.stride_category,
            "dread": {
                "damage": self.dread_damage,
                "reproducibility": self.dread_reproducibility,
                "exploitability": self.dread_exploitability,
                "affected_users": self.dread_affected_users,
                "discoverability": self.dread_discoverability,
                "score": self.dread_score,
            },
            "pasta_stage": self.pasta_stage,
            "entry_point": self.entry_point,
            "attack_vector": self.attack_vector,
            "mitigations": self.mitigations,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────
#  VULNERABILITY
# ─────────────────────────────────────────────────────────
class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    vuln_id = db.Column(db.String(50), unique=True, nullable=False)   # e.g. VULN-001
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text)
    owasp_category = db.Column(db.String(100))     # A01:2021 – Broken Access Control
    cve_id = db.Column(db.String(50))
    cvss_score = db.Column(db.Float, default=0.0)  # 0.0 – 10.0
    cvss_vector = db.Column(db.String(200))
    severity = db.Column(db.String(20))            # Critical, High, Medium, Low, Informational
    affected_component = db.Column(db.String(200))
    proof_of_concept = db.Column(db.Text)
    remediation = db.Column(db.Text)
    status = db.Column(db.String(50), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "vuln_id": self.vuln_id,
            "title": self.title,
            "description": self.description,
            "owasp_category": self.owasp_category,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "affected_component": self.affected_component,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────
#  RISK ENTRY  (Risk Register)
# ─────────────────────────────────────────────────────────
class RiskEntry(db.Model):
    __tablename__ = "risk_entries"

    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.String(50), unique=True, nullable=False)   # RISK-AUTH-001
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=True)
    threat_id_fk = db.Column(db.Integer, db.ForeignKey("threats.id"), nullable=True)

    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text)

    # NIST SP 800-30 / OWASP Risk Rating  (1–10 each)
    likelihood = db.Column(db.Integer, default=5)
    impact = db.Column(db.Integer, default=5)

    owner = db.Column(db.String(200))
    treatment = db.Column(db.String(50), default="Mitigate")  # Mitigate, Accept, Transfer, Avoid
    status = db.Column(db.String(50), default="Open")         # Open, In Progress, Closed
    due_date = db.Column(db.String(20))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def risk_score(self):
        return self.likelihood * self.impact

    @property
    def risk_level(self):
        score = self.risk_score
        if score >= 80:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        else:
            return "Low"

    def to_dict(self):
        return {
            "id": self.id,
            "risk_id": self.risk_id,
            "asset_id": self.asset_id,
            "threat_id": self.threat_id_fk,
            "title": self.title,
            "description": self.description,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "owner": self.owner,
            "treatment": self.treatment,
            "status": self.status,
            "due_date": self.due_date,
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────
#  CONTROL
# ─────────────────────────────────────────────────────────
class Control(db.Model):
    __tablename__ = "controls"

    id = db.Column(db.Integer, primary_key=True)
    control_id = db.Column(db.String(50), unique=True, nullable=False)
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text)
    control_type = db.Column(db.String(50))    # Preventive, Detective, Corrective
    nist_mapping = db.Column(db.String(200))   # e.g. NIST SP 800-53 AC-1
    owasp_mapping = db.Column(db.String(200))
    implementation_status = db.Column(db.String(50), default="Not Implemented")
    owner = db.Column(db.String(200))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "control_type": self.control_type,
            "nist_mapping": self.nist_mapping,
            "owasp_mapping": self.owasp_mapping,
            "implementation_status": self.implementation_status,
            "owner": self.owner,
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────
#  CHECKLIST ITEM
# ─────────────────────────────────────────────────────────
class ChecklistItem(db.Model):
    __tablename__ = "checklist_items"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(100), nullable=False)   # OWASP Top 10, Authentication, API, etc.
    item_code = db.Column(db.String(50))
    description = db.Column(db.Text, nullable=False)
    reference = db.Column(db.String(200))                # OWASP ASVS 2.1.1, NIST AC-7, etc.
    status = db.Column(db.String(50), default="Not Checked")  # Pass, Fail, N/A, Not Checked
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "domain": self.domain,
            "item_code": self.item_code,
            "description": self.description,
            "reference": self.reference,
            "status": self.status,
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────
#  REPORT
# ─────────────────────────────────────────────────────────
class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    report_type = db.Column(db.String(50), default="Technical")  # Executive, Technical
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "report_type": self.report_type,
            "content": self.content,
            "created_at": self.created_at.isoformat(),
        }
