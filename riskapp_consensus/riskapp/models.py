from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# -------------------------------------------------
# RPN eşikleri (istersen config'e taşıyabilirsin)
# -------------------------------------------------
RPN_CRITICAL_MIN = 28   # >= 28  → critical
RPN_MODERATE_MIN = 18   # 18..27 → moderate
RPN_LOW_MIN      = 9    #  9..17 → low
# <9 → acceptable


# --------------------------------
# Risk
# --------------------------------
class Risk(db.Model):
    __tablename__ = "risks"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    category = db.Column(db.String(100), nullable=True, index=True)
    description = db.Column(db.Text, nullable=True)
    owner = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(50), default="Open", index=True)

    # --- ek alanlar ---
    risk_type = db.Column(db.String(20), nullable=True)       # "product" | "project" | serbest
    responsible = db.Column(db.String(120), nullable=True)    # Sorumlu kişi/ekip
    mitigation = db.Column(db.Text, nullable=True)            # Önlemler / faaliyetler

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    evaluations = db.relationship(
        "Evaluation", backref="risk", cascade="all, delete-orphan", lazy=True
    )
    comments = db.relationship(
        "Comment", backref="risk", cascade="all, delete-orphan", lazy=True
    )

    # ---- 2D metrikler (P×S)
    def avg_prob(self):
        vals = [e.probability for e in self.evaluations if e.probability]
        return sum(vals) / len(vals) if vals else None

    def avg_sev(self):
        vals = [e.severity for e in self.evaluations if e.severity]
        return sum(vals) / len(vals) if vals else None

    def score(self):
        """Olasılık × Şiddet (1–25)."""
        ap, asv = self.avg_prob(), self.avg_sev()
        if ap is None or asv is None:
            return None
        return round(ap * asv, 2)

    def score_band(self):
        """
        Renk/şiddet bandı: low / mid / high
        (UI'da .score-low / .score-mid / .score-high)
        """
        s = self.score()
        if s is None:
            return None
        if s <= 6:
            return "low"
        if s <= 15:
            return "mid"
        return "high"

    # ---- 3D metrikler (P×S×D = RPN)  → Decision/Acceptance için
    def avg_det(self):
        vals = [e.detection for e in self.evaluations if e.detection]
        return sum(vals) / len(vals) if vals else None

    def last_rpn(self):
        """Son değerlendirmenin RPN’i (varsa)."""
        if not self.evaluations:
            return None
        last = sorted(
            self.evaluations,
            key=lambda e: e.created_at or datetime.min
        )[-1]
        return last.rpn()

    def avg_rpn(self):
        vals = [e.rpn() for e in self.evaluations if e.rpn() is not None]
        return round(sum(vals) / len(vals), 2) if vals else None

    def grade(self):
        """
        Ortalama RPN'e göre sınıf:
        'critical' | 'moderate' | 'low' | 'acceptable'
        """
        rpn = self.avg_rpn()
        if rpn is None:
            return None
        if rpn >= RPN_CRITICAL_MIN:
            return "critical"
        if rpn >= RPN_MODERATE_MIN:
            return "moderate"
        if rpn >= RPN_LOW_MIN:
            return "low"
        return "acceptable"

    def __repr__(self):
        return f"<Risk id={self.id} title={self.title!r} status={self.status}>"


# --------------------------------
# Değerlendirme
# --------------------------------
class Evaluation(db.Model):
    __tablename__ = "evaluations"

    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey("risks.id"), nullable=False, index=True)
    evaluator = db.Column(db.String(120), nullable=True)

    probability = db.Column(db.Integer, nullable=False)  # 1..5
    severity    = db.Column(db.Integer, nullable=False)  # 1..5
    detection   = db.Column(db.Integer, nullable=True)   # 1..5 (opsiyonel; yoksa 1 kabul)
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def rpn(self):
        """P×S×D (D yoksa 1 kabul edilir)."""
        if not self.probability or not self.severity:
            return None
        d = self.detection if self.detection else 1
        return self.probability * self.severity * d

    def __repr__(self):
        return f"<Eval risk={self.risk_id} P={self.probability} S={self.severity} D={self.detection or 1}>"


# --------------------------------
# Yorum
# --------------------------------
class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey("risks.id"), nullable=False, index=True)
    text = db.Column(db.Text, nullable=False)
    is_system = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Comment risk={self.risk_id} system={self.is_system}>"


# --------------------------------
# Öneri (kategoriye göre)
# --------------------------------
class Suggestion(db.Model):
    __tablename__ = "suggestions"

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False, index=True)
    text = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<Suggestion cat={self.category!r}>"


# --------------------------------
# Hesap
# --------------------------------
class Account(db.Model):
    __tablename__ = "accounts"

    id = db.Column(db.Integer, primary_key=True)
    language = db.Column(db.String(20), default="Türkçe")
    contact_name = db.Column(db.String(120), nullable=False)   # Yetkili Kişi
    contact_title = db.Column(db.String(120), nullable=True)   # Yetkili Ünvanı
    email = db.Column(db.String(200), unique=True, nullable=False, index=True)
    role = db.Column(db.String(20), default="uzman")           # admin | uzman
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Account {self.email} role={self.role}>"


# --------------------------------
# Proje/İşyeri Bilgisi
# --------------------------------
class ProjectInfo(db.Model):
    __tablename__ = "project_info"

    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey("accounts.id"), nullable=False, index=True)
    workplace_name = db.Column(db.String(200), nullable=False)   # İş yeri unvanı
    workplace_address = db.Column(db.Text, nullable=False)       # İş yeri adresi
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    account = db.relationship("Account", backref="projects")

    def __repr__(self):
        return f"<ProjectInfo id={self.id} name={self.workplace_name!r}>"
