from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, current_app, Response
)
from werkzeug.security import generate_password_hash, check_password_hash

from datetime import datetime
from functools import wraps
from sqlalchemy import text  # ensure_schema için
from models import db, Risk, Evaluation, Comment, Suggestion, Account, ProjectInfo
from seeder import seed_if_empty

import csv
from io import StringIO


# -------------------------------------------------
# Şema güvence: eksik kolonlar varsa ekle (SQLite)
# -------------------------------------------------
def ensure_schema():
    """SQLite üzerinde basit ALTER kontrolleri (geriye dönük uyum)."""

    def has_col(table, col):
        res = db.session.execute(text(f"PRAGMA table_info({table})")).fetchall()
        return any(r[1] == col for r in res)

    changed = False

    # risks tablosu için yeni alanlar
    if not has_col("risks", "risk_type"):
        db.session.execute(text("ALTER TABLE risks ADD COLUMN risk_type TEXT"))
        changed = True
    if not has_col("risks", "responsible"):
        db.session.execute(text("ALTER TABLE risks ADD COLUMN responsible TEXT"))
        changed = True
    if not has_col("risks", "mitigation"):
        db.session.execute(text("ALTER TABLE risks ADD COLUMN mitigation TEXT"))
        changed = True

    # accounts.role
    if not has_col("accounts", "role"):
        db.session.execute(text("ALTER TABLE accounts ADD COLUMN role TEXT DEFAULT 'uzman'"))
        changed = True

    # evaluations.detection  (RPN için)
    if not has_col("evaluations", "detection"):
        db.session.execute(text("ALTER TABLE evaluations ADD COLUMN detection INTEGER"))
        changed = True

    if changed:
        db.session.commit()


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev-secret-change-me"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///riskapp.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["CONSENSUS_THRESHOLD"] = 30  # Konsensüs eşiği (“30 uzman”)

    db.init_app(app)

    with app.app_context():
        db.create_all()
        ensure_schema()
        seed_if_empty()

    # ---- Yardımcılar ----
    def role_required(role):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                if "username" not in session:
                    return redirect(url_for("welcome"))
                if session.get("role") != role:
                    flash("Bu işlemi yapmak için yetkiniz yok.", "danger")
                    return redirect(url_for("dashboard"))
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    @app.before_request
    def require_login():
        # Onboarding ve login sayfaları giriş gerektirmez
        allowed = {"static", "welcome", "login", "setup_step1", "setup_step2", "forgot_password"}
        if "username" not in session and request.endpoint not in allowed:
            return redirect(url_for("welcome"))

    # -----------------------
    #  Onboarding / Landing
    # -----------------------
    @app.route("/")
    def index():
        return redirect(url_for("welcome"))

    @app.route("/welcome")
    def welcome():
        return render_template("welcome.html")

    # -----------------------
    #  Giriş — e-posta + şifre
    # -----------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if Account.query.count() == 0:
            return redirect(url_for("setup_step1"))

        if request.method == "POST":
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            acc = Account.query.filter_by(email=email).first()
            if not acc or not check_password_hash(acc.password_hash, password):
                flash("E-posta veya şifre hatalı.", "danger")
                return render_template("login.html", email=email)

            session["account_id"] = acc.id
            session["username"] = acc.contact_name
            session["role"] = acc.role or "uzman"
            flash(f"Hoş geldin, {acc.contact_name}!", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("welcome"))

    # -----------------------
    #  Şifre Sıfırlama (Lokal)
    # -----------------------
    @app.route("/forgot", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = request.form.get("email", "").strip()
            new_pw = request.form.get("new_password", "")
            new_pw2 = request.form.get("new_password2", "")

            if not email or not new_pw or not new_pw2:
                flash("Lütfen tüm alanları doldurun.", "danger")
                return render_template("forgot.html", email=email)
            if new_pw != new_pw2:
                flash("Yeni şifreler eşleşmiyor.", "danger")
                return render_template("forgot.html", email=email)

            acc = Account.query.filter_by(email=email).first()
            if not acc:
                flash("Bu e-posta ile kayıt bulunamadı.", "danger")
                return render_template("forgot.html", email=email)

            acc.password_hash = generate_password_hash(new_pw)
            db.session.commit()
            flash("Şifre başarıyla güncellendi. Şimdi giriş yapabilirsiniz.", "success")
            return redirect(url_for("login"))

        return render_template("forgot.html")

    # -----------------------
    #  Dashboard
    # -----------------------
    @app.route("/dashboard")
    def dashboard():
        risks = Risk.query.order_by(Risk.updated_at.desc()).all()
        # 5x5 matris (olasılık × şiddet) dağılımı
        matrix = [[0] * 5 for _ in range(5)]
        for r in risks:
            ap, asv = r.avg_prob(), r.avg_sev()
            if ap and asv:
                pi = min(max(int(round(ap)), 1), 5) - 1
                si = min(max(int(round(asv)), 1), 5) - 1
                matrix[si][pi] += 1
        return render_template("dashboard.html", risks=risks, matrix=matrix)

    # -----------------------
    #  Risk Mitigation – Liste
    # -----------------------
    @app.route("/mitigation")
    def mitigation_list():
        """Hazırlanan / devam eden raporlar (riskler) listesi."""
        status = request.args.get("status", "").strip()
        q = request.args.get("q", "").strip()

        query = Risk.query
        if status:
            query = query.filter(Risk.status == status)
        if q:
            like = f"%{q}%"
            query = query.filter(
                (Risk.title.ilike(like)) |
                (Risk.category.ilike(like)) |
                (Risk.description.ilike(like))
            )

        risks = query.order_by(Risk.updated_at.desc()).all()
        return render_template("mitigation_list.html", risks=risks, q=q, status=status)

    # -----------------------
    #  CSV Export – Riskler
    # -----------------------
    @app.route("/risks/export.csv")
    def risks_export_csv():
        q = request.args.get("q", "").strip()
        status = request.args.get("status", "").strip()

        query = Risk.query
        if q:
            like = f"%{q}%"
            query = query.filter(
                (Risk.title.ilike(like)) |
                (Risk.category.ilike(like)) |
                (Risk.description.ilike(like))
            )
        if status:
            query = query.filter(Risk.status == status)

        risks = query.order_by(Risk.updated_at.desc()).all()

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "Başlık", "Kategori", "Durum", "Tip", "Sorumlu",
            "Oluşturma", "Güncelleme", "Olasılık(ort)", "Şiddet(ort)", "Skor"
        ])
        for r in risks:
            ap = r.avg_prob()
            sv = r.avg_sev()
            sc = r.score()
            writer.writerow([
                r.id,
                (r.title or "").strip(),
                r.category or "",
                r.status or "",
                r.risk_type or "",
                r.responsible or "",
                r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else "",
                r.updated_at.strftime("%Y-%m-%d %H:%M") if r.updated_at else "",
                f"{ap:.2f}" if ap is not None else "",
                f"{sv:.2f}" if sv is not None else "",
                sc if sc is not None else ""
            ])

        resp = Response(output.getvalue(), mimetype="text/csv; charset=utf-8")
        resp.headers["Content-Disposition"] = "attachment; filename=risks_export.csv"
        return resp

    # -----------------------
    #  Risk Tanımlama (liste seç + şablon ekle)
    # -----------------------
    @app.route("/identify", methods=["GET", "POST"])
    def risk_identify():
        # kategorilere göre gruplu liste
        def grouped():
            cats = {}
            for s in Suggestion.query.order_by(Suggestion.category).all():
                cats.setdefault(s.category, []).append(s)
            return cats

        categories = grouped()

        if request.method == "POST":
            action = request.form.get("action")

            # A) Yeni şablon (Suggestion) ekleme
            if action == "add_suggestion":
                new_cat = (request.form.get("new_category") or "").strip()
                new_txt = (request.form.get("new_text") or "").strip()
                if not new_cat or not new_txt:
                    flash("Kategori ve metin zorunludur.", "danger")
                    return render_template("risk_identify.html", categories=categories)

                db.session.add(Suggestion(category=new_cat, text=new_txt))
                db.session.commit()
                flash("Yeni risk şablonu eklendi.", "success")
                return render_template("risk_identify.html", categories=grouped())

            # B) Seçilen mevcut şablonlardan Risk oluşturma
            if action == "add_selected":
                selected_ids = request.form.getlist("selected")
                if not selected_ids:
                    flash("Lütfen en az bir risk seçin.", "danger")
                    return render_template("risk_identify.html", categories=categories)

                owner = session.get("username")
                cnt = 0
                for sid in selected_ids:
                    s = Suggestion.query.get(int(sid))
                    if not s:
                        continue
                    r = Risk(
                        title=s.text[:150],
                        category=s.category,
                        description=s.text,
                        owner=owner
                    )
                    db.session.add(r)
                    db.session.flush()
                    db.session.add(Comment(
                        risk_id=r.id,
                        text=f"Tanımlı risk seçildi: {datetime.utcnow().isoformat(timespec='seconds')} UTC",
                        is_system=True
                    ))
                    cnt += 1
                db.session.commit()
                flash(f"{cnt} risk eklendi.", "success")
                return redirect(url_for("dashboard"))

            flash("Geçersiz işlem.", "danger")

        return render_template("risk_identify.html", categories=categories)

    # -----------------------
    #  Yeni Risk
    # -----------------------
    @app.route("/risks/new", methods=["GET", "POST"])
    def risk_new():
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            category = request.form.get("category") or None
            description = request.form.get("description") or None
            risk_type = request.form.get("risk_type") or None
            responsible = request.form.get("responsible") or None
            mitigation = request.form.get("mitigation") or None

            if not title:
                flash("Başlık zorunludur.", "danger")
                return render_template("risk_new.html", form=request.form)

            owner = session.get("username")
            r = Risk(
                title=title,
                category=category,
                description=description,
                owner=owner,
                risk_type=risk_type,
                responsible=responsible,
                mitigation=mitigation,
            )
            db.session.add(r)
            db.session.commit()

            # İlk değerlendirme (varsa)
            p = request.form.get("probability")
            s = request.form.get("severity")
            d = request.form.get("detection")  # opsiyonel detection
            if p and s:
                try:
                    p = min(max(int(p), 1), 5)
                    s = min(max(int(s), 1), 5)
                    d_val = None
                    if d not in (None, ""):
                        d_val = min(max(int(d), 1), 5)

                    db.session.add(Evaluation(
                        risk_id=r.id,
                        evaluator=owner or "System",
                        probability=p,
                        severity=s,
                        detection=d_val,
                        comment="İlk değerlendirme"
                    ))
                    db.session.commit()
                except ValueError:
                    pass

            db.session.add(Comment(
                risk_id=r.id,
                text=f"Risk oluşturuldu: {datetime.utcnow().isoformat(timespec='seconds')} UTC",
                is_system=True
            ))
            db.session.commit()
            flash("Risk oluşturuldu.", "success")
            return redirect(url_for("risk_detail", risk_id=r.id))

        return render_template("risk_new.html")

    # -----------------------
    #  Risk Listesi / Arama
    # -----------------------
    @app.route("/risks")
    def risk_select():
        q = request.args.get("q", "").strip()
        query = Risk.query
        if q:
            like = f"%{q}%"
            query = query.filter(
                (Risk.title.ilike(like)) |
                (Risk.category.ilike(like)) |
                (Risk.description.ilike(like))
            )
        risks = query.order_by(Risk.updated_at.desc()).all()
        return render_template("risk_select.html", risks=risks, q=q)

    # -----------------------
    #  Risk Detay + Konsensüs Banner
    # -----------------------
    @app.route("/risks/<int:risk_id>", methods=["GET", "POST"])
    def risk_detail(risk_id):
        r = Risk.query.get_or_404(risk_id)
        if request.method == "POST":
            r.title = request.form.get("title", r.title)
            r.category = request.form.get("category", r.category)
            r.description = request.form.get("description", r.description)
            r.status = request.form.get("status", r.status)
            r.risk_type = request.form.get("risk_type", r.risk_type)
            r.responsible = request.form.get("responsible", r.responsible)
            r.mitigation = request.form.get("mitigation", r.mitigation)
            db.session.commit()
            db.session.add(Comment(
                risk_id=r.id,
                text=f"Risk düzenlendi: {datetime.utcnow().isoformat(timespec='seconds')} UTC",
                is_system=True
            ))
            db.session.commit()
            flash("Değişiklikler kaydedildi.", "success")
            return redirect(url_for("risk_detail", risk_id=r.id))

        # Kategoriye göre öneriler
        sugg = Suggestion.query.filter(Suggestion.category == (r.category or "")).all()

        # Konsensüs: aynı (P,Ş) çiftinden belirli eşik ve üzeri varsa banner
        threshold = int(current_app.config.get("CONSENSUS_THRESHOLD", 30))
        pair_counts = {}
        for e in r.evaluations:
            pair = (e.probability, e.severity)
            pair_counts[pair] = pair_counts.get(pair, 0) + 1
        consensus = None
        if pair_counts:
            (p, s), cnt = max(pair_counts.items(), key=lambda kv: kv[1])
            if cnt >= threshold:
                consensus = {"p": p, "s": s, "count": cnt}

        return render_template(
            "risk_detail.html",
            r=r,
            suggestions=sugg,
            consensus=consensus,
            threshold=threshold
        )

    # -----------------------
    #  Yorum / Değerlendirme
    # -----------------------
    @app.route("/risks/<int:risk_id>/comment", methods=["POST"])
    def add_comment(risk_id):
        r = Risk.query.get_or_404(risk_id)
        text = request.form.get("text", "").strip()
        if text:
            db.session.add(Comment(risk_id=r.id, text=text, is_system=False))
            db.session.commit()
        return redirect(url_for("risk_detail", risk_id=r.id))

    @app.route("/risks/<int:risk_id>/evaluation", methods=["POST"])
    def add_eval(risk_id):
        r = Risk.query.get_or_404(risk_id)
        evaluator = request.form.get("evaluator") or session.get("username")

        # P, S
        p = int(request.form.get("probability", "3"))
        s = int(request.form.get("severity", "3"))
        p = min(max(p, 1), 5)
        s = min(max(s, 1), 5)

        # D (opsiyonel)
        d_raw = request.form.get("detection")
        d_val = None
        if d_raw not in (None, ""):
            try:
                d_val = int(d_raw)
                d_val = min(max(d_val, 1), 5)
            except ValueError:
                d_val = None

        c = request.form.get("comment", "")

        db.session.add(Evaluation(
            risk_id=r.id,
            evaluator=evaluator,
            probability=p,
            severity=s,
            detection=d_val,  # detection kaydı
            comment=c
        ))
        # Değerlendirme eklendiyse durum "Assessed" olsun
        r.status = "Assessed"
        db.session.commit()
        flash("Değerlendirme eklendi.", "success")
        return redirect(url_for("risk_detail", risk_id=r.id))

    # -----------------------
    #  Raporlar
    # -----------------------
    @app.route("/reports")
    def reports():
        risks = Risk.query.order_by(Risk.updated_at.desc()).all()
        return render_template("reports.html", risks=risks)

    @app.route("/reports/<int:risk_id>")
    def report_view(risk_id):
        r = Risk.query.get_or_404(risk_id)
        suggestions = Suggestion.query.filter(Suggestion.category == (r.category or "")).all()
        return render_template("report_view.html", r=r, suggestions=suggestions)

    # -----------------------
    #  Kayıt — Figure 1 (a) ve (b)
    # -----------------------
    @app.route("/setup/1", methods=["GET", "POST"])
    def setup_step1():
        if request.method == "POST":
            lang = request.form.get("language") or "Türkçe"
            name = request.form.get("contact_name", "").strip()
            title = request.form.get("contact_title", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")

            if not name or not email or not password:
                flash("Lütfen tüm zorunlu alanları doldurun.", "danger")
                return render_template("setup_step1.html", form=request.form)

            existing = Account.query.filter_by(email=email).first()
            if existing:
                flash("Bu e-posta adresi zaten kayıtlı, lütfen giriş yapın.", "danger")
                return render_template("setup_step1.html", form=request.form)

            role = "admin" if Account.query.count() == 0 else "uzman"

            acc = Account(
                language=lang,
                contact_name=name,
                contact_title=title,
                email=email,
                password_hash=generate_password_hash(password),
                role=role
            )
            db.session.add(acc)
            db.session.commit()
            flash("Hesap oluşturuldu. Şimdi proje bilgilerini giriniz.", "success")

            session["account_id"] = acc.id
            session["username"] = acc.contact_name
            session["role"] = acc.role
            return redirect(url_for("setup_step2"))

        return render_template("setup_step1.html")

    @app.route("/setup/2", methods=["GET", "POST"])
    def setup_step2():
        if "account_id" not in session:
            flash("Önce giriş bilgilerini doldurun.", "danger")
            return redirect(url_for("setup_step1"))

        if request.method == "POST":
            name = request.form.get("workplace_name", "").strip()
            addr = request.form.get("workplace_address", "").strip()
            if not name or not addr:
                flash("İş yeri unvanı ve adres zorunludur.", "danger")
                return render_template("setup_step2.html", form=request.form)

            pi = ProjectInfo(
                account_id=session["account_id"],
                workplace_name=name,
                workplace_address=addr
            )
            db.session.add(pi)
            db.session.commit()
            flash("Proje bilgileri kaydedildi.", "success")
            return redirect(url_for("dashboard"))

        return render_template("setup_step2.html")

    # -----------------------
    #  AYARLAR — Hesap ve Proje
    # -----------------------
    @app.route("/settings/account", methods=["GET", "POST"])
    def settings_account():
        acc = Account.query.get(session.get("account_id"))
        if not acc:
            return redirect(url_for("logout"))

        if request.method == "POST":
            acc.contact_name = request.form.get("contact_name", acc.contact_name).strip()
            acc.contact_title = request.form.get("contact_title", acc.contact_title).strip()
            acc.language = request.form.get("language", acc.language).strip()

            current_pw = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            new_pw2 = request.form.get("new_password2", "")
            if new_pw or new_pw2:
                if not current_pw or not check_password_hash(acc.password_hash, current_pw):
                    flash("Mevcut şifre hatalı.", "danger")
                    return render_template("settings_account.html", acc=acc)
                if new_pw != new_pw2:
                    flash("Yeni şifreler eşleşmiyor.", "danger")
                    return render_template("settings_account.html", acc=acc)
                acc.password_hash = generate_password_hash(new_pw)

            db.session.commit()
            session["username"] = acc.contact_name
            flash("Hesap bilgileri güncellendi.", "success")
            return redirect(url_for("settings_account"))

        return render_template("settings_account.html", acc=acc)

    @app.route("/settings/project", methods=["GET", "POST"])
    def settings_project():
        acc_id = session.get("account_id")
        proj = ProjectInfo.query.filter_by(account_id=acc_id).order_by(ProjectInfo.created_at.desc()).first()
        if request.method == "POST":
            name = request.form.get("workplace_name", "").strip()
            addr = request.form.get("workplace_address", "").strip()
            if not name or not addr:
                flash("İş yeri unvanı ve adres zorunludur.", "danger")
                return render_template("settings_project.html", proj=proj)
            if proj:
                proj.workplace_name = name
                proj.workplace_address = addr
            else:
                proj = ProjectInfo(account_id=acc_id, workplace_name=name, workplace_address=addr)
                db.session.add(proj)
            db.session.commit()
            flash("Proje bilgileri güncellendi.", "success")
            return redirect(url_for("settings_project"))
        return render_template("settings_project.html", proj=proj)

    # -----------------------
    #  ADMIN — Kullanıcı Yönetimi
    # -----------------------
    @app.route("/admin/users", methods=["GET", "POST"])
    @role_required("admin")
    def admin_users():
        if request.method == "POST":
            uid = int(request.form.get("user_id"))
            new_role = request.form.get("new_role")
            if new_role not in {"admin", "uzman"}:
                flash("Geçersiz rol.", "danger")
                return redirect(url_for("admin_users"))
            acc = Account.query.get(uid)
            if not acc:
                flash("Kullanıcı bulunamadı.", "danger")
                return redirect(url_for("admin_users"))
            acc.role = new_role
            db.session.commit()
            flash(f"Kullanıcının rolü {new_role} olarak güncellendi.", "success")
            if uid == session.get("account_id"):
                session["role"] = new_role
            return redirect(url_for("admin_users"))

        users = Account.query.order_by(Account.created_at.desc()).all()
        return render_template("admin_users.html", users=users)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
