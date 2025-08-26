import os
<<<<<<< HEAD
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE = os.getenv("SUPABASE_SERVICE_ROLE")  # optional, backend-only
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@ceasa.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
BUCKET = os.getenv("SUPABASE_BUCKET", "rateios")

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise RuntimeError("Defina SUPABASE_URL e SUPABASE_ANON_KEY no .env (ou nas variáveis do Render)")

# Supabase clients
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
supabase_admin: Client | None = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE) if SUPABASE_SERVICE_ROLE else None

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "troque-esta-chave")
app.permanent_session_lifetime = timedelta(hours=6)

# Utils
def is_admin():
    return session.get("is_admin") is True

def normalize_cnpj(v: str) -> str:
    return "".join([c for c in (v or "") if c.isdigit()])

def ensure_bucket():
    try:
        supabase.storage.from_(BUCKET).list("", {"limit": 1})
    except Exception:
        if supabase_admin:
            try:
                supabase_admin.storage.create_bucket(BUCKET, {"public": False})
            except Exception:
                pass

ensure_bucket()

# Routes
=======
from flask import Flask, render_template, request, redirect, url_for, session, flash
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Carregar variáveis
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("❌ Erro: SUPABASE_URL ou SUPABASE_ANON_KEY não definidos no .env")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
app.secret_key = "super_secret_key"

# ================= HOME =================
>>>>>>> 76d5f6d (primeiro commit)
@app.route("/")
def home():
    return render_template("home.html")

<<<<<<< HEAD
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        cnpj = normalize_cnpj(request.form.get("cnpj", ""))
        nome = request.form.get("nome", "").strip()
        box = request.form.get("box", "").strip()
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        if not (cnpj and len(cnpj) == 14 and nome and box and email and senha):
            flash("Preencha todos os campos (CNPJ com 14 dígitos).", "danger")
            return redirect(url_for("register"))
        # Auth signup
        try:
            supabase.auth.sign_up({"email": email, "password": senha})
        except Exception as e:
            flash(f"Erro no cadastro do usuário: {e}", "danger")
            return redirect(url_for("register"))
        # Insert empresa
        try:
            client = supabase_admin or supabase
            client.table("empresas").insert({"cnpj": cnpj, "nome": nome, "box": box, "email": email}).execute()
        except Exception as e:
            flash(f"Erro ao salvar dados da empresa: {e}", "danger")
            return redirect(url_for("register"))
        flash("Empresa cadastrada! Faça login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario","").strip()
        senha = request.form.get("senha","")
        email_login = usuario
        display_name = None
        if "@" not in usuario:
            cnpj = normalize_cnpj(usuario)
            if len(cnpj) != 14:
                flash("CNPJ inválido.", "danger")
                return redirect(url_for("login"))
            try:
                resp = supabase.table("empresas").select("email,nome").eq("cnpj", cnpj).single().execute()
                if not resp.data:
                    flash("CNPJ não encontrado.", "danger")
                    return redirect(url_for("login"))
                email_login = resp.data["email"]
                display_name = resp.data.get("nome")
            except Exception as e:
                flash(f"Erro ao buscar CNPJ: {e}", "danger")
                return redirect(url_for("login"))
        try:
            supabase.auth.sign_in_with_password({"email": email_login, "password": senha})
        except Exception as e:
            flash(f"Erro no login: {e}", "danger")
            return redirect(url_for("login"))
        session["user"] = {"email": email_login, "nome": display_name}
        session["is_admin"] = (email_login == ADMIN_EMAIL)
        flash("Login realizado.", "success")
        if session["is_admin"]:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("meus_arquivos"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Sessão encerrada.", "info")
    return redirect(url_for("home"))

@app.route("/me/arquivos")
def meus_arquivos():
    if not session.get("user"):
        flash("Faça login.", "warning")
        return redirect(url_for("login"))
    email = session["user"]["email"]
    try:
        files = supabase.storage.from_(BUCKET).list(email) or []
    except Exception:
        files = []
    signed = []
    for f in files:
        try:
            url = supabase.storage.from_(BUCKET).create_signed_url(f"{email}/{f['name']}", 3600)
            signed.append({"name": f["name"], "url": url.get("signedURL") or url.get("signed_url")})
        except Exception:
            pass
    return render_template("meus_arquivos.html", arquivos=signed, email=email, nome=session["user"].get("nome"))

# Admin
@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        senha = request.form.get("senha","")
        if email == ADMIN_EMAIL and senha == ADMIN_PASSWORD:
            session["user"] = {"email": email, "nome": "Admin"}
            session["is_admin"] = True
            flash("Admin logado.", "success")
            return redirect(url_for("admin_dashboard"))
        flash("Credenciais inválidas.", "danger")
    return render_template("admin_login.html")

@app.route("/admin")
def admin_dashboard():
    if not is_admin():
        flash("Acesso restrito ao administrador.", "warning")
        return redirect(url_for("admin_login"))
    return render_template("admin_dashboard.html")

@app.route("/admin/empresas")
def admin_empresas():
    if not is_admin():
        flash("Acesso restrito ao administrador.", "warning")
        return redirect(url_for("admin_login"))
    q = (request.args.get("q") or "").strip()
    filtro = (request.args.get("filtro") or "nome")
    query = supabase.table("empresas").select("*")
    if q:
        if filtro == "cnpj":
            query = query.ilike("cnpj", f"%{normalize_cnpj(q)}%")
        elif filtro == "box":
            query = query.ilike("box", f"%{q}%")
        else:
            query = query.ilike("nome", f"%{q}%")
    data = query.order("nome").limit(200).execute().data or []
    return render_template("admin_empresas.html", empresas=data, q=q, filtro=filtro)

@app.route("/admin/empresa/<email>/editar", methods=["GET","POST"])
def admin_editar_empresa(email):
    if not is_admin():
        flash("Acesso restrito ao administrador.", "warning")
        return redirect(url_for("admin_login"))
    email = email.lower()
    if request.method == "POST":
        nome = request.form.get("nome","").strip()
        box = request.form.get("box","").strip()
        cnpj = normalize_cnpj(request.form.get("cnpj",""))
        try:
            (supabase_admin or supabase).table("empresas").update(
                {"nome": nome, "box": box, "cnpj": cnpj}
            ).eq("email", email).execute()
            flash("Empresa atualizada.", "success")
        except Exception as e:
            flash(f"Erro ao atualizar: {e}", "danger")
        return redirect(url_for("admin_empresas"))
    emp = supabase.table("empresas").select("*").eq("email", email).single().execute().data
    return render_template("admin_editar.html", emp=emp)

@app.route("/admin/upload", methods=["GET","POST"])
def admin_upload():
    if not is_admin():
        flash("Acesso restrito ao administrador.", "warning")
        return redirect(url_for("admin_login"))
    if request.method == "POST":
        alvo = request.form.get("email","").strip().lower()
        if not alvo:
            flash("Informe o e-mail da empresa.", "warning")
            return redirect(url_for("admin_upload"))
        files = request.files.getlist("arquivos")
        ok, fails = 0, 0
        for f in files:
            if not f or not f.filename:
                continue
            if not f.filename.lower().endswith(".pdf"):
                fails += 1
                continue
            filename = secure_filename(f.filename)
            path = f"{alvo}/{filename}"
            try:
                supabase.storage.from_(BUCKET).upload(path, f.read(), {"upsert": True})
                ok += 1
            except Exception:
                fails += 1
        flash(f"Upload concluído. Sucesso: {ok} | Falhas: {fails}", "info")
        return redirect(url_for("admin_upload"))
    empresas = supabase.table("empresas").select("email,nome,box,cnpj").order("nome").limit(200).execute().data or []
    return render_template("admin_upload.html", empresas=empresas)

# Local dev
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
=======
# ================= CADASTRO =================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        cnpj = request.form["cnpj"]
        nome = request.form["nome"]
        box = request.form["box"]
        email = request.form["email"]
        senha = generate_password_hash(request.form["senha"])

        supabase.table("empresas").insert({
            "cnpj": cnpj,
            "nome": nome,
            "box": box,
            "email": email,
            "senha": senha
        }).execute()

        flash("✅ Empresa cadastrada com sucesso!")
        return redirect(url_for("login"))
    return render_template("register.html")

# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        senha = request.form["senha"]

        empresa = supabase.table("empresas").select("*").eq("email", email).execute()
        if empresa.data and check_password_hash(empresa.data[0]["senha"], senha):
            session["empresa_id"] = empresa.data[0]["id"]
            session["nome"] = empresa.data[0]["nome"]
            return redirect(url_for("dashboard"))
        elif email == "admin@ceasa.com" and senha == "admin123":
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        else:
            flash("❌ Credenciais inválidas")
    return render_template("login.html")

# ================= DASHBOARD EMPRESA =================
@app.route("/dashboard")
def dashboard():
    if "empresa_id" not in session:
        return redirect(url_for("login"))

    arquivos = supabase.table("arquivos").select("*").eq("empresa_id", session["empresa_id"]).execute()
    return render_template("dashboard.html", arquivos=arquivos.data, nome=session["nome"])

# ================= DASHBOARD ADMIN =================
@app.route("/admin", methods=["GET", "POST"])
def admin_dashboard():
    if "admin" not in session:
        return redirect(url_for("login"))

    empresas = supabase.table("empresas").select("*").execute()

    if request.method == "POST":
        empresa_id = request.form["empresa_id"]
        file = request.files["arquivo"]

        # Upload para bucket do Supabase
        supabase.storage.from_("pdfs").upload(file.filename, file.read())
        url = supabase.storage.from_("pdfs").get_public_url(file.filename)

        supabase.table("arquivos").insert({
            "empresa_id": empresa_id,
            "nome_arquivo": file.filename,
            "url": url
        }).execute()

        flash("✅ Arquivo enviado com sucesso!")

    return render_template("admin_dashboard.html", empresas=empresas.data)

# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
>>>>>>> 76d5f6d (primeiro commit)
