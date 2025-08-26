from flask import Flask, render_template, request, redirect, session, url_for
from supabase import create_client, Client
from dotenv import load_dotenv
import os

# 🔹 Carregar variáveis do .env
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("❌ Erro: SUPABASE_URL ou SUPABASE_ANON_KEY não definidos no .env")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# 🔹 Inicializar Flask
app = Flask(__name__)
app.secret_key = "supersegredo123"  # troque por algo mais seguro depois

# ================================
# Rotas
# ================================

@app.route("/")
def home():
    if "user" in session:
        return render_template("home.html", user=session["user"], role=session.get("role", "user"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        try:
            # 🔹 Login no Supabase
            result = supabase.auth.sign_in_with_password({"email": email, "password": password})

            if not result.user:
                return "❌ Usuário ou senha inválidos!"

            # 🔹 Armazena informações na sessão
            session["user"] = result.user.email
            session["role"] = result.user.user_metadata.get("role", "user")

            # 🔹 Redireciona dependendo do papel
            if session["role"] == "admin":
                return redirect(url_for("admin"))
            else:
                return redirect(url_for("home"))

        except Exception as e:
            return f"Erro ao logar: {e}"

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin")
def admin():
    if "user" not in session or session.get("role") != "admin":
        return "🚫 Acesso negado. Apenas administradores podem acessar."
    return render_template("admin.html", user=session["user"])

# ================================
# Inicializar
# ================================
if __name__ == "__main__":
    app.run(debug=True)
