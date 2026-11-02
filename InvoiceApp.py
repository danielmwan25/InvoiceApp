"""Small Flask invoice generator prepared for authenticated deployment."""
import io
import json
import os
import secrets
import smtplib
import sqlite3
import urllib.error
import urllib.request
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation
from email.message import EmailMessage

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask, abort, jsonify, redirect, request, send_file, session, url_for
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from werkzeug.middleware.proxy_fix import ProxyFix

secret_key = os.getenv("SECRET_KEY")
if not secret_key:
	raise RuntimeError("Set SECRET_KEY before starting the application")

app = Flask(__name__)
app.config.update(
	SECRET_KEY=secret_key,
	SESSION_COOKIE_HTTPONLY=True,
	SESSION_COOKIE_SAMESITE="Lax",
	SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() in {"1", "true", "yes"},
	PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
DB = os.getenv("INVOICE_DB", "invoices.sqlite3")
if os.getenv("RENDER"):
	app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
limiter = Limiter(get_remote_address, app=app, storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
				  default_limits=[])


def connect():
	conn = sqlite3.connect(DB)
	conn.row_factory = sqlite3.Row
	return conn


with connect() as db:
	db.execute("""CREATE TABLE IF NOT EXISTS invoices (
		id INTEGER PRIMARY KEY, number TEXT UNIQUE, client TEXT, email TEXT,
		issued TEXT, currency TEXT, items TEXT, total TEXT, etims_ref TEXT)""")


def get_csrf_token():
	token = session.get("csrf_token")
	if token is None:
		token = secrets.token_urlsafe(32)
		session["csrf_token"] = token
	return token


@app.before_request
def protect_application():
	if request.endpoint == "health" or (request.endpoint == "login" and request.method == "GET"):
		return None
	if request.endpoint != "login" and not session.get("authenticated"):
		if request.is_json:
			return jsonify(error="Authentication required"), 401
		return redirect(url_for("login"))
	if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
		submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
		expected = session.get("csrf_token", "")
		if not submitted or not secrets.compare_digest(submitted, expected):
			if request.is_json:
				return jsonify(error="Invalid CSRF token"), 400
			abort(400, description="Invalid CSRF token")
	return None


@app.get("/healthz")
def health():
	return jsonify(status="ok")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
	if request.method == "GET":
		return f'''<!doctype html><title>Invoice app login</title>
		<h1>Invoice app login</h1>
		<form method="post">
		<input type="hidden" name="csrf_token" value="{get_csrf_token()}">
		<label>Username <input name="username" autocomplete="username" required></label><br>
		<label>Password <input name="password" type="password" autocomplete="current-password" required></label><br>
		<button>Sign in</button></form>'''

	configured_user = os.getenv("ADMIN_USERNAME", "")
	configured_password = os.getenv("ADMIN_PASSWORD", "")
	if not configured_user or not configured_password:
		return "Set ADMIN_USERNAME and ADMIN_PASSWORD in the service environment.", 503
	username = request.form.get("username", "").encode("utf-8")
	password = request.form.get("password", "").encode("utf-8")
	valid_user = secrets.compare_digest(username, configured_user.encode("utf-8"))
	valid_password = secrets.compare_digest(password, configured_password.encode("utf-8"))
	if not (valid_user & valid_password):
		return "Invalid username or password.", 401

	session.clear()
	session.permanent = True
	session["authenticated"] = True
	get_csrf_token()
	return redirect(url_for("home"))


@app.post("/logout")
def logout():
	session.clear()
	return redirect(url_for("login"))


def invoice(invoice_id):
	with connect() as db:
		row = db.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
	if row is None:
		abort(404)
	return row


def make_pdf(inv):
	out = io.BytesIO()
	pdf = canvas.Canvas(out, pagesize=A4)
	pdf.setTitle("Invoice " + inv["number"])
	y = 790
	pdf.setFont("Helvetica-Bold", 18)
	pdf.drawString(50, y, os.getenv("SELLER_NAME", "Your Business")[:80])
	y -= 35
	pdf.setFont("Helvetica", 11)
	for text in ("INVOICE " + inv["number"], "Date: " + inv["issued"],
				 "Bill to: " + inv["client"], "Email: " + inv["email"]):
		pdf.drawString(50, y, text[:100])
		y -= 22
	y -= 12
	pdf.setFont("Helvetica-Bold", 10)
	pdf.drawString(50, y, "Item")
	pdf.drawString(340, y, "Qty")
	pdf.drawString(420, y, "Unit price")
	pdf.drawString(520, y, "Amount")
	y -= 18
	pdf.setFont("Helvetica", 10)
	for item in json.loads(inv["items"]):
		if y < 70:
			pdf.showPage()
			y = 790
			pdf.setFont("Helvetica", 10)
		pdf.drawString(50, y, item["description"][:45])
		pdf.drawRightString(375, y, item["quantity"])
		pdf.drawRightString(485, y, item["unit_price"])
		pdf.drawRightString(550, y, item["line_total"])
		y -= 18
	pdf.setFont("Helvetica-Bold", 12)
	pdf.drawRightString(550, y - 10, f"Total: {inv['currency']} {inv['total']}")
	pdf.save()
	out.seek(0)
	return out


@app.get("/")
def home():
	return f'''<!doctype html><title>Invoice generator</title><h1>Create invoice</h1>
	<form method="post" action="/invoices">
	<input type="hidden" name="csrf_token" value="{get_csrf_token()}">
	<label>Number <input name="number" required></label><br>
	<label>Client <input name="client" required></label><br>
	<label>Email <input name="email" type="email" required></label><br>
	<label>Currency <input name="currency" value="KES" maxlength="3"></label><br>
	<label>Items, one per line: description, quantity, unit price<br>
	<textarea name="items" required placeholder="Consulting, 2, 1500"></textarea></label><br>
	<button>Create invoice</button></form>
	<form method="post" action="/logout">
	<input type="hidden" name="csrf_token" value="{get_csrf_token()}">
	<button>Sign out</button></form>'''


@app.post("/invoices")
def create_invoice():
	data = request.get_json(silent=True) if request.is_json else request.form
	try:
		if not hasattr(data, "get"):
			raise ValueError("Request body must be an object")
		number, client = str(data.get("number", "")).strip(), str(data.get("client", "")).strip()
		email = str(data.get("email", "")).strip()
		currency = str(data.get("currency", "KES")).upper().strip()
		if not number or not client or "@" not in email or len(currency) != 3:
			raise ValueError("Enter invoice number, client, valid email, and 3-letter currency")
		raw = data.get("items", [])
		if isinstance(raw, str):
			raw = [line.split(",", 2) for line in raw.splitlines() if line.strip()]
		if not isinstance(raw, list) or not raw:
			raise ValueError("Add at least one item")
		items, total = [], Decimal("0.00")
		for item in raw:
			if isinstance(item, dict):
				desc, qty, price = item.get("description"), item.get("quantity"), item.get("unit_price")
			else:
				if not isinstance(item, (list, tuple)) or len(item) != 3:
					raise ValueError("Each item needs description, quantity, unit price")
				desc, qty, price = item
			qty, price = Decimal(str(qty)), Decimal(str(price))
			if desc is None or not str(desc).strip() or not qty.is_finite() or qty <= 0 or not price.is_finite() or price < 0:
				raise ValueError("Invalid item details or amount")
			price = price.quantize(Decimal("0.01"))
			line_total = (qty * price).quantize(Decimal("0.01"))
			items.append({"description": str(desc).strip(), "quantity": str(qty),
						  "unit_price": str(price), "line_total": str(line_total)})
			total += line_total
		with connect() as db:
			cur = db.execute("INSERT INTO invoices(number,client,email,issued,currency,items,total) VALUES(?,?,?,?,?,?,?)",
							 (number, client, email, date.today().isoformat(), currency,
							  json.dumps(items), str(total)))
			invoice_id = cur.lastrowid
		if request.is_json:
			return jsonify(id=invoice_id, number=number, total=str(total)), 201
		return f'Created. <a href="/invoices/{invoice_id}/pdf">Download PDF</a> | <a href="/">New invoice</a>'
	except (ValueError, TypeError, InvalidOperation, sqlite3.IntegrityError) as error:
		return jsonify(error=str(error)), 400


@app.get("/invoices/<int:invoice_id>/pdf")
def download_pdf(invoice_id):
	inv = invoice(invoice_id)
	return send_file(make_pdf(inv), mimetype="application/pdf", as_attachment=True,
					 download_name=f"invoice-{inv['number']}.pdf")


@app.post("/invoices/<int:invoice_id>/email")
def email_invoice(invoice_id):
	inv = invoice(invoice_id)
	if not os.getenv("SMTP_HOST") or not os.getenv("SMTP_FROM"):
		return jsonify(error="Configure SMTP_HOST and SMTP_FROM"), 503
	if os.getenv("SMTP_USER") and not os.getenv("SMTP_PASSWORD"):
		return jsonify(error="Configure SMTP_PASSWORD when SMTP_USER is set"), 503
	msg = EmailMessage()
	msg["Subject"] = "Invoice " + inv["number"]
	msg["From"], msg["To"] = os.environ["SMTP_FROM"], inv["email"]
	msg.set_content(f"Hello {inv['client']},\nPlease find invoice {inv['number']} attached.")
	msg.add_attachment(make_pdf(inv).getvalue(), maintype="application", subtype="pdf",
					   filename=f"invoice-{inv['number']}.pdf")
	with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.getenv("SMTP_PORT", "587")), timeout=20) as smtp:
		smtp.starttls()
		if os.getenv("SMTP_USER"):
			smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
		smtp.send_message(msg)
	return jsonify(status="sent", to=inv["email"])


@app.post("/invoices/<int:invoice_id>/etims")
def submit_etims(invoice_id):
	inv = invoice(invoice_id)
	endpoint, token = os.getenv("ETIMS_URL"), os.getenv("ETIMS_TOKEN")
	if not endpoint or not token:
		return jsonify(error="Configure ETIMS_URL and ETIMS_TOKEN"), 503
	payload = {"invoice_number": inv["number"], "issued": inv["issued"],
			   "seller_tax_id": os.getenv("SELLER_TAX_ID", ""), "buyer": inv["client"],
			   "currency": inv["currency"], "items": json.loads(inv["items"]), "total": inv["total"]}
	try:
		req = urllib.request.Request(
			endpoint, data=json.dumps(payload).encode("utf-8"), method="POST",
			headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
		with urllib.request.urlopen(req, timeout=20) as response:
			result = json.loads(response.read().decode("utf-8"))
		reference = str(result.get("reference", ""))[:200]
		if not reference:
			return jsonify(error="eTIMS response missing reference"), 502
		with connect() as db:
			db.execute("UPDATE invoices SET etims_ref=? WHERE id=?", (reference, invoice_id))
		return jsonify(status="submitted", reference=reference)
	except (urllib.error.URLError, ValueError) as error:
		return jsonify(error=f"eTIMS request failed: {error}"), 502


if __name__ == "__main__":
	app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
