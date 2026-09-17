import http.server, json, os, uuid, urllib.parse, mimetypes, datetime, pathlib, html, time, re
from http import HTTPStatus

ROOT = pathlib.Path(__file__).parent
DATA_FILE = ROOT / "data.json"
UPLOADS = ROOT / "uploads"
STATIC = ROOT / "static"

UPLOADS.mkdir(exist_ok=True)

def load_data():
    if not DATA_FILE.exists():
        return {"owner":"baibhavcuteboy@gmail.com","adminPassword":"Baibhav@2026","subjects":[],"pdfs":[],"secretPdf":None,"easterRequests":[],"pendingTransfers":[],"allowedSecretEmails":[]}
    d=json.loads(DATA_FILE.read_text(encoding='utf-8'))
    if "allowedSecretEmails" not in d: d["allowedSecretEmails"]=[]
    if "pendingTransfers" not in d: d["pendingTransfers"]=[]
    return d

def save_data(d):
    DATA_FILE.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding='utf-8')

def is_admin(headers, data):
    auth = headers.get('Authorization','')
    if auth.startswith('Bearer '):
        try:
            token = auth[7:]
            email, pwd = token.split(':',1)
            if email.strip().lower() == data['owner'].strip().lower() and pwd.strip() == data['adminPassword']:
                return True
        except: pass
    return False

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(ROOT), **kw)

    def log_message(self, format, *args):
        print(f"[{self.client_address[0]}] {format%args}")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/api/config":
            d = load_data()
            # public config
            self.send_json({"owner": d["owner"], "subjects": d["subjects"], "pdfs": d["pdfs"], "secretPdf": d["secretPdf"] is not None, "secretTitle": d["secretPdf"]["title"] if d["secretPdf"] else None})
            return
        if path == "/api/search":
            q = qs.get("q",[""])[0].lower()
            d = load_data()
            res = [p for p in d["pdfs"] if q in p["title"].lower() or q in p["originalName"].lower()]
            self.send_json(res)
            return
        if path == "/api/easter/status":
            rid = qs.get("id",[""])[0]
            d = load_data()
            req = next((r for r in d["easterRequests"] if r["id"]==rid), None)
            if not req:
                self.send_json({"status":"not_found"},404)
                return
            # auto-expire after 5 minutes if pending
            if req["status"]=="pending":
                t = datetime.datetime.fromisoformat(req["time"])
                if (datetime.datetime.now() - t).total_seconds() > 300:
                    req["status"]="expired"
                    save_data(d)
            out = {"status": req["status"]}
            if req["status"]=="approved" and d["secretPdf"]:
                out["secretUrl"] = f"/uploads/{d['secretPdf']['filename']}"
                out["secretTitle"] = d["secretPdf"]["title"]
            self.send_json(out)
            return
        if path == "/api/easter/requests":
            d = load_data()
            if not is_admin(self.headers, d):
                self.send_json({"error":"unauthorized"},401); return
            self.send_json(d["easterRequests"])
            return
        if path == "/api/secret/allowed":
            d = load_data()
            if not is_admin(self.headers, d):
                self.send_json({"error":"unauthorized"},401); return
            self.send_json(d.get("allowedSecretEmails",[]))
            return
        if path == "/api/secret/check":
            email = qs.get("email",[""])[0].strip().lower()
            d = load_data()
            allowed = any(x["email"].lower()==email for x in d.get("allowedSecretEmails",[]))
            if allowed and d["secretPdf"]:
                self.send_json({"allowed":True, "secretUrl": f"/uploads/{d['secretPdf']['filename']}", "secretTitle": d["secretPdf"]["title"]})
            else:
                self.send_json({"allowed":allowed})
            return
        if path.startswith("/api/transfer/accept"):
            token = qs.get("token",[""])[0]
            d = load_data()
            t = next((x for x in d["pendingTransfers"] if x["token"]==token), None)
            if not t:
                self.send_html("<h1>Invalid or expired transfer link</h1>")
                return
            if t["status"] != "pending":
                self.send_html(f"<h1>Transfer already {t['status']}</h1>")
                return
            old_owner = d["owner"]
            d["owner"] = t["newEmail"]
            t["status"]="accepted"
            save_data(d)
            # log
            print(f"[TRANSFER] {old_owner} -> {d['owner']} accepted")
            self.send_html(f"<html><body style='font-family:sans-serif; max-width:600px; margin:40px auto; text-align:center'><h1>✅ Ownership Transferred!</h1><p>New owner: <b>{html.escape(d['owner'])}</b></p><p>Previous owner {html.escape(old_owner)} has been notified.</p><a href='/'>Go to site</a></body></html>")
            return
        if path == "/uploads/" or path.startswith("/uploads/"):
            return super().do_GET()
        if path == "/" or path == "/index.html":
            return super().do_GET()
        if path.startswith("/static/"):
            return super().do_GET()
        # fallback serve index
        if path in ["/admin", "/admin.html"]:
            self.path = "/index.html"
            return super().do_GET()
        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        d = load_data()

        if path == "/api/login":
            length = int(self.headers.get('Content-Length',0))
            body = json.loads(self.rfile.read(length) or b'{}')
            email = body.get("email","").strip().lower()
            pwd = body.get("password","")
            # email compare case-insensitive, password case-sensitive + strip outer spaces
            if email == d["owner"].strip().lower() and pwd.strip() == d["adminPassword"]:
                # token uses real owner email to keep is_admin working
                self.send_json({"ok":True, "token": f"{d['owner']}:{d['adminPassword']}", "owner": d["owner"]})
            else:
                self.send_json({"ok":False, "error":"Invalid email or password. Owner is "+d["owner"]},401)
            return

        if path == "/api/subjects":
            if not is_admin(self.headers, d):
                self.send_json({"error":"admin only"},401); return
            length = int(self.headers.get('Content-Length',0))
            body = json.loads(self.rfile.read(length) or b'{}')
            name = body.get("name","").strip()
            if not name:
                self.send_json({"error":"name required"},400); return
            sid = re.sub(r'[^a-z0-9]+','-', name.lower()).strip('-')
            if any(s["id"]==sid for s in d["subjects"]):
                sid = sid + "-" + uuid.uuid4().hex[:4]
            icon = body.get("icon","📚")
            d["subjects"].append({"id":sid,"name":name,"icon":icon})
            save_data(d)
            self.send_json({"ok":True,"subject":{"id":sid,"name":name,"icon":icon}})
            return

        if path.startswith("/api/subjects/") and path.endswith("/rename"):
            if not is_admin(self.headers, d): self.send_json({"error":"admin only"},401); return
            sid = path.split("/")[3]
            length = int(self.headers.get('Content-Length',0))
            body = json.loads(self.rfile.read(length) or b'{}')
            subj = next((s for s in d["subjects"] if s["id"]==sid), None)
            if not subj: self.send_json({"error":"not found"},404); return
            subj["name"] = body.get("name","").strip() or subj["name"]
            save_data(d)
            self.send_json({"ok":True})
            return

        if path == "/api/easter/request":
            length = int(self.headers.get('Content-Length',0))
            body_raw = self.rfile.read(length) if length else b'{}'
            try: body = json.loads(body_raw or b'{}')
            except: body={}
            name = body.get("name","").strip()
            email = body.get("email","").strip()
            if not name or not email:
                self.send_json({"ok":False,"error":"Name and Gmail required"},400); return
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                self.send_json({"ok":False,"error":"Invalid Gmail"},400); return
            # if already allowed, directly grant
            if any(x["email"].lower()==email.lower() for x in d.get("allowedSecretEmails",[])):
                # still create request as approved for audit
                req_id = uuid.uuid4().hex
                entry = {"id": req_id, "time": datetime.datetime.now().isoformat(), "status":"approved", "clientToken": uuid.uuid4().hex[:8], "ip": self.client_address[0], "name": name, "email": email}
                d["easterRequests"].append(entry)
                save_data(d)
                self.send_json({"ok":True, "id": req_id, "message":"Already approved — access granted", "alreadyAllowed": True})
                return
            req_id = uuid.uuid4().hex
            client_token = uuid.uuid4().hex[:8]
            entry = {"id": req_id, "time": datetime.datetime.now().isoformat(), "status":"pending", "clientToken": client_token, "ip": self.client_address[0], "name": name, "email": email}
            d["easterRequests"].append(entry)
            d["easterRequests"] = d["easterRequests"][-50:]
            save_data(d)
            print(f"[EASTER] New request {req_id} from {name} <{email}> -> notify {d['owner']}")
            self.send_json({"ok":True, "id": req_id, "message":"Request sent — waiting for approval", "note": f"(Demo) Owner {d['owner']} can Approve/Deny in admin panel."})
            return

        if path == "/api/easter/decide":
            if not is_admin(self.headers, d): self.send_json({"error":"owner only"},401); return
            length = int(self.headers.get('Content-Length',0))
            body = json.loads(self.rfile.read(length) or b'{}')
            rid = body.get("id")
            action = body.get("action") # approve / deny
            req = next((r for r in d["easterRequests"] if r["id"]==rid), None)
            if not req: self.send_json({"error":"not found"},404); return
            if action == "approve":
                req["status"]="approved"
                # grant persistent access until manually removed
                email = req.get("email","").strip()
                name = req.get("name","")
                if email and not any(x["email"].lower()==email.lower() for x in d.get("allowedSecretEmails",[])):
                    d.setdefault("allowedSecretEmails",[]).append({"email": email, "name": name, "approvedAt": datetime.datetime.now().isoformat(), "requestId": rid})
                save_data(d)
                self.send_json({"ok":True, "status": req["status"]})
                return
            elif action == "deny":
                # close denied requests immediately (do not keep clutter)
                email = (req.get("email") or "").lower()
                d["easterRequests"] = [r for r in d["easterRequests"] if r["id"]!=rid]
                # safety: ensure no allowed entry lingers
                if email:
                    d["allowedSecretEmails"]=[x for x in d.get("allowedSecretEmails",[]) if x.get("email","").lower()!=email]
                save_data(d)
                self.send_json({"ok":True, "status": "denied-closed"})
                return
            else:
                self.send_json({"error":"invalid action"},400); return
        if path == "/api/secret/revoke":
            if not is_admin(self.headers, d): self.send_json({"error":"owner only"},401); return
            length = int(self.headers.get('Content-Length',0))
            body = json.loads(self.rfile.read(length) or b'{}')
            email = body.get("email","").strip().lower()
            before=len(d.get("allowedSecretEmails",[]))
            d["allowedSecretEmails"]=[x for x in d.get("allowedSecretEmails",[]) if x["email"].lower()!=email]
            save_data(d)
            self.send_json({"ok":True, "removed": before - len(d["allowedSecretEmails"])})
            return

        if path == "/api/transfer/request":
            if not is_admin(self.headers, d): self.send_json({"error":"owner only"},401); return
            length = int(self.headers.get('Content-Length',0))
            body = json.loads(self.rfile.read(length) or b'{}')
            new_email = body.get("newEmail","").strip()
            if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
                self.send_json({"error":"invalid email"},400); return
            token = uuid.uuid4().hex
            d["pendingTransfers"].append({"token": token, "newEmail": new_email, "time": datetime.datetime.now().isoformat(), "status":"pending", "from": d["owner"]})
            save_data(d)
            link = f"http://{self.headers.get('Host','localhost:8000')}/api/transfer/accept?token={token}"
            print(f"[TRANSFER] Request {d['owner']} -> {new_email}  Link: {link}")
            self.send_json({"ok":True, "link": link, "message": f"Confirmation email simulated. Send this link to {new_email}: {link}"})
            return

        if path == "/api/upload":
            if not is_admin(self.headers, d): self.send_json({"error":"admin only"},401); return
            ctype = self.headers.get('Content-Type','')
            if 'multipart/form-data' not in ctype:
                self.send_json({"error":"use multipart"},400); return
            # custom multipart parser (no cgi in py3.13)
            length = int(self.headers.get('Content-Length',0))
            body_bytes = self.rfile.read(length)
            # extract boundary
            boundary = None
            for part in ctype.split(';'):
                part=part.strip()
                if part.startswith('boundary='):
                    boundary = part.split('=',1)[1].strip().strip('"')
                    break
            if not boundary:
                self.send_json({"error":"no boundary"},400); return
            fields, files = self.parse_multipart(body_bytes, boundary)
            subject_id = fields.get('subjectId')
            title = fields.get('title','')
            is_secret = fields.get('isSecret') == '1'
            fileinfo = files.get('file')
            if is_secret:
                if not fileinfo or not fileinfo[0]:
                    self.send_json({"error":"file required"},400); return
                filename, data_bytes = fileinfo
                ext = pathlib.Path(filename).suffix or '.pdf'
                fname = f"secret{ext}"
                fpath = UPLOADS / fname
                with open(fpath,'wb') as f: f.write(data_bytes)
                d["secretPdf"] = {"title": title or filename, "filename": fname}
                save_data(d)
                self.send_json({"ok":True, "secretPdf": d["secretPdf"]})
                return
            if not subject_id or not any(s["id"]==subject_id for s in d["subjects"]):
                self.send_json({"error":"invalid subject"},400); return
            if not fileinfo or not fileinfo[0]:
                self.send_json({"error":"file required"},400); return
            filename, data_bytes = fileinfo
            if not filename.lower().endswith('.pdf'):
                self.send_json({"error":"only PDF allowed"},400); return
            pid = uuid.uuid4().hex
            fname = f"{pid}.pdf"
            fpath = UPLOADS / fname
            with open(fpath,'wb') as f: f.write(data_bytes)
            pdf = {"id": pid, "subjectId": subject_id, "title": title or pathlib.Path(filename).stem, "filename": fname, "originalName": filename, "size": len(data_bytes)}
            d["pdfs"].append(pdf)
            save_data(d)
            self.send_json({"ok":True, "pdf": pdf})
            return

        self.send_json({"error":"not found"},404)

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        d = load_data()
        if not is_admin(self.headers, d):
            self.send_json({"error":"admin only"},401); return
        if path.startswith("/api/subjects/"):
            sid = path.split("/")[3]
            d["subjects"] = [s for s in d["subjects"] if s["id"]!=sid]
            # also remove pdfs in that subject? spec says delete subject, so delete its pdfs files
            to_del = [p for p in d["pdfs"] if p["subjectId"]==sid]
            for p in to_del:
                try: (UPLOADS / p["filename"]).unlink(missing_ok=True)
                except: pass
            d["pdfs"] = [p for p in d["pdfs"] if p["subjectId"]!=sid]
            save_data(d)
            self.send_json({"ok":True})
            return
        if path.startswith("/api/pdf/"):
            pid = path.split("/")[3]
            pdf = next((p for p in d["pdfs"] if p["id"]==pid), None)
            if not pdf: self.send_json({"error":"not found"},404); return
            try: (UPLOADS / pdf["filename"]).unlink(missing_ok=True)
            except: pass
            d["pdfs"] = [p for p in d["pdfs"] if p["id"]!=pid]
            save_data(d)
            self.send_json({"ok":True})
            return
        if path.startswith("/api/easter/"):
            # DELETE /api/easter/<id> -> manually remove/close request
            parts = path.split("/")
            if len(parts) >= 4 and parts[3]:
                rid = parts[3]
                req = next((r for r in d["easterRequests"] if r["id"]==rid), None)
                if not req: self.send_json({"error":"not found"},404); return
                # remove request
                d["easterRequests"] = [r for r in d["easterRequests"] if r["id"]!=rid]
                # if it was approved, also revoke persistent access (same email / requestId)
                email = (req.get("email") or "").lower()
                if req.get("status")=="approved" and email:
                    d["allowedSecretEmails"]=[x for x in d.get("allowedSecretEmails",[]) if x.get("requestId")!=rid and x.get("email","").lower()!=email]
                save_data(d)
                self.send_json({"ok":True})
                return
        self.send_json({"error":"not found"},404)

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        d = load_data()
        if not is_admin(self.headers, d):
            self.send_json({"error":"admin only"},401); return
        if path.startswith("/api/pdf/"):
            pid = path.split("/")[3]
            length = int(self.headers.get('Content-Length',0))
            body = json.loads(self.rfile.read(length) or b'{}')
            pdf = next((p for p in d["pdfs"] if p["id"]==pid), None)
            if not pdf: self.send_json({"error":"not found"},404); return
            if "title" in body:
                pdf["title"] = body["title"].strip() or pdf["title"]
            save_data(d)
            self.send_json({"ok":True, "pdf": pdf})
            return
        self.send_json({"error":"not found"},404)

    def send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Headers","Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods","GET,POST,PUT,DELETE,OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def parse_multipart(self, body, boundary):
        # returns (fields dict, files dict: name -> (filename, bytes))
        fields={}
        files={}
        delim = ('--' + boundary).encode()
        parts = body.split(delim)
        for part in parts:
            if not part or part in (b'--', b'--\r\n', b'\r\n'): continue
            # strip leading CRLF
            if part.startswith(b'\r\n'): part = part[2:]
            if part.endswith(b'--\r\n'): part = part[:-4]
            if part.endswith(b'--'): part = part[:-2]
            if part.endswith(b'\r\n'): part = part[:-2]
            if b'\r\n\r\n' not in part: continue
            header, data = part.split(b'\r\n\r\n',1)
            header_s = header.decode(errors='ignore')
            m_name = re.search(r'name="([^"]+)"', header_s)
            m_file = re.search(r'filename="([^"]+)"', header_s)
            if not m_name: continue
            name = m_name.group(1)
            if m_file:
                filename = m_file.group(1)
                # data may end with \r\n
                if data.endswith(b'\r\n'): data = data[:-2]
                files[name] = (filename, data)
            else:
                if data.endswith(b'\r\n'): data = data[:-2]
                fields[name] = data.decode(errors='ignore')
        return fields, files

    def send_html(self, html_str, code=200):
        body = html_str.encode()
        self.send_response(code)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Headers","Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods","GET,POST,PUT,DELETE,OPTIONS")
        self.end_headers()

if __name__ == "__main__":
    import socketserver, sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    PORT = int(os.environ.get("PORT", "8000"))
    print(f"School_Pustak running at http://localhost:{PORT}")
    print(f"Owner: {load_data()['owner']}  Password: {load_data()['adminPassword']}")
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        httpd.serve_forever()
