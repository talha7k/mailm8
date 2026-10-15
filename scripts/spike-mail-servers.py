#!/usr/bin/env python3
"""Scripted plaintext IMAP (port 1143), POP3 (port 1110) and SMTP (port 2525) servers for the
Overlook IMAP/POP3 work.

Not a real server: it answers the commands the provider issues with Dovecot-shaped responses
from an in-memory mailbox. User: spike / password: secret.

Read path (M0-M2): CAPABILITY, LOGIN, LIST, SELECT/EXAMINE, UID SEARCH ALL, UID FETCH with
FLAGS / INTERNALDATE / RFC822.SIZE / ENVELOPE / BODYSTRUCTURE-less sections (BODY[],
BODY[HEADER], BODY[TEXT], BODY[n.m], BODY[n.m.MIME], partial fetches).

Write path (M3): CREATE, UID STORE (±FLAGS[.SILENT]), UID COPY and UID MOVE with COPYUID,
UID EXPUNGE / EXPUNGE, APPEND with APPENDUID, UID SEARCH HEADER <name> <value>, all against
every folder.

M5: ENABLE QRESYNC, HIGHESTMODSEQ on SELECT/EXAMINE, MODSEQ per message, UID FETCH …
(CHANGEDSINCE n [VANISHED]) with "* VANISHED (EARLIER)" for expunged UIDs, IDLE (changes to
the selected folder are pushed as EXISTS / EXPUNGE / FETCH until DONE), UID SEARCH TEXT
(with CHARSET and LITERAL+ literals; every word must occur in the decoded message), and the
control command XDELIVER [subject…], which appends a fresh message to INBOX (what the IDLE
test uses as "new mail arriving").

Fault injection, for the exit-criterion run (any connection, no login needed):
  XDROPAFTER <word> [n]      the next n (default 1) commands whose line contains <word>
                             (case-insensitive, e.g. "UID MOVE", "APPEND", "UID FETCH") are
                             executed, then that connection closes without answering
  XFAILNEXT <word> <reply>   the next command containing <word> is answered with
                             "<tag> <reply>" instead of being executed
  XSTATE                     prints the folders and their UIDs (for eyeballing)
SMTP:
  XDROPAFTERDATA             the next DATA body is read, then the connection closes
                             without the 250 reply (an uncertain send)

POP3 (M4) serves the INBOX folder's messages as a maildrop (UIDL "uidl-<uid>"): CAPA, USER,
PASS, STAT, LIST, UIDL, TOP, RETR, DELE, RSET, NOOP, QUIT, with DELE committed on QUIT and
discarded otherwise. STLS is refused. XDROPAFTER / XFAILNEXT / XSTATE work there too; a
POP3 DELE + QUIT removes the message from INBOX for the IMAP side as well.
"""
import utils.transport
import utils.session
import base64, email, email.policy, re, select, socketserver, threading, time

IMAP_PORT, POP3_PORT, SMTP_PORT = 1143, 1110, 2525
USER, PASSWORD = "spike", "secret"
CAPS = "IMAP4rev1 UIDPLUS MOVE IDLE SPECIAL-USE LITERAL+ ENABLE CONDSTORE QRESYNC"

def msg(headers, body):
    return ("\r\n".join(headers) + "\r\n\r\n" + body).encode()

class Folder:
    def __init__(self, attrs, uidvalidity):
        self.attrs, self.uidvalidity = attrs, uidvalidity
        self.messages = {}  # uid -> [flags(list), internaldate, bytes, modseq]
        self.next_uid = 1
        self.highest_modseq = 1   # CONDSTORE
        self.expunged = []        # (uid, modseq) for VANISHED
        self.generation = 0       # bumped by every change, for IDLE
    def bump(self):
        self.highest_modseq += 1; self.generation += 1
        return self.highest_modseq
    def add(self, flags, idate, raw, _modseq=None):
        uid = self.next_uid; self.next_uid += 1
        self.messages[uid] = [list(flags), idate, raw, self.bump()]
        return uid
    def remove(self, uid):
        if uid in self.messages:
            del self.messages[uid]; self.expunged.append((uid, self.bump()))
    def set_flags(self, uid, flags):
        self.messages[uid][0] = flags; self.messages[uid][3] = self.bump()
    def last_changed(self):
        if not self.messages: return None
        uid = max(self.messages, key=lambda u: self.messages[u][3])
        return sorted(self.messages).index(uid) + 1, uid

FOLDERS = {
    "INBOX": Folder(["\\HasNoChildren"], 1760400000),
    "Sent": Folder(["\\HasNoChildren", "\\Sent"], 1760400001),
    "Trash": Folder(["\\HasNoChildren", "\\Trash"], 1760400002),
    "Junk": Folder(["\\HasNoChildren", "\\Junk"], 1760400003),
    "Work": Folder(["\\HasChildren"], 1760400004),
    "Work/Clients": Folder(["\\HasNoChildren"], 1760400005),
}
FOLDERS["INBOX"].add(["\\Seen"], "10-Oct-2026 09:12:00 +0000", msg([
    "From: Ada Lovelace <ada@example.com>", "To: spike@example.com", "Subject: Plain hello",
    "Date: Sat, 10 Oct 2026 09:12:00 +0000", "Message-ID: <plain-1@example.com>",
    "Content-Type: text/plain; charset=utf-8"], "Hello from a plain message.\r\n"))
FOLDERS["INBOX"].add([], "12-Oct-2026 14:30:00 +0000", msg([
    "From: =?UTF-8?Q?Gr=C3=A9goire?= <greg@example.com>", "To: spike@example.com", "Cc: Ada Lovelace <ada@example.com>",
    "Subject: =?UTF-8?B?UmU6IFBsYWluIGhlbGxv?=", "Date: Mon, 12 Oct 2026 14:30:00 +0000",
    "Message-ID: <multi-2@example.com>", "In-Reply-To: <plain-1@example.com>", "References: <plain-1@example.com>",
    "MIME-Version: 1.0", 'Content-Type: multipart/mixed; boundary="outer"'],
    '--outer\r\nContent-Type: multipart/alternative; boundary="inner"\r\n\r\n'
    '--inner\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nText part.\r\n'
    '--inner\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>HTML part with <img src="cid:logo"></p>\r\n'
    '--inner--\r\n'
    '--outer\r\nContent-Type: image/png; name="logo.png"\r\nContent-ID: <logo>\r\nContent-Disposition: inline; filename="logo.png"\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n'
    '--outer\r\nContent-Type: application/pdf; name="report.pdf"\r\nContent-Disposition: attachment; filename="report.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n'
    '--outer--\r\n'))
FOLDERS["INBOX"].add(["\\Flagged"], "13-Oct-2026 08:00:00 +0000", msg([
    "From: Calendar <cal@example.com>", "To: spike@example.com", "Subject: Invitation: Standup",
    "Date: Tue, 13 Oct 2026 08:00:00 +0000", "Message-ID: <invite-3@example.com>", "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="b"'],
    '--b\r\nContent-Type: text/plain\r\n\r\nYou are invited.\r\n'
    '--b\r\nContent-Type: text/calendar; method=REQUEST\r\n\r\nBEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:ev1\r\nSUMMARY:Standup\r\nDTSTART:20261014T090000Z\r\nDTEND:20261014T091500Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'
    '--b--\r\n'))
FOLDERS["Work/Clients"].add([], "09-Oct-2026 09:00:00 +0000", msg([
    "From: client@example.com", "To: spike@example.com", "Subject: Contract", "Message-ID: <work-1@example.com>",
    "Date: Fri, 09 Oct 2026 09:00:00 +0000"], "Please sign.\r\n"))

LOCK = threading.Lock()
FAULTS = {"drop_after": None, "drop_count": 0, "fail_next": None, "smtp_drop_after_data": False}

def header(raw, name):
    for line in raw.split(b"\r\n\r\n", 1)[0].split(b"\r\n"):
        if line.lower().startswith(name.lower().encode() + b":"):
            return line.split(b":", 1)[1].strip().decode()
    return None

def quoted(s):
    return "NIL" if s is None else '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'

def unquote(s):
    s = s.strip()
    return s[1:-1].replace('\\"', '"').replace('\\\\', '\\') if len(s) >= 2 and s[0] == s[-1] == '"' else s

def addr(h):
    if not h: return "NIL"
    out = []
    for part in h.split(","):
        part = part.strip()
        if "<" in part:
            name, mail = part.split("<", 1); mail = mail.rstrip(">")
            name = name.strip().strip('"') or None
        else:
            name, mail = None, part
        local, _, host = mail.partition("@")
        out.append(f"({quoted(name)} NIL {quoted(local)} {quoted(host)})")
    return "(" + "".join(out) + ")"

def envelope(raw):
    frm = addr(header(raw, "From"))
    return (f"({quoted(header(raw,'Date'))} {quoted(header(raw,'Subject'))} {frm} {frm} {frm} "
            f"{addr(header(raw,'To'))} {addr(header(raw,'Cc'))} NIL {quoted(header(raw,'In-Reply-To'))} {quoted(header(raw,'Message-ID'))})")

def section_bytes(raw, spec):
    """BODY[<spec>] bytes: '' (whole), HEADER, TEXT, n.m, n.m.MIME — served from the raw
    message so the client sees what a real server would send."""
    head, _, body = raw.partition(b"\r\n\r\n")
    if spec == "": return raw
    if spec.upper() == "HEADER": return head + b"\r\n\r\n"
    if spec.upper() == "TEXT": return body
    m = email.message_from_bytes(raw, policy=email.policy.compat32)
    want_mime = spec.upper().endswith(".MIME")
    numbers = [int(n) for n in (spec[:-5] if want_mime else spec).split(".")]
    part = m
    for n in numbers:
        if part.is_multipart(): part = part.get_payload()[n - 1]
        elif n != 1: return b""
    part_bytes = part.as_bytes()
    phead, _, pbody = part_bytes.partition(b"\r\n\r\n")
    if b"\r\n\r\n" not in part_bytes:  # compat32 may emit bare LF
        phead, _, pbody = part_bytes.partition(b"\n\n")
        phead = phead.replace(b"\n", b"\r\n"); pbody = pbody.replace(b"\n", b"\r\n")
    return phead + b"\r\n" if want_mime else pbody

def tokenize(criteria):
    """SEARCH words, with quoted strings (already unquoted) kept together."""
    out, cur, quoted_, escaped = [], "", False, False
    for c in criteria:
        if quoted_:
            if escaped: cur += c; escaped = False
            elif c == "\\": escaped = True
            elif c == '"': quoted_ = False; out.append(cur); cur = ""
            else: cur += c
        elif c == '"': quoted_ = True
        elif c == " ":
            if cur: out.append(cur); cur = ""
        else: cur += c
    if cur: out.append(cur)
    return out

def searchable_text(raw):
    """What SEARCH TEXT matches: decoded headers and text parts, lower-cased."""
    m = email.message_from_bytes(raw, policy=email.policy.default)
    text = "".join(f"{k}: {v}\n" for k, v in m.items())
    for part in m.walk():
        if part.get_content_maintype() == "text":
            try: text += part.get_content() + "\n"
            except Exception: pass
    return (text + raw.decode(errors="replace")).lower()

def parse_set(s, uids):
    uids = list(uids)
    out = set()
    for piece in s.split(","):
        if ":" in piece:
            a, b = piece.split(":"); a = int(a); b = (max(uids) if uids else 0) if b == "*" else int(b)
            out.update(u for u in uids if min(a, b) <= u <= max(a, b))
        else:
            out.add(int(piece))
    return sorted(u for u in out if u in uids)

def encode_set(uids):
    uids = sorted(set(uids)); out = []; i = 0
    while i < len(uids):
        start = end = uids[i]
        while i + 1 < len(uids) and uids[i + 1] == end + 1: i += 1; end = uids[i]
        out.append(str(start) if start == end else f"{start}:{end}"); i += 1
    return ",".join(out)

def fault_check(text):
    """Returns ("drop", None), ("fail", reply) or (None, None) for a command line."""
    upper = text.upper()
    with LOCK:
        if FAULTS["fail_next"] and FAULTS["fail_next"][0] in upper:
            reply = FAULTS["fail_next"][1]; FAULTS["fail_next"] = None
            return "fail", reply
        if FAULTS["drop_after"] and FAULTS["drop_after"] in upper:
            FAULTS["drop_count"] -= 1
            if FAULTS["drop_count"] <= 0: FAULTS["drop_after"] = None
            return "drop", None
    return None, None

class Imap(socketserver.StreamRequestHandler):
    muted = False
    def send(self, s):
        if self.muted: return
        self.wfile.write(s.encode() if isinstance(s, str) else s); self.wfile.write(b"\r\n")
    def write(self, b):
        if not self.muted: self.wfile.write(b)
    def handle(self):
        self.send(f"* OK [CAPABILITY {CAPS}] Spike IMAP ready.")
        box = None
        self.watched = (0, 0)
        while True:
            line = self.rfile.readline()
            if not line: return
            text = line.decode(errors="replace").rstrip("\r\n")
            # LITERAL+ at the end of the line (SEARCH words): read the bytes and the rest.
            while text.endswith("+}") and "{" in text:
                open_at = text.rindex("{")
                try: size = int(text[open_at + 1:-2])
                except ValueError: break
                literal = self.rfile.read(size).decode(errors="replace")
                rest = self.rfile.readline().decode(errors="replace").rstrip("\r\n")
                text = text[:open_at] + quoted(literal) + rest
            print("IMAP <", text if "LOGIN" not in text.upper() else text.split()[0] + " LOGIN ****", flush=True)
            tag, _, rest = text.partition(" ")
            cmd, _, args = rest.partition(" ")
            cmd = cmd.upper()
            if cmd.startswith("X"):
                self.control(tag, cmd, args); continue
            kind, reply = fault_check(text)
            if kind == "fail":
                print(f"IMAP fault: answering {tag} {reply}", flush=True)
                self.send(f"{tag} {reply}"); continue
            if kind == "drop":
                print("IMAP fault: executing, then dropping the connection without a reply", flush=True)
                self.muted = True
            if cmd == "CAPABILITY":
                self.send(f"* CAPABILITY {CAPS}"); self.send(f"{tag} OK Capability completed.")
            elif cmd == "LOGIN":
                u, p = [unquote(a) for a in args.split(" ", 1)]
                if (u, p) == (USER, PASSWORD): self.send(f"{tag} OK [CAPABILITY {CAPS}] Logged in")
                else: self.send(f"{tag} NO [AUTHENTICATIONFAILED] Authentication failed.")
            elif cmd == "STARTTLS":
                self.send(f"{tag} NO STARTTLS is not offered by the fake server")
            elif cmd in ("LIST", "LSUB"):
                with LOCK: items = [(p, f.attrs) for p, f in FOLDERS.items()]
                for path, attrs in items:
                    self.send(f'* {cmd} ({" ".join(attrs)}) "/" {quoted(path)}')
                self.send(f"{tag} OK {cmd.title()} completed.")
            elif cmd in ("SELECT", "EXAMINE"):
                path = unquote(args)
                with LOCK: f = FOLDERS.get(path)
                if f is None:
                    self.send(f"{tag} NO Mailbox doesn't exist: {path}"); continue
                box = path
                with LOCK: n, nxt, uv, hm = len(f.messages), f.next_uid, f.uidvalidity, f.highest_modseq; self.watched = (n, f.generation)
                self.send("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
                self.send("* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted.")
                self.send(f"* {n} EXISTS"); self.send("* 0 RECENT")
                self.send(f"* OK [UIDVALIDITY {uv}] UIDs valid"); self.send(f"* OK [UIDNEXT {nxt}] Predicted next UID")
                self.send(f"* OK [HIGHESTMODSEQ {hm}] Highest")
                self.send(f"{tag} OK [{'READ-WRITE' if cmd == 'SELECT' else 'READ-ONLY'}] {cmd.title()} completed")
            elif cmd == "CREATE":
                path = unquote(args)
                with LOCK:
                    exists = path in FOLDERS
                    if not exists: FOLDERS[path] = Folder(["\\HasNoChildren"], 1760500000 + len(FOLDERS))
                self.send(f"{tag} NO [ALREADYEXISTS] Mailbox already exists" if exists else f"{tag} OK Create completed.")
            elif cmd == "DELETE":
                path = unquote(args)
                with LOCK: gone = FOLDERS.pop(path, None) is not None
                self.send(f"{tag} OK Delete completed." if gone else f"{tag} NO Mailbox doesn't exist: {path}")
            elif cmd == "UID":
                sub, _, sargs = args.partition(" ")
                sub = sub.upper()
                with LOCK: f = FOLDERS.get(box)
                if f is None:
                    self.send(f"{tag} BAD No mailbox selected"); continue
                if sub == "SEARCH":
                    tokens = tokenize(sargs.strip()); hits = None; i = 0; bad = None
                    with LOCK:
                        while i < len(tokens):
                            key = tokens[i].upper()
                            if key == "ALL": found = sorted(f.messages); i += 1
                            elif key == "CHARSET": i += 2; continue
                            elif key == "HEADER":
                                name, value = tokens[i + 1], tokens[i + 2]
                                found = [u for u, v in f.messages.items() if header(v[2], name) == value]; i += 3
                            elif key == "TEXT":
                                word = tokens[i + 1].lower()
                                found = [u for u, v in f.messages.items() if word in searchable_text(v[2])]; i += 2
                            else: bad = key; break
                            hits = found if hits is None else [u for u in hits if u in found]
                    if bad: self.send(f"{tag} BAD Unknown search key {bad}"); continue
                    self.send("* SEARCH" + "".join(f" {u}" for u in sorted(hits or []))); self.send(f"{tag} OK Search completed.")
                elif sub == "FETCH":
                    self.fetch(tag, f, sargs)
                elif sub == "STORE":
                    sset, _, rest = sargs.partition(" ")
                    item, _, flags = rest.partition(" ")
                    flags = flags.strip().strip("()").split()
                    lines = []
                    with LOCK:
                        for i, u in enumerate(sorted(f.messages)):
                            if u not in parse_set(sset, f.messages): continue
                            cur = f.messages[u][0]
                            if item.startswith("+"): cur += [x for x in flags if x not in cur]
                            elif item.startswith("-"): cur = [x for x in cur if x not in flags]
                            else: cur = list(flags)
                            f.set_flags(u, cur)
                            if not item.upper().endswith(".SILENT"): lines.append(f"* {i+1} FETCH (UID {u} FLAGS ({' '.join(cur)}))")
                    for l in lines: self.send(l)
                    self.send(f"{tag} OK Store completed.")
                elif sub in ("COPY", "MOVE"):
                    sset, _, target = sargs.partition(" "); target = unquote(target)
                    with LOCK:
                        t = FOLDERS.get(target)
                        if t is None:
                            self.send(f"{tag} NO [TRYCREATE] Mailbox doesn't exist: {target}"); continue
                        uids = parse_set(sset, f.messages)
                        pairs = [(u, t.add(*f.messages[u])) for u in uids]
                        seqs = []
                        if sub == "MOVE":
                            seqs = [i + 1 for i, u in enumerate(sorted(f.messages)) if u in uids]
                            for u in uids: f.remove(u)
                        tv = t.uidvalidity
                    code = f"[COPYUID {tv} {encode_set(p[0] for p in pairs)} {encode_set(p[1] for p in pairs)}] " if pairs else ""
                    if sub == "MOVE":
                        if code: self.send(f"* OK {code}Moved UIDs.")
                        for s in reversed(seqs): self.send(f"* {s} EXPUNGE")
                        self.send(f"{tag} OK Move completed.")
                    else:
                        self.send(f"{tag} OK {code}Copy completed.")
                elif sub == "EXPUNGE":
                    self.expunge(tag, f, sargs.strip())
                else:
                    self.send(f"{tag} BAD Unknown UID command")
            elif cmd == "EXPUNGE":
                with LOCK: f = FOLDERS.get(box)
                if f is None: self.send(f"{tag} BAD No mailbox selected")
                else: self.expunge(tag, f, None)
            elif cmd == "APPEND":
                # a APPEND "Sent" (\Seen) ["date"] {N}  or with LITERAL+ {N+}
                size = int(args[args.rindex("{")+1:].rstrip("}+ "))
                head = args[:args.rindex("{")].strip()
                m = re.match(r'("(?:[^"\\]|\\.)*"|\S+)\s*(?:\(([^)]*)\))?', head)
                mailbox, flags = unquote(m.group(1)), (m.group(2) or "").split()
                with LOCK: t = FOLDERS.get(mailbox)
                if t is None:
                    self.send(f"{tag} NO [TRYCREATE] Mailbox doesn't exist: {mailbox}"); continue
                if not args.rstrip().endswith("+}"):
                    muted, self.muted = self.muted, False
                    self.send("+ OK"); self.muted = muted
                raw = self.rfile.read(size); self.rfile.readline()
                with LOCK: uid = t.add(flags, "14-Oct-2026 12:00:00 +0000", raw); tv = t.uidvalidity
                print(f"IMAP appended {len(raw)} bytes to {mailbox!r} as UID {uid}, subject={header(raw, 'Subject')!r}", flush=True)
                self.send(f"{tag} OK [APPENDUID {tv} {uid}] Append completed.")
            elif cmd == "NOOP":
                self.send(f"{tag} OK NOOP completed.")
            elif cmd == "ENABLE":
                enabled = [c.upper() for c in args.split() if c.upper() in CAPS.split()]
                if enabled: self.send("* ENABLED " + " ".join(enabled))
                self.send(f"{tag} OK Enabled.")
            elif cmd == "IDLE":
                self.idle(tag, box)
            elif cmd == "LOGOUT":
                self.send("* BYE Logging out"); self.send(f"{tag} OK Logout completed."); return
            else:
                self.send(f"{tag} BAD Unknown command {cmd}")
            if self.muted:
                return

    def control(self, tag, cmd, args):
        with LOCK:
            if cmd == "XDROPAFTER":
                parts = args.rsplit(" ", 1)
                if len(parts) == 2 and parts[1].isdigit(): word, count = parts[0], int(parts[1])
                else: word, count = args, 1
                FAULTS["drop_after"], FAULTS["drop_count"] = word.strip().upper(), count
            elif cmd == "XFAILNEXT":
                word, _, reply = args.partition(" ")
                FAULTS["fail_next"] = (word.upper(), reply)
            elif cmd == "XDROPAFTERDATA":
                FAULTS["smtp_drop_after_data"] = True
            elif cmd == "XSTATE":
                for path, f in FOLDERS.items():
                    self.send(f"* XSTATE {quoted(path)} uidvalidity={f.uidvalidity} modseq={f.highest_modseq} uids={encode_set(f.messages) or '-'} flags={[(u, v[0]) for u, v in f.messages.items()]}")
            elif cmd == "XDELIVER":
                subject = args.strip() or f"Delivered at {time.strftime('%H:%M:%S')}"
                stamp = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
                raw = msg(["From: courier@example.com", "To: spike@example.com", f"Subject: {subject}",
                           f"Message-ID: <deliver-{int(time.time()*1000)}@example.com>", f"Date: {stamp}"], f"{subject}\r\n")
                uid = FOLDERS["INBOX"].add([], time.strftime("%d-%b-%Y %H:%M:%S +0000", time.gmtime()), raw)
                self.send(f"* XDELIVER INBOX uid={uid}")
            else:
                self.send(f"{tag} BAD Unknown control command"); return
        print(f"IMAP control: {cmd} {args}", flush=True)
        self.send(f"{tag} OK {cmd} armed")

    def idle(self, tag, box):
        """Pushes the selected folder's changes until DONE. Changes between a DONE and the
        next IDLE are reported at once, as a real server does, through self.watched."""
        self.send("+ idling")
        while True:
            # select() instead of a socket timeout: a timed-out buffered reader cannot be
            # read again in Python.
            readable, _, _ = select.select([self.request], [], [], 0.05)
            if readable:
                line = self.rfile.readline()
                if not line: return
                self.send(f"{tag} OK Idle completed." if line.strip().upper() == b"DONE" else f"{tag} BAD Expected DONE")
                return
            with LOCK:
                f = FOLDERS.get(box)
                if f is None: continue
                exists, generation = len(f.messages), f.generation
                if (exists, generation) == self.watched: continue
                before = self.watched[0]
                if exists > before: out = [f"* {exists} EXISTS", "* 1 RECENT"]
                elif exists < before: out = [f"* {min(before, exists + 1)} EXPUNGE"]
                else:
                    lc = f.last_changed()
                    out = [f"* {lc[0]} FETCH (UID {lc[1]} FLAGS ({' '.join(f.messages[lc[1]][0])}))"] if lc else []
                self.watched = (exists, generation)
            for l in out:
                print("IMAP > " + l, flush=True); self.send(l)

    def expunge(self, tag, f, sset):
        with LOCK:
            wanted = parse_set(sset, f.messages) if sset else list(f.messages)
            gone = [u for u in sorted(f.messages) if u in wanted and "\\Deleted" in f.messages[u][0]]
            seqs = [i + 1 for i, u in enumerate(sorted(f.messages)) if u in gone]
            for u in gone: f.remove(u)
        for s in reversed(seqs): self.send(f"* {s} EXPUNGE")
        self.send(f"{tag} OK Expunge completed.")

    def fetch(self, tag, f, sargs):
        sset, _, items = sargs.partition(" ")
        items = items.strip().upper()
        since, vanished = None, False
        m = re.search(r"\(CHANGEDSINCE (\d+)( VANISHED)?\)", items)
        if m:
            since, vanished = int(m.group(1)), bool(m.group(2)); items = items[:m.start()]
        items = items.strip().strip("()")
        with LOCK:
            universe = list(f.messages) + [u for u, _ in f.expunged]   # n:* reaches past expunges
            uids = parse_set(sset, universe)
            rows = [(i, u, list(f.messages[u])) for i, u in enumerate(sorted(f.messages)) if u in uids and (since is None or f.messages[u][3] > since)]
            gone = encode_set(u for u, ms in f.expunged if vanished and ms > since and u in uids)
        if gone: self.send(f"* VANISHED (EARLIER) {gone}")
        for i, u, (flags, idate, raw, modseq) in rows:
            parts = [f"UID {u}", f"MODSEQ ({modseq})"]
            if "FLAGS" in items: parts.append(f"FLAGS ({' '.join(flags)})")
            if "INTERNALDATE" in items: parts.append(f'INTERNALDATE "{idate}"')
            if "RFC822.SIZE" in items: parts.append(f"RFC822.SIZE {len(raw)}")
            if "ENVELOPE" in items: parts.append("ENVELOPE " + envelope(raw))
            head = f"* {i+1} FETCH (" + " ".join(parts)
            sections = re.findall(r"BODY(?:\.PEEK)?\[([^\]]*)\](<0\.(\d+)>)?", items)
            if sections:
                self.write(head.encode())
                for spec, partial, limit in sections:
                    data = section_bytes(raw, spec)
                    if partial: data = data[:int(limit)]
                    self.write(f" BODY[{spec}]{'<0>' if partial else ''} {{{len(data)}}}\r\n".encode()); self.write(data)
                self.send(")")
            else:
                self.send(head + ")")
        self.send(f"{tag} OK Fetch completed.")

class Smtp(socketserver.StreamRequestHandler):
    def send(self, s): self.wfile.write((s + "\r\n").encode())
    def handle(self):
        self.send("220 spike.local ESMTP fake")
        authed = False
        while True:
            line = self.rfile.readline()
            if not line: return
            text = line.decode(errors="replace").rstrip("\r\n")
            print("SMTP <", text if not text.startswith(("AUTH", "dXNlc", "c3Bpa")) and not (len(text) > 8 and " " not in text) else "(auth data)", flush=True)
            cmd = text.split(" ", 1)[0].upper()
            if cmd in ("EHLO", "HELO"):
                self.send("250-spike.local"); self.send("250-AUTH PLAIN LOGIN"); self.send("250-8BITMIME"); self.send("250 SIZE 10485760")
            elif cmd == "AUTH":
                parts = text.split(" ")
                if parts[1].upper() == "PLAIN":
                    blob = parts[2] if len(parts) > 2 else (self.send("334 ") or self.rfile.readline().decode().strip())
                    _, u, p = base64.b64decode(blob).split(b"\0")
                    authed = (u.decode(), p.decode()) == (USER, PASSWORD)
                elif parts[1].upper() == "LOGIN":
                    self.send("334 VXNlcm5hbWU6"); u = base64.b64decode(self.rfile.readline().strip()).decode()
                    self.send("334 UGFzc3dvcmQ6"); p = base64.b64decode(self.rfile.readline().strip()).decode()
                    authed = (u, p) == (USER, PASSWORD)
                self.send("235 2.7.0 Authentication successful" if authed else "535 5.7.8 Authentication credentials invalid")
            elif cmd in ("MAIL", "RCPT"):
                self.send("250 2.1.0 OK" if authed else "530 5.7.0 Authentication required")
            elif cmd == "DATA":
                self.send("354 End data with <CR><LF>.<CR><LF>")
                data = b""
                while not data.endswith(b"\r\n.\r\n"):
                    chunk = self.rfile.readline()
                    if not chunk: return
                    data += chunk
                print(f"SMTP received {len(data)} bytes, subject={header(data, 'Subject')!r}", flush=True)
                with LOCK:
                    drop = FAULTS["smtp_drop_after_data"]; FAULTS["smtp_drop_after_data"] = False
                if drop:
                    print("SMTP fault: dropping the connection without the 250 reply", flush=True)
                    return
                self.send("250 2.0.0 OK: queued as spike-1")
            elif cmd == "XDROPAFTERDATA":
                with LOCK: FAULTS["smtp_drop_after_data"] = True
                print("SMTP control: XDROPAFTERDATA armed", flush=True)
                self.send("250 XDROPAFTERDATA armed")
            elif cmd == "STARTTLS":
                self.send("454 TLS not available")
            elif cmd == "QUIT":
                self.send("221 2.0.0 Bye"); return
            elif cmd in ("RSET", "NOOP"):
                self.send("250 OK")
            else:
                self.send("502 5.5.2 Command not implemented")

class Pop3(socketserver.StreamRequestHandler):
    """RFC 1939 over the INBOX folder. Message numbers are positions in the UID order of the
    messages present at login (a maildrop is frozen for the session)."""
    muted = False
    def send(self, s):
        if not self.muted: self.wfile.write((s + "\r\n").encode())
    def body(self, raw):
        if self.muted: return
        out = b""
        for line in raw.splitlines(keepends=True):
            out += (b"." if line.startswith(b".") else b"") + line
        if not out.endswith(b"\n"): out += b"\r\n"
        self.wfile.write(out + b".\r\n")
    def handle(self):
        self.send("+OK Spike POP3 ready.")
        user, authed, uids, marked = None, False, [], set()
        while True:
            line = self.rfile.readline()
            if not line: return
            text = line.decode(errors="replace").rstrip("\r\n")
            cmd, _, args = text.partition(" ")
            cmd = cmd.upper()
            print("POP3 <", "PASS ****" if cmd == "PASS" else text, flush=True)
            if cmd.startswith("X"):
                if cmd == "XSTATE":
                    with LOCK:
                        for p, f in FOLDERS.items(): print(f"  {p}: {sorted(f.messages)}", flush=True)
                    self.send("+OK printed"); continue
                if cmd == "XDROPAFTER":
                    w, _, n = args.partition(" ")
                    with LOCK: FAULTS["drop_after"], FAULTS["drop_count"] = w.upper(), int(n or 1)
                    self.send("+OK armed"); continue
                if cmd == "XFAILNEXT":
                    w, _, reply = args.partition(" ")
                    with LOCK: FAULTS["fail_next"] = (w.upper(), reply)
                    self.send("+OK armed"); continue
                self.send("-ERR unknown control"); continue
            kind, reply = fault_check(text)
            if kind == "fail":
                print(f"POP3 fault: answering -ERR {reply}", flush=True)
                self.send(f"-ERR {reply}"); continue
            if kind == "drop":
                print("POP3 fault: executing, then dropping the connection without a reply", flush=True)
                self.muted = True
            if not authed and cmd not in ("USER", "PASS", "CAPA", "QUIT", "STLS"):
                self.send("-ERR [AUTH] Unauthenticated")
            elif cmd == "CAPA":
                self.send("+OK"); self.body(b"TOP\r\nUIDL\r\nUSER\r\nPIPELINING\r\n")
            elif cmd == "STLS":
                self.send("-ERR STLS is not offered by the fake server")
            elif cmd == "USER":
                user = args; self.send("+OK")
            elif cmd == "PASS":
                if (user, args) == (USER, PASSWORD):
                    authed = True
                    with LOCK: uids = sorted(FOLDERS["INBOX"].messages)
                    self.send(f"+OK Logged in. {len(uids)} messages")
                else:
                    self.send("-ERR [AUTH] Authentication failed.")
            elif cmd in ("NOOP",):
                self.send("+OK")
            elif cmd == "RSET":
                marked.clear(); self.send("+OK")
            elif cmd in ("STAT", "LIST", "UIDL"):
                with LOCK:
                    rows = [(i + 1, u, len(FOLDERS["INBOX"].messages[u][2])) for i, u in enumerate(uids)
                            if (i + 1) not in marked and u in FOLDERS["INBOX"].messages]
                if cmd == "STAT":
                    self.send(f"+OK {len(rows)} {sum(r[2] for r in rows)}")
                else:
                    fmt = (lambda r: f"{r[0]} {r[2]}") if cmd == "LIST" else (lambda r: f"{r[0]} uidl-{r[1]}")
                    if args.strip():
                        hit = [r for r in rows if str(r[0]) == args.strip()]
                        self.send(f"+OK {fmt(hit[0])}" if hit else "-ERR no such message")
                    else:
                        self.send(f"+OK {len(rows)} messages"); self.body("".join(fmt(r) + "\r\n" for r in rows).encode())
            elif cmd in ("RETR", "TOP"):
                parts = args.split()
                n = int(parts[0]) if parts and parts[0].isdigit() else 0
                lines = int(parts[1]) if cmd == "TOP" and len(parts) > 1 and parts[1].isdigit() else 0
                with LOCK:
                    raw = FOLDERS["INBOX"].messages.get(uids[n - 1])[2] if 0 < n <= len(uids) and n not in marked and uids[n - 1] in FOLDERS["INBOX"].messages else None
                if raw is None:
                    self.send("-ERR no such message"); continue
                if cmd == "TOP":
                    head, _, body = raw.partition(b"\r\n\r\n")
                    raw = head + b"\r\n\r\n" + b"".join(body.splitlines(keepends=True)[:lines])
                self.send(f"+OK {len(raw)} octets"); self.body(raw)
            elif cmd == "DELE":
                n = int(args) if args.strip().isdigit() else 0
                if 0 < n <= len(uids) and n not in marked:
                    marked.add(n); self.send(f"+OK message {n} deleted")
                else:
                    self.send("-ERR no such message")
            elif cmd == "QUIT":
                if authed:
                    with LOCK:
                        for n in marked: FOLDERS["INBOX"].remove(uids[n - 1])
                    if marked: print(f"POP3 committed {len(marked)} deletion(s)", flush=True)
                self.send("+OK Logging out."); return
            else:
                self.send("-ERR Unknown command")
            if self.muted: return

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    imap = Server(("127.0.0.1", IMAP_PORT), Imap); pop3 = Server(("127.0.0.1", POP3_PORT), Pop3); smtp = Server(("127.0.0.1", SMTP_PORT), Smtp)
    threading.Thread(target=imap.serve_forever, daemon=True).start()
    threading.Thread(target=pop3.serve_forever, daemon=True).start()
    threading.Thread(target=smtp.serve_forever, daemon=True).start()
    print(f"fake IMAP on 127.0.0.1:{IMAP_PORT}, fake POP3 on 127.0.0.1:{POP3_PORT}, fake SMTP on 127.0.0.1:{SMTP_PORT}; user {USER}", flush=True)
    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt:
        pass
