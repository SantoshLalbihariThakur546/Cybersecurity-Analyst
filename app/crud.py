"""Declarative, validated CRUD resources. Whitelisted fields only (no mass assignment), parameterized SQL only."""
import json
import re
from datetime import date, datetime, timezone

from flask import jsonify, request

from .db import get_db, jload, now_iso
from .security import ApiError, current_user, require, write_audit

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class F:
    """Field specification. kinds: str text int float bool date datetime choice json"""

    def __init__(self, name, kind="str", required=False, choices=None, lo=None, hi=None, maxlen=None, default=None):
        self.name, self.kind, self.required, self.choices = name, kind, required, choices
        self.lo, self.hi, self.default = lo, hi, default
        self.maxlen = maxlen or (8000 if kind in ("text", "json") else 300)


def parse_date(v):
    return date.fromisoformat(v)


def norm_datetime(v):
    s = str(v).strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_value(f, v):
    if f.kind in ("str", "text"):
        if isinstance(v, (dict, list, bool)):
            raise ValueError("must be text")
        s = _CTRL.sub("", str(v)).strip()
        if len(s) > f.maxlen:
            raise ValueError(f"must be at most {f.maxlen} characters")
        return s
    if f.kind in ("int", "float"):
        if isinstance(v, bool):
            raise ValueError("must be a number")
        try:
            n = int(v) if f.kind == "int" and str(v).strip().lstrip("-").isdigit() else float(v)
        except (TypeError, ValueError):
            raise ValueError("must be a number")
        if f.kind == "int" and n != int(n):
            raise ValueError("must be a whole number")
        if f.kind == "int":
            n = int(n)
        if n != n or n in (float("inf"), float("-inf")):
            raise ValueError("must be finite")
        if f.lo is not None and n < f.lo:
            raise ValueError(f"must be at least {f.lo}")
        if f.hi is not None and n > f.hi:
            raise ValueError(f"must be at most {f.hi}")
        return n
    if f.kind == "bool":
        if v in (True, 1, "1", "true", "True"):
            return 1
        if v in (False, 0, "0", "false", "False"):
            return 0
        raise ValueError("must be true or false")
    if f.kind == "date":
        s = str(v).strip()
        try:
            parse_date(s)
        except ValueError:
            raise ValueError("must be a date YYYY-MM-DD")
        return s
    if f.kind == "datetime":
        try:
            return norm_datetime(v)
        except ValueError:
            raise ValueError("must be an ISO date-time, e.g. 2026-10-20T09:30:00Z")
    if f.kind == "choice":
        if v not in f.choices:
            raise ValueError("must be one of: " + ", ".join(map(str, f.choices)))
        return v
    if f.kind == "json":
        if not isinstance(v, (list, dict)):
            raise ValueError("must be a list or object")
        s = json.dumps(v)
        if len(s) > f.maxlen:
            raise ValueError("value too large")
        return s
    raise ValueError("unsupported field type")


def validate(fields, payload, partial):
    if not isinstance(payload, dict):
        raise ApiError(400, "BAD_REQUEST", "JSON object expected.")
    clean, errors = {}, []
    for f in fields:
        present = f.name in payload
        if not present:
            if not partial:
                if f.required and f.default is None:
                    errors.append({"field": f.name, "message": "is required"})
                elif f.default is not None:
                    clean[f.name] = f.default
                else:
                    clean[f.name] = None
            continue
        v = payload[f.name]
        if v is None or (isinstance(v, str) and v.strip() == "" and f.kind != "json"):
            if f.required:
                errors.append({"field": f.name, "message": "is required"})
            else:
                clean[f.name] = f.default if (f.default is not None and not partial) else None
            continue
        try:
            clean[f.name] = clean_value(f, v)
        except ValueError as exc:
            errors.append({"field": f.name, "message": str(exc)})
    if errors:
        raise ApiError(422, "VALIDATION_ERROR", "Please correct the highlighted fields.", errors)
    return clean


def row_out(row, fields):
    d = dict(row)
    for f in fields:
        if f.kind == "json" and f.name in d:
            d[f.name] = jload(d[f.name], [])
        if f.kind == "bool" and f.name in d and d[f.name] is not None:
            d[f.name] = bool(d[f.name])
    return d


class Resource:
    def __init__(self, name, table, fields, write, search=(), filters=(), sorts=("id",), default_sort="id",
                 before_save=None, decorate=None, after_save=None, before_delete=None, timestamps=False,
                 deletable=True, parent_field=None, read=None):
        self.name, self.table, self.fields, self.write = name, table, fields, write
        self.search, self.filters, self.sorts, self.default_sort = search, filters, sorts, default_sort
        self.before_save, self.decorate, self.after_save, self.before_delete = before_save, decorate, after_save, before_delete
        self.timestamps, self.deletable, self.parent_field = timestamps, deletable, parent_field
        self.read = read
        self.colnames = {f.name for f in fields}

    # -- helpers
    def out(self, row):
        d = row_out(row, self.fields)
        return self.decorate(d) if self.decorate else d

    def get_row(self, rid):
        row = get_db().execute(f"SELECT * FROM {self.table} WHERE id=?", (rid,)).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND", "Record not found.")
        return row

    # -- handlers
    def list(self):
        sql, args, where = f"SELECT * FROM {self.table}", [], []
        for col in self.filters:
            val = request.args.get(col)
            if val not in (None, ""):
                where.append(f"{col}=?")
                args.append(val)
        q = (request.args.get("q") or "").strip()
        if q and self.search:
            esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in self.search) + ")")
            args += [f"%{esc}%"] * len(self.search)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sort = request.args.get("sort") or self.default_sort
        direction = "DESC" if sort.startswith("-") else "ASC"
        col = sort.lstrip("-")
        if col not in self.sorts:
            raise ApiError(422, "VALIDATION_ERROR", "Unsupported sort field.")
        sql += f" ORDER BY {col} {direction}, id ASC"
        rows = [self.out(r) for r in get_db().execute(sql, args).fetchall()]
        return jsonify({"items": rows, "total": len(rows)})

    def get(self, rid):
        return jsonify(self.out(self.get_row(rid)))

    def create(self):
        user = current_user()
        clean = validate(self.fields, request.get_json(silent=True), partial=False)
        if self.before_save:
            clean = self.before_save(clean, None, user) or clean
        if self.timestamps:
            clean["created_at"] = clean["updated_at"] = now_iso()
        cols = list(clean)
        cur = get_db().execute(f"INSERT INTO {self.table}({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                               [clean[c] for c in cols])
        get_db().commit()
        rid = cur.lastrowid
        if self.after_save:
            self.after_save(rid, "create", user)
        write_audit("CREATE", self.name, rid, {"fields": sorted(clean)})
        return jsonify(self.out(self.get_row(rid))), 201

    def update(self, rid):
        user = current_user()
        existing = dict(self.get_row(rid))
        clean = validate(self.fields, request.get_json(silent=True), partial=True)
        if self.before_save:
            clean = self.before_save(clean, existing, user) or clean
        if not clean:
            return jsonify(self.out(self.get_row(rid)))
        if self.timestamps:
            clean["updated_at"] = now_iso()
        get_db().execute(f"UPDATE {self.table} SET {','.join(c + '=?' for c in clean)} WHERE id=?",
                         [clean[c] for c in clean] + [rid])
        get_db().commit()
        if self.after_save:
            self.after_save(rid, "update", user)
        changes = {k: v for k, v in clean.items() if k != "updated_at" and existing.get(k) != v}
        write_audit("UPDATE", self.name, rid, {"changed": sorted(changes)})
        return jsonify(self.out(self.get_row(rid)))

    def delete(self, rid):
        row = self.get_row(rid)
        if self.before_delete:
            self.before_delete(dict(row))
        get_db().execute(f"DELETE FROM {self.table} WHERE id=?", (rid,))
        get_db().commit()
        write_audit("DELETE", self.name, rid, {})
        return jsonify({"deleted": True})

    def register(self, bp, skip=()):
        from .security import login_required
        path = f"/{self.name}"
        guard = require(self.read) if self.read else login_required
        bp.add_url_rule(path, f"{self.name}_list", guard(self.list), methods=["GET"])
        bp.add_url_rule(path + "/<int:rid>", f"{self.name}_get", guard(self.get), methods=["GET"])
        if "create" not in skip:
            bp.add_url_rule(path, f"{self.name}_create", require(self.write)(self.create), methods=["POST"])
        bp.add_url_rule(path + "/<int:rid>", f"{self.name}_update", require(self.write)(self.update), methods=["PUT", "PATCH"])
        if self.deletable:
            bp.add_url_rule(path + "/<int:rid>", f"{self.name}_delete", require(self.write)(self.delete), methods=["DELETE"])


def today():
    return date.today().isoformat()


def days_between(a, b):
    return (date.fromisoformat(b) - date.fromisoformat(a)).days


def add_days(d, n):
    from datetime import timedelta
    return (date.fromisoformat(d) + timedelta(days=n)).isoformat()
