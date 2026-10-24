"""history functions, assembled into the standalone helper."""

def listing_scan(a):
    directory = state_root() / "operations"
    query = a.get("query", "")
    if not isinstance(query, str) or len(query) > 200:
        raise ValueError("query must be at most 200 characters.")
    states = a.get("states")
    allowed = {"starting", "running", "completed", "failed", "cancelled", "timed_out", "process_lost"}
    if states is not None and (not isinstance(states, list) or not 1 <= len(states) <= 7 or any(state not in allowed for state in states)):
        raise ValueError("Invalid operation states.")
    def timestamp(value):
        if value is None:
            return None
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("History timestamps require a timezone.")
        return parsed.timestamp()
    after, before = timestamp(a.get("created_after")), timestamp(a.get("created_before"))
    if after is not None and before is not None and after > before:
        raise ValueError("created_after must not be later than created_before.")
    resource = resource_name(a.get("resource"))
    limit = a.get("limit", 100)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("History limit must be 1..100.")
    criteria = {"query": query.casefold(), "states": sorted(set(states)) if states else None,
                "resource": resource, "after": after, "before": before}
    filter_hash = digest(json.dumps(criteria, sort_keys=True).encode())
    boundary = None
    cursor = a.get("cursor")
    if cursor:
        try:
            if not isinstance(cursor, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,2048}", cursor):
                raise ValueError()
            page = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
            boundary = page["before"]
            if page["filter_hash"] != filter_hash or not isinstance(boundary, list) or len(boundary) != 2 or not isinstance(boundary[0], (int, float)) or not re.fullmatch(r"[a-f0-9]{32}", boundary[1]):
                raise ValueError()
            boundary = tuple(boundary)
        except (ValueError, TypeError, KeyError):
            raise ValueError("Invalid history cursor or changed filters. Start a new search.") from None
    result, unavailable = [], 0
    if directory.exists():
        for entry in directory.iterdir():
            if entry.is_dir() and re.fullmatch(r"[a-f0-9]{32}", entry.name):
                try:
                    data = status({"operation_id": entry.name})
                    item = operation_summary(data)
                    order = (item["created_at"], item["operation_id"])
                    if boundary is not None and order >= boundary:
                        continue
                    if states and item["state"] not in states or resource is not None and item["resource"] != resource:
                        continue
                    if after is not None and item["created_at"] < after or before is not None and item["created_at"] > before:
                        continue
                    haystack = "\n".join(str(item.get(key) or "") for key in ("title", "request_id", "operation_id", "resource")).casefold()
                    if criteria["query"] not in haystack:
                        continue
                    result.append(item)
                except (OSError, ValueError, KeyError, TypeError):
                    unavailable += 1
    result.sort(key=lambda item: (item["created_at"], item["operation_id"]), reverse=True)
    more = len(result) > limit
    selected = result[:limit]
    next_cursor = None
    if more:
        last = selected[-1]
        next_cursor = base64.urlsafe_b64encode(json.dumps({"filter_hash": filter_hash, "before": [last["created_at"], last["operation_id"]]}).encode()).decode().rstrip("=")
    return {"operations": selected, "next_cursor": next_cursor, "more": more,
            "matched_remaining": len(result), "unavailable_count": unavailable}

def history_db():
    import sqlite3
    file = state_root() / 'history.sqlite'
    fd = os.open(file, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    os.close(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('Unsafe history index.')
    os.chmod(file, 0o600)
    db = sqlite3.connect(file, timeout=2)
    try:
        db.executescript('''CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT);
      CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, created REAL, state TEXT, resource TEXT, search TEXT, summary TEXT);
      CREATE INDEX IF NOT EXISTS history_created ON operations(created DESC,id DESC);
      CREATE INDEX IF NOT EXISTS history_state ON operations(state,created DESC,id DESC);
      CREATE INDEX IF NOT EXISTS history_resource ON operations(resource,created DESC,id DESC);
      CREATE TABLE IF NOT EXISTS unavailable (id TEXT PRIMARY KEY);''')
    except Exception:
        db.close()
        raise
    return db

def history_upsert(db, operation_id):
    try:
        item = operation_summary(status({'operation_id': operation_id}))
        search = '\n'.join(str(item.get(key) or '') for key in ('title', 'request_id', 'operation_id', 'resource')).casefold()
        db.execute('INSERT OR REPLACE INTO operations VALUES (?,?,?,?,?,?)',
                   (operation_id, item['created_at'], item['state'], item['resource'], search, json.dumps(item)))
        db.execute('DELETE FROM unavailable WHERE id=?', (operation_id,))
    except (OSError, ValueError, KeyError, TypeError):
        db.execute('DELETE FROM operations WHERE id=?', (operation_id,))
        db.execute('INSERT OR IGNORE INTO unavailable VALUES (?)', (operation_id,))

def history_save(file, value):
    dirty = state_root() / 'history-dirty'
    secure_dir(dirty)
    # Durable intent first: a crash between state replacement and cache update is repairable.
    with lock(state_root() / '.history.lock'):
        marker = dirty / file.parent.name
        fd = os.open(marker, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        sync_parent(marker)
        plain_save_json(file, value)
        try:
            with contextlib.closing(history_db()) as db, db:
                history_upsert(db, file.parent.name)
            marker.unlink()
        except Exception:
            pass  # Cache failure never changes a persisted operation result.

def listing(a):
    # Reuse the old validator/cursor rules, but push filters and pagination into SQLite.
    query = a.get('query', '')
    states = a.get('states')
    allowed = {'starting', 'running', 'completed', 'failed', 'cancelled', 'timed_out', 'process_lost'}
    if not isinstance(query, str) or len(query) > 200 or states is not None and (not isinstance(states, list) or not 1 <= len(states) <= 7 or any(x not in allowed for x in states)):
        raise ValueError('Invalid history filters.')
    def timestamp(value):
        if value is None:
            return None
        parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('History timestamps require a timezone.')
        return parsed.timestamp()
    after, before = timestamp(a.get('created_after')), timestamp(a.get('created_before'))
    if after is not None and before is not None and after > before:
        raise ValueError('created_after must not be later than created_before.')
    resource = resource_name(a.get('resource'))
    limit = a.get('limit', 100)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError('History limit must be 1..100.')
    criteria = {'query': query.casefold(), 'states': sorted(set(states)) if states else None, 'resource': resource, 'after': after, 'before': before}
    filter_hash = digest(json.dumps(criteria, sort_keys=True).encode())
    boundary = None
    if a.get('cursor'):
        try:
            cursor = a['cursor']
            if not isinstance(cursor, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,2048}', cursor):
                raise ValueError()
            page = json.loads(base64.urlsafe_b64decode(cursor + '=' * (-len(cursor) % 4)))
            boundary = page['before']
            if page['filter_hash'] != filter_hash or not isinstance(boundary, list) or len(boundary) != 2 or not isinstance(boundary[0], (int, float)) or not re.fullmatch(r'[a-f0-9]{32}', boundary[1]):
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise ValueError('Invalid history cursor or changed filters. Start a new search.') from None
    try:
        with lock(state_root() / '.history.lock'), contextlib.closing(history_db()) as db, db:
            directory = state_root() / 'operations'
            if not db.execute("SELECT 1 FROM metadata WHERE key='initialized'").fetchone():
                db.execute('DELETE FROM operations')
                db.execute('DELETE FROM unavailable')
                for entry in directory.iterdir() if directory.exists() else []:
                    if re.fullmatch(r'[a-f0-9]{32}', entry.name) and not entry.is_symlink() and entry.is_dir():
                        history_upsert(db, entry.name)
                db.execute("INSERT INTO metadata VALUES ('initialized','1')")
            dirty = state_root() / 'history-dirty'
            directory_time = str(directory.stat().st_mtime_ns) if directory.exists() else 'missing'
            previous_time = db.execute("SELECT value FROM metadata WHERE key='directory_time'").fetchone()
            if not previous_time or previous_time[0] != directory_time:
                known = {row[0] for row in db.execute('SELECT id FROM operations UNION SELECT id FROM unavailable')}
                for entry in directory.iterdir() if directory.exists() else []:
                    if re.fullmatch(r'[a-f0-9]{32}', entry.name) and entry.name not in known and not entry.is_symlink() and entry.is_dir():
                        history_upsert(db, entry.name)
                db.execute("INSERT OR REPLACE INTO metadata VALUES ('directory_time',?)", (directory_time,))
            markers = list(dirty.iterdir()) if dirty.exists() else []
            refresh = {row[0] for row in db.execute("SELECT id FROM operations WHERE state IN ('starting','running','process_lost')")}
            refresh.update(x.name for x in markers if re.fullmatch(r'[a-f0-9]{32}', x.name))
            for operation_id in refresh:
                history_upsert(db, operation_id)
            # Commit cache data before discarding durable dirty markers.
            db.commit()
            for marker in markers:
                if re.fullmatch(r'[a-f0-9]{32}', marker.name) and not marker.is_symlink():
                    marker.unlink(missing_ok=True)
            where, params = [], []
            if criteria['query']:
                where.append('instr(search,?)>0'); params.append(criteria['query'])
            if states:
                where.append('state IN (' + ','.join('?' for _ in states) + ')'); params.extend(states)
            if resource is not None:
                where.append('resource=?'); params.append(resource)
            if after is not None:
                where.append('created>=?'); params.append(after)
            if before is not None:
                where.append('created<=?'); params.append(before)
            if boundary:
                where.append('(created<? OR (created=? AND id<?))'); params.extend([boundary[0], boundary[0], boundary[1]])
            clause = ' WHERE ' + ' AND '.join(where) if where else ''
            count = db.execute('SELECT count(*) FROM operations' + clause, params).fetchone()[0]
            selected = [json.loads(row[0]) for row in db.execute('SELECT summary FROM operations' + clause + ' ORDER BY created DESC,id DESC LIMIT ?', params + [limit])]
            unavailable = db.execute('SELECT count(*) FROM unavailable').fetchone()[0]
            more, next_cursor = count > limit, None
            if more:
                last = selected[-1]
                next_cursor = base64.urlsafe_b64encode(json.dumps({'filter_hash': filter_hash, 'before': [last['created_at'], last['operation_id']]}).encode()).decode().rstrip('=')
            return {'operations': selected, 'next_cursor': next_cursor, 'more': more, 'matched_remaining': count, 'unavailable_count': unavailable}
    except Exception as error:
        if getattr(error, 'sqlite_errorcode', None) in (11, 26):
            with lock(state_root() / '.history.lock'):
                index = state_root() / 'history.sqlite'
                try:
                    index.rename(state_root() / ('history-invalid-' + uuid.uuid4().hex + '.sqlite'))
                except OSError:
                    pass
        value = listing_scan(a)
        value['warnings'] = [{'code': 'history_index_unavailable', 'message': 'History was read from operation files; no modifying action was repeated.'}]
        return value
