"""maintenance functions, assembled into the standalone helper."""

def state_file(relative):
    root = state_root()
    parts = pathlib.PurePosixPath(relative).parts
    if not parts or any(x in ('..', '.') for x in parts) or pathlib.PurePosixPath(relative).is_absolute():
        raise ValueError('Invalid state path.')
    current = root
    for part in parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('Unsafe state file.')
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('State target must be regular.')
    return current

def state_fingerprint(file):
    info = file.stat()
    h = hashlib.sha256()
    with file.open('rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            h.update(chunk)
    after = file.stat()
    before_id = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if before_id != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('State file changed during inspection.')
    return {'size': info.st_size, 'sha256': h.hexdigest(), 'identity': [str(x) for x in before_id]}

def finish_backup(file):
    save_json(file.with_suffix('.bak.json'), {'created_at': time.time(), 'complete': True, 'fingerprint': state_fingerprint(file)})

def maintenance_guard(action):
    def guarded(a):
        with lock(state_root() / '.maintenance.lock'):
            return action(a)
    return guarded

def state_inventory(category=None, cutoff=None):
    stats = {key: {'bytes': 0, 'count': 0, 'unknown_count': 0} for key in ('operation_logs', 'operations_metadata', 'file_backups')}
    items = []
    root = state_root()
    operations = root / 'operations'
    for entry in operations.iterdir() if operations.exists() else []:
        if not re.fullmatch(r'[a-f0-9]{32}', entry.name) or entry.is_symlink() or not entry.is_dir():
            continue
        try:
            state_path = state_file('operations/' + entry.name + '/status.json')
            data = status({'operation_id': entry.name})
            terminal = data.get('state') in ('completed', 'failed', 'cancelled', 'timed_out')
            old = terminal and data.get('finished_at', float('inf')) < (cutoff or 0) and data.get('created_at', float('inf')) < (cutoff or 0)
            for name in ('status.json', 'spec.json'):
                if not (entry / name).exists():
                    continue
                file = state_file('operations/' + entry.name + '/' + name)
                stats['operations_metadata']['bytes'] += file.stat().st_size
                stats['operations_metadata']['count'] += 1
            if not terminal:
                stats['operation_logs']['unknown_count'] += 1
            for name in ('stdout.log', 'stderr.log'):
                if not (entry / name).exists():
                    continue
                relative = 'operations/' + entry.name + '/' + name
                file = state_file(relative)
                stats['operation_logs']['bytes'] += file.stat().st_size
                stats['operation_logs']['count'] += 1
                if category == 'operation_logs' and old:
                    items.append({'relative': relative, 'operation_id': entry.name, 'fingerprint': state_fingerprint(file), 'status_hash': digest(state_path.read_bytes())})
        except (OSError, ValueError, KeyError, TypeError):
            stats['operation_logs']['unknown_count'] += 1
    backups = root / 'backups'
    for file in backups.iterdir() if backups.exists() else []:
        if not re.fullmatch(r'[a-f0-9]{32}\.bak', file.name):
            continue
        try:
            relative = 'backups/' + file.name
            file = state_file(relative)
            stats['file_backups']['bytes'] += file.stat().st_size
            stats['file_backups']['count'] += 1
            meta = state_file(relative + '.json')
            metadata = load_json(meta)
            if not metadata.get('complete'):
                raise ValueError('Incomplete backup.')
            if category == 'file_backups' and metadata.get('created_at', float('inf')) < (cutoff or 0):
                fingerprint = state_fingerprint(file)
                if fingerprint != metadata.get('fingerprint'):
                    raise ValueError('Backup changed.')
                items.append({'relative': relative, 'fingerprint': fingerprint, 'metadata_hash': digest(meta.read_bytes())})
        except (OSError, ValueError, KeyError, TypeError):
            stats['file_backups']['unknown_count'] += 1
    return stats, items

def state_usage(a):
    stats, _ = state_inventory()
    total = sum(x['bytes'] for x in stats.values())
    warn = a.get('warn_bytes')
    return {'categories': stats, 'bytes': total, 'partial': any(x['unknown_count'] for x in stats.values()),
            'warning': 'state_budget_exceeded' if warn and total > warn else None}

def state_cleanup(a):
    category = a.get('category')
    if category not in ('operation_logs', 'file_backups'):
        raise ValueError('Remote cleanup requires an explicit category.')
    target = a.get('target_identity')
    if not isinstance(target, str) or not re.fullmatch(r'[a-f0-9]{24}', target):
        raise ValueError('Missing selected server identity.')
    plans = state_root() / 'cleanup-plans'
    secure_dir(plans)
    operations = state_root() / 'operations'
    secure_dir(operations)
    with lock(state_root() / '.maintenance.lock'), lock(operations / '.registry.lock'):
        if a.get('preview', True):
            value = a.get('created_before')
            if not isinstance(value, str):
                raise ValueError('Preview requires a past created_before timestamp.')
            parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None or parsed.timestamp() > time.time():
                raise ValueError('Preview requires a past created_before timestamp with timezone.')
            limit = a.get('max_items', 100)
            if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
                raise ValueError('max_items must be 1..100.')
            stats, candidates = state_inventory(category, parsed.timestamp())
            candidates.sort(key=lambda x: x['relative'])
            selected = candidates[:limit]
            plan_id = uuid.uuid4().hex
            expires = time.time() + 900
            save_json(plans / (plan_id + '.json'), {'target': target, 'scope': 'remote', 'category': category, 'expires_at': expires, 'items': selected})
            return {'preview': True, 'plan_id': plan_id, 'expires_at': utc(expires), 'more': len(candidates) > limit,
                    'unavailable_count': stats[category]['unknown_count'],
                    'candidates': [{'id': x['relative'], 'bytes': x['fingerprint']['size']} for x in selected]}
        plan_id = a.get('plan_id', '')
        if not re.fullmatch(r'[a-f0-9]{32}', plan_id):
            raise ValueError('Apply requires plan_id from preview.')
        plan_file = state_file('cleanup-plans/' + plan_id + '.json')
        plan = load_json(plan_file)
        if plan.get('target') != target or plan.get('category') != category or plan.get('scope') != 'remote' or plan.get('expires_at', 0) <= time.time() or not isinstance(plan.get('items'), list) or len(plan['items']) > 100:
            raise ValueError('Cleanup plan expired or belongs to another server/category. Preview again.')
        if plan.get('applied'):
            raise ValueError('Cleanup plan was already applied. Preview again.')
        save_json(plan_file, dict(plan, applied=True))
        removed, skipped = [], []
        for item in plan['items']:
            relative = item.get('relative', '')
            try:
                pattern = r'operations/[a-f0-9]{32}/(?:stdout|stderr)\.log' if category == 'operation_logs' else r'backups/[a-f0-9]{32}\.bak'
                if not re.fullmatch(pattern, relative):
                    raise ValueError('Unknown cleanup target.')
                file = state_file(relative)
                if state_fingerprint(file) != item['fingerprint']:
                    raise ValueError('File changed.')
                if category == 'operation_logs':
                    operation_id = relative.split('/')[1]
                    current = status({'operation_id': operation_id})
                    if current['state'] not in ('completed', 'failed', 'cancelled', 'timed_out') or digest(state_file('operations/' + operation_id + '/status.json').read_bytes()) != item['status_hash']:
                        raise ValueError('Operation changed.')
                    save_json(operation_dir(operation_id) / 'logs-cleaned.json', {'removed_at': time.time()})
                else:
                    metadata = state_file(relative + '.json')
                    if digest(metadata.read_bytes()) != item['metadata_hash']:
                        raise ValueError('Backup metadata changed.')
                file.unlink()
                if category == 'file_backups':
                    metadata.unlink()
                removed.append(relative)
            except (OSError, ValueError, KeyError, TypeError):
                skipped.append({'id': relative, 'code': 'changed_or_unavailable'})
        return {'plan_id': plan_id, 'removed': removed, 'skipped': skipped}
