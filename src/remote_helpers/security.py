"""security functions, assembled into the standalone helper."""

def masked(text):
    def lines(value):
        return re.sub(r"[^\r\n]+", "[REDACTED]", value)
    def sensitive(key):
        normal = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).replace("-", "_").replace(".", "_").lower()
        return re.search(r"(?:^|_)(?:password|passwd|passphrase|token|secret|api_?key|private_?key|access_?key|secret_?key|credentials?|authorization)(?:_(?:value|data))?$", normal) is not None
    def assignment(match):
        prefix, value = match.groups()
        key = re.match(r'''^["']?([\w.-]+)''', prefix)[1]
        if key.lower() == "authorization" and re.fullmatch(r"(?:Bearer|Basic)[ \t]+", value):
            return match[0]
        suffix = re.search(r"[ \t]*(?:#.*)?$", value)[0]
        scalar = value[:len(value) - len(suffix)] if suffix else value
        if not sensitive(key) or not scalar or re.fullmatch(r"(?:true|false|null|~|[|>][+-]?)", scalar, flags=re.I):
            return match[0]
        if value[0] in "\"'" and value[-1] == value[0]:
            return prefix + value[0] + lines(value[1:-1]) + value[-1]
        return prefix + "[REDACTED]" + suffix
    text = re.sub(r"(Authorization[ \t]*[:=][ \t]*(?:Bearer|Basic)[ \t]+)\S+", r"\1[REDACTED]", text, flags=re.I)
    text = re.sub(r'''((?:"[\w.-]+"|'[\w.-]+'|\b[\w.-]+)[ \t]*[:=][ \t]*)("(?:\\.|[^"\\])*"|'(?:''|[^'])*'|[^\r\n,;{}\[\]]+)''', assignment, text)
    result, block_indent = [], None
    for line in text.splitlines(keepends=True):
        indent = len(re.match(r"^[ \t]*", line)[0])
        if block_indent is not None:
            if not line.strip():
                result.append(line)
                continue
            if indent > block_indent:
                result.append(re.sub(r"[^\r\n]+", lambda m: re.match(r"^[ \t]*", m[0])[0] + "[REDACTED]", line, count=1))
                continue
            block_indent = None
        block = re.fullmatch(r'''[ \t]*["']?([\w.-]+)["']?[ \t]*:[ \t]*[|>][+-]?[ \t]*(?:#.*)?(?:\r?\n)?''', line)
        if block and sensitive(block[1]):
            block_indent = indent
        result.append(line)
    text = "".join(result)
    text = re.sub(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----|$)", lambda m: lines(m[0]), text)
    text = re.sub(r"(Authorization[ \t]*[:=][ \t]*(?:Bearer|Basic)[ \t]+)\S+", r"\1[REDACTED]", text, flags=re.I)
    return re.sub(r"(\w+://[^\s/:]+:)[^\s@]+@", r"\1[REDACTED]@", text)

def safe_label(value, fallback=None):
    if value is None:
        return fallback
    if not isinstance(value, str) or not 1 <= len(value) <= 200 or "\x00" in value:
        raise ValueError("Operation labels must contain 1..200 characters, without NUL.")
    return masked(value)
