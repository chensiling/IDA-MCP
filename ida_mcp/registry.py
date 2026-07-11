"""Instance registry - maps file_id to connection/handler."""
import threading


class FileEntry:
    __slots__ = ('fid', 'name', 'arch', 'bits', 'path', 'pid', 'conn',
                 'local', 'call_port', 'protocol_version',
                 'implementation_version', 'tool_manifest_sha256',
                 'read_only', '_capabilities')

    def __init__(self, fid, name, arch, bits, path, pid, conn=None,
                 local=False, call_port=0, *, protocol_version,
                 implementation_version, tool_manifest_sha256, read_only,
                 capabilities):
        self.fid = fid
        self.name = name
        self.arch = arch
        self.bits = bits
        self.path = path
        self.pid = pid
        self.conn = conn
        self.local = local
        self.call_port = call_port
        self.protocol_version = protocol_version
        self.implementation_version = implementation_version
        self.tool_manifest_sha256 = tool_manifest_sha256
        self.read_only = read_only
        self._capabilities = dict(capabilities)

    @property
    def capabilities(self):
        return dict(self._capabilities)

    def public_metadata(self):
        return {
            'fid': self.fid,
            'name': self.name,
            'arch': self.arch,
            'bits': self.bits,
            'path': self.path,
            'read_only': self.read_only,
            'capabilities': dict(self._capabilities),
            'protocol_version': self.protocol_version,
            'implementation_version': self.implementation_version,
            'tool_manifest_sha256': self.tool_manifest_sha256,
        }


class Registry:
    def __init__(self):
        self._lock = threading.Lock()
        self._changed = threading.Condition(self._lock)
        self._files = {}
        self._conns = {}
        self._generation = 0
        self._accepting = True

    def register(self, entry):
        with self._lock:
            if not self._accepting:
                return False
            previous = self._files.get(entry.fid)
            if previous is not None and previous.conn is not None:
                self._untrack(previous.conn, entry.fid)
            self._files[entry.fid] = entry
            if entry.conn is not None:
                self._track(entry.conn, entry.fid)
            self._notify_changed()
            return True

    def unregister(self, fid, conn=None):
        """Remove an entry only when it still belongs to ``conn``.

        Passing no connection retains the administrative/unconditional behavior.
        """
        with self._lock:
            entry = self._files.get(fid)
            if entry is None or (conn is not None and entry.conn is not conn):
                return None
            self._files.pop(fid, None)
            if entry.conn is not None:
                self._untrack(entry.conn, fid)
            self._notify_changed()
            return entry

    def unregister_conn(self, conn):
        with self._lock:
            owner = self._conns.get(id(conn))
            if owner is None or owner[0] is not conn:
                return []
            _, tracked_fids = self._conns.pop(id(conn))
            removed = []
            fids = list(tracked_fids)
            for fid in fids:
                entry = self._files.get(fid)
                if entry is not None and entry.conn is conn:
                    self._files.pop(fid, None)
                    removed.append(fid)
            if removed:
                self._notify_changed()
            return removed

    def snapshot(self):
        """Return ``(member_count, generation, accepting)`` atomically."""
        with self._lock:
            return len(self._files), self._generation, self._accepting

    def wait_for_change(self, generation, timeout=None):
        """Wait until membership/acceptance changes, then return a snapshot."""
        with self._changed:
            self._changed.wait_for(
                lambda: self._generation != generation,
                timeout=timeout,
            )
            return len(self._files), self._generation, self._accepting

    def begin_shutdown_if_empty(self, generation):
        """Atomically stop registration if ``generation`` is still empty."""
        with self._lock:
            if (not self._accepting or self._generation != generation
                    or self._files):
                return False
            self._accepting = False
            self._notify_changed()
            return True

    def stop_accepting(self):
        with self._lock:
            if not self._accepting:
                return False
            self._accepting = False
            self._notify_changed()
            return True

    def is_accepting(self):
        with self._lock:
            return self._accepting

    def _notify_changed(self):
        self._generation += 1
        self._changed.notify_all()

    def _track(self, conn, fid):
        key = id(conn)
        owner = self._conns.get(key)
        if owner is None or owner[0] is not conn:
            owner = (conn, set())
            self._conns[key] = owner
        owner[1].add(fid)

    def _untrack(self, conn, fid):
        key = id(conn)
        owner = self._conns.get(key)
        if owner is None or owner[0] is not conn:
            return
        owner[1].discard(fid)
        if not owner[1]:
            self._conns.pop(key, None)

    def get(self, fid):
        with self._lock:
            return self._files.get(fid)

    def list_all(self):
        with self._lock:
            return list(self._files.values())

    def count(self):
        with self._lock:
            return len(self._files)

    def all_conns(self):
        with self._lock:
            seen = set()
            conns = []
            for e in self._files.values():
                if e.conn is not None and id(e.conn) not in seen:
                    seen.add(id(e.conn))
                    conns.append(e.conn)
            return conns

    def remote_entries(self):
        with self._lock:
            return [e for e in self._files.values() if not e.local]
