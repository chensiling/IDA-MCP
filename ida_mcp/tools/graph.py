"""MCP 工具（graph 域）。

从单文件 server.py 拆分。共享项（mcp 实例、resolve_identifier、format_output、
错误翻译、辅助函数、常量）在 .._base。导入本模块即触发 @mcp.tool 注册。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool()
def call_graph(identifier: str, depth: int = 2, direction: str = "callees") -> str:
    """Build a call graph from a function up to N levels. direction is 'callees'
    (functions it calls), 'callers' (functions that call it), or 'both'.
    identifier accepts a name, hex address, or integer. Node count is capped;
    use small depth for large binaries."""
    try:
        root = resolve_identifier(identifier)
        root = _func_start(root) or root
        if direction not in ("callees", "callers", "both"):
            return format_output({"error": {"code": "INVALID_PARAM",
                "message": "direction must be callees/callers/both"}})
        depth = max(1, min(depth, CALLGRAPH_MAX_DEPTH))

        nodes = {}          # ea -> name
        edges = []          # {from, to}
        seen_edges = set()
        truncated = False

        def add_node(ea, name):
            if ea not in nodes:
                nodes[ea] = name or ea_to_hex(ea)

        try:
            root_name = api.get_name(root)["name"]
        except IDAError:
            root_name = ea_to_hex(root)
        add_node(root, root_name)

        def expand(get_neighbors, forward):
            nonlocal truncated
            frontier = [root]
            for _ in range(depth):
                nxt = []
                for cur in frontier:
                    for nb_ea, nb_name in get_neighbors(cur):
                        add_node(nb_ea, nb_name)
                        edge = (cur, nb_ea) if forward else (nb_ea, cur)
                        if edge not in seen_edges:
                            seen_edges.add(edge)
                            edges.append({"from": ea_to_hex(edge[0]),
                                          "to": ea_to_hex(edge[1])})
                        if nb_ea not in [f for f in frontier]:
                            nxt.append(nb_ea)
                        if len(nodes) >= CALLGRAPH_NODE_LIMIT:
                            truncated = True
                            return
                frontier = list(dict.fromkeys(nxt))
                if not frontier:
                    break

        if direction in ("callees", "both"):
            expand(_callees_of, True)
        if direction in ("callers", "both"):
            expand(_callers_of, False)

        return format_output({
            "root": {"name": root_name, "ea": ea_to_hex(root)},
            "direction": direction,
            "depth": depth,
            "node_count": len(nodes),
            "nodes": [{"ea": ea_to_hex(e), "name": n} for e, n in nodes.items()],
            "edges": edges,
            "truncated": truncated,
        })
    except IDAError as e:
        return error_result(e)


@mcp.tool()
def function_reachability(source: str, target: str, max_depth: int = 6) -> str:
    """Determine whether the source function can reach the target function via
    call edges, and return one call path if so. Both accept name, hex address,
    or integer. Uses bounded BFS; increase max_depth for deep call chains."""
    try:
        src = _func_start(resolve_identifier(source))
        dst = _func_start(resolve_identifier(target))
        if src is None or dst is None:
            return format_output({"error": {"code": "NO_FUNCTION",
                "message": "source or target is not inside a function"}})
        max_depth = max(1, min(max_depth, CALLGRAPH_MAX_DEPTH + 5))

        # BFS，记录前驱以重建路径
        from collections import deque
        visited = {src}
        parent = {}
        q = deque([(src, 0)])
        found = False
        nodes_scanned = 0
        while q:
            cur, d = q.popleft()
            if cur == dst:
                found = True
                break
            if d >= max_depth:
                continue
            nodes_scanned += 1
            if nodes_scanned > CALLGRAPH_NODE_LIMIT * 5:
                break
            for nb_ea, _nm in _callees_of(cur):
                if nb_ea not in visited:
                    visited.add(nb_ea)
                    parent[nb_ea] = cur
                    q.append((nb_ea, d + 1))

        if not found:
            return format_output({
                "reachable": False,
                "source": ea_to_hex(src),
                "target": ea_to_hex(dst),
                "searched_depth": max_depth,
            })
        # 重建路径
        path = [dst]
        while path[-1] != src:
            path.append(parent[path[-1]])
        path.reverse()
        detailed = []
        for ea in path:
            try:
                nm = api.get_name(ea)["name"]
            except IDAError:
                nm = ea_to_hex(ea)
            detailed.append({"ea": ea_to_hex(ea), "name": nm})
        return format_output({
            "reachable": True,
            "source": ea_to_hex(src),
            "target": ea_to_hex(dst),
            "path_length": len(path),
            "path": detailed,
        })
    except IDAError as e:
        return error_result(e)


# ---------------------------------------------------------------------------
# 意图工具（intent tools）——一次调用聚合"完成一个 LLM 认知任务"所需的最小完备证据集。
# 只给确定性证据（不含 has_crypto/score 之类语义结论），语义判断留给 LLM。
# 全部为 Layer 3 纯组合，复用已有原子/辅助，不新增 Layer 2 原子。
# ---------------------------------------------------------------------------
INTENT_CALLEE_LIMIT = 40
INTENT_CALLER_LIMIT = 20
INTENT_STRING_LIMIT = 40
