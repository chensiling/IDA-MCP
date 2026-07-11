"""MCP 工具（graph 域）。
"""

from .._base import *  # noqa: F401,F403


@mcp.tool(annotations=READ_ONLY_TOOL)
def call_graph(identifier: str, depth: CallGraphDepth = 2,
               direction: GraphDirection = "callees",
               f: str = None) -> str:
    """Build a call graph from a function up to N levels. direction is 'callees'
    (functions it calls), 'callers' (functions that call it), or 'both'.
    identifier accepts a name or address string. Node count is capped;
    use small depth for large binaries."""
    r = _route_if_remote(f, "call_graph", identifier=identifier,
                         depth=depth, direction=direction)
    if r: return r
    try:
        root = resolve_identifier(identifier)
        root = _func_start(root) or root
        if (not isinstance(direction, str)
                or direction not in ("callees", "callers", "both")):
            raise IDAError(
                "INVALID_PARAM", "direction must be callees/callers/both")
        depth = _validate_positive_int(
            depth, "depth", CALLGRAPH_MAX_DEPTH)

        nodes = {}
        edges = []
        seen_edges = set()
        truncated = False

        def add_node(ea, name):
            nonlocal truncated
            if ea not in nodes:
                if len(nodes) >= CALLGRAPH_NODE_LIMIT:
                    truncated = True
                    return False
                nodes[ea] = name or ea_to_hex(ea)
            return True

        try:
            root_name = api.get_name(root)["name"]
        except IDAError:
            root_name = ea_to_hex(root)
        add_node(root, root_name)

        def expand(get_neighbors, forward):
            frontier = [root]
            visited = {root}
            for _ in range(depth):
                nxt = []
                for cur in frontier:
                    for nb_ea, nb_name in get_neighbors(cur):
                        if not add_node(nb_ea, nb_name):
                            return
                        edge = (cur, nb_ea) if forward else (nb_ea, cur)
                        if edge not in seen_edges:
                            seen_edges.add(edge)
                            edges.append({"from": ea_to_hex(edge[0]),
                                          "to": ea_to_hex(edge[1])})
                        if nb_ea not in visited:
                            visited.add(nb_ea)
                            nxt.append(nb_ea)
                frontier = nxt
                if not frontier:
                    break

        if direction in ("callees", "both"):
            expand(_callees_of, True)
        if not truncated and direction in ("callers", "both"):
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


@mcp.tool(annotations=READ_ONLY_TOOL)
def function_reachability(source: str, target: str,
                          max_depth: ReachabilityDepth = 6,
                          f: str = None) -> str:
    """Determine whether the source function can reach the target function via
    call edges, and return one call path if so. Both accept name, hex address,
    or address string. Uses bounded BFS; increase max_depth for deep call chains."""
    r = _route_if_remote(f, "function_reachability",
                         source=source, target=target, max_depth=max_depth)
    if r: return r
    try:
        src = _func_start(resolve_identifier(source))
        dst = _func_start(resolve_identifier(target))
        if src is None or dst is None:
            raise IDAError(
                "NO_FUNCTION", "source or target is not inside a function")
        max_depth = _validate_positive_int(
            max_depth, "max_depth", CALLGRAPH_MAX_DEPTH + 5)

        from collections import deque
        visited = {src}
        parent = {}
        q = deque([(src, 0)])
        found = False
        nodes_scanned = 0
        node_budget = CALLGRAPH_NODE_LIMIT * 5
        budget_exhausted = False
        while q:
            cur, d = q.popleft()
            if cur == dst:
                found = True
                break
            if d >= max_depth:
                continue
            if nodes_scanned >= node_budget:
                budget_exhausted = True
                break
            nodes_scanned += 1
            for nb_ea, _nm in _callees_of(cur):
                if nb_ea == dst:
                    if nb_ea not in visited:
                        visited.add(nb_ea)
                        parent[nb_ea] = cur
                    found = True
                    break
                if nb_ea not in visited:
                    visited.add(nb_ea)
                    parent[nb_ea] = cur
                    q.append((nb_ea, d + 1))
            if found:
                break

        if not found:
            return format_output({
                "reachable": None if budget_exhausted else False,
                "complete": not budget_exhausted,
                "truncated": budget_exhausted,
                "source": ea_to_hex(src),
                "target": ea_to_hex(dst),
                "searched_depth": max_depth,
                "nodes_scanned": nodes_scanned,
            })
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
            "complete": True,
            "truncated": False,
            "source": ea_to_hex(src),
            "target": ea_to_hex(dst),
            "path_length": len(path),
            "path": detailed,
            "nodes_scanned": nodes_scanned,
        })
    except IDAError as e:
        return error_result(e)


_ALL_TOOLS.update({
    "call_graph": call_graph,
    "function_reachability": function_reachability,
})
