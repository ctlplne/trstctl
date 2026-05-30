package graph

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Row is one result of a Cypher-style query: a mapping from each RETURN
// expression (e.g. "c" or "r.name") to its string value. A bare variable
// resolves to the bound node's ID; a "var.field" expression resolves to that
// field (id, kind, name, or an Attrs key).
type Row map[string]string

// Query runs a Cypher-style query against the graph and returns the matching
// rows. The supported subset is a single linear MATCH path with optional node
// labels, an optional WHERE of AND-joined equality predicates, and a RETURN of
// one or more variables or variable fields:
//
//	MATCH (w:workload)-[:OWNS]->(c)-[:DEPLOYED_TO]->(r)
//	WHERE w.name = "payments-svc"
//	RETURN c, r.name
//
// It is deliberately small — enough for reachability, ownership, and
// blast-radius style questions — not a general Cypher engine.
func (g *Graph) Query(q string) ([]Row, error) {
	cq, err := parseCypher(q)
	if err != nil {
		return nil, err
	}
	return g.execCypher(cq)
}

// nodePat is a parsed node pattern: a binding variable and an optional kind
// label.
type nodePat struct {
	varName string
	kind    NodeKind // "" means any kind
}

// predicate is a parsed WHERE equality: variable.field = "value".
type predicate struct {
	varName string
	field   string
	value   string
}

// retCol is a parsed RETURN column: a variable and an optional field. expr is
// the original text, used as the Row key.
type retCol struct {
	expr    string
	varName string
	field   string // "" means return the node ID
}

type cypherQuery struct {
	nodes []nodePat
	edges []EdgeType // len(edges) == len(nodes)-1
	where []predicate
	ret   []retCol
}

var (
	reNode   = regexp.MustCompile(`^\(\s*([A-Za-z_]\w*)\s*(?::\s*([A-Za-z_]\w*)\s*)?\)`)
	reEdge   = regexp.MustCompile(`^-\s*\[\s*:\s*([A-Za-z_]\w*)\s*\]\s*->`)
	rePred   = regexp.MustCompile(`^([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*=\s*(?:"([^"]*)"|'([^']*)')$`)
	reRetCol = regexp.MustCompile(`^([A-Za-z_]\w*)(?:\.([A-Za-z_]\w*))?$`)
)

// splitClauses locates the MATCH / WHERE / RETURN keywords case-insensitively
// and returns the text of each section. WHERE is optional.
func splitClauses(q string) (match, where, ret string, err error) {
	upper := strings.ToUpper(q)
	mi := strings.Index(upper, "MATCH")
	ri := strings.LastIndex(upper, "RETURN")
	if mi != 0 {
		return "", "", "", fmt.Errorf("graph: query must begin with MATCH")
	}
	if ri < 0 {
		return "", "", "", fmt.Errorf("graph: query must contain RETURN")
	}
	ret = strings.TrimSpace(q[ri+len("RETURN"):])
	body := q[mi+len("MATCH") : ri]
	if wi := strings.Index(strings.ToUpper(body), "WHERE"); wi >= 0 {
		where = strings.TrimSpace(body[wi+len("WHERE"):])
		match = strings.TrimSpace(body[:wi])
	} else {
		match = strings.TrimSpace(body)
	}
	if match == "" || ret == "" {
		return "", "", "", fmt.Errorf("graph: query missing a MATCH pattern or RETURN list")
	}
	return match, where, ret, nil
}

func parseCypher(q string) (cypherQuery, error) {
	var cq cypherQuery
	matchSeg, whereSeg, retSeg, err := splitClauses(q)
	if err != nil {
		return cq, err
	}

	// Parse the path: a node, then zero or more (edge, node) pairs.
	s := strings.TrimSpace(matchSeg)
	m := reNode.FindStringSubmatch(s)
	if m == nil {
		return cq, fmt.Errorf("graph: expected a node pattern at %q", s)
	}
	cq.nodes = append(cq.nodes, nodePat{varName: m[1], kind: NodeKind(m[2])})
	s = strings.TrimSpace(s[len(m[0]):])
	for s != "" {
		em := reEdge.FindStringSubmatch(s)
		if em == nil {
			return cq, fmt.Errorf("graph: expected an edge -[:TYPE]-> at %q", s)
		}
		s = strings.TrimSpace(s[len(em[0]):])
		nm := reNode.FindStringSubmatch(s)
		if nm == nil {
			return cq, fmt.Errorf("graph: expected a node pattern after an edge at %q", s)
		}
		cq.edges = append(cq.edges, EdgeType(em[1]))
		cq.nodes = append(cq.nodes, nodePat{varName: nm[1], kind: NodeKind(nm[2])})
		s = strings.TrimSpace(s[len(nm[0]):])
	}

	bound := map[string]bool{}
	for _, n := range cq.nodes {
		if bound[n.varName] {
			return cq, fmt.Errorf("graph: variable %q is bound more than once", n.varName)
		}
		bound[n.varName] = true
	}

	// Parse WHERE predicates (AND-joined equalities).
	if whereSeg != "" {
		for _, part := range splitAnd(whereSeg) {
			pm := rePred.FindStringSubmatch(strings.TrimSpace(part))
			if pm == nil {
				return cq, fmt.Errorf("graph: malformed WHERE predicate %q", part)
			}
			val := pm[3]
			if val == "" {
				val = pm[4]
			}
			if !bound[pm[1]] {
				return cq, fmt.Errorf("graph: WHERE references unbound variable %q", pm[1])
			}
			cq.where = append(cq.where, predicate{varName: pm[1], field: pm[2], value: val})
		}
	}

	// Parse RETURN columns.
	for _, part := range strings.Split(retSeg, ",") {
		expr := strings.TrimSpace(part)
		rm := reRetCol.FindStringSubmatch(expr)
		if rm == nil {
			return cq, fmt.Errorf("graph: malformed RETURN item %q", expr)
		}
		if !bound[rm[1]] {
			return cq, fmt.Errorf("graph: RETURN references unbound variable %q", rm[1])
		}
		cq.ret = append(cq.ret, retCol{expr: expr, varName: rm[1], field: rm[2]})
	}
	if len(cq.ret) == 0 {
		return cq, fmt.Errorf("graph: empty RETURN list")
	}
	return cq, nil
}

// splitAnd splits a WHERE body on the AND keyword, case-insensitively, on word
// boundaries.
func splitAnd(where string) []string {
	re := regexp.MustCompile(`(?i)\s+AND\s+`)
	return re.Split(where, -1)
}

// execCypher evaluates a parsed query by binding the path against the graph,
// applying WHERE, and projecting the RETURN columns.
func (g *Graph) execCypher(cq cypherQuery) ([]Row, error) {
	// A binding maps each variable to a node ID. Start by binding the first
	// pattern to every node of the matching kind.
	type binding map[string]string
	var bindings []binding
	for _, n := range g.Nodes() {
		if matchesKind(n, cq.nodes[0].kind) {
			bindings = append(bindings, binding{cq.nodes[0].varName: n.ID})
		}
	}

	// Extend along each edge in the path.
	for i, et := range cq.edges {
		fromVar := cq.nodes[i].varName
		toPat := cq.nodes[i+1]
		var next []binding
		for _, b := range bindings {
			for _, e := range g.out[b[fromVar]] {
				if e.Type != et {
					continue
				}
				tn, ok := g.nodes[e.To]
				if !ok || !matchesKind(tn, toPat.kind) {
					continue
				}
				nb := make(binding, len(b)+1)
				for k, v := range b {
					nb[k] = v
				}
				nb[toPat.varName] = e.To
				next = append(next, nb)
			}
		}
		bindings = next
	}

	// Apply WHERE predicates.
	var kept []binding
	for _, b := range bindings {
		if g.satisfies(b, cq.where) {
			kept = append(kept, b)
		}
	}

	// Project RETURN columns, de-duplicating identical rows.
	seen := map[string]bool{}
	var rows []Row
	for _, b := range kept {
		row := Row{}
		key := make([]string, 0, len(cq.ret))
		for _, rc := range cq.ret {
			n := g.nodes[b[rc.varName]]
			val := n.ID
			if rc.field != "" {
				val = nodeField(n, rc.field)
			}
			row[rc.expr] = val
			key = append(key, rc.expr+"="+val)
		}
		k := strings.Join(key, "\x00")
		if seen[k] {
			continue
		}
		seen[k] = true
		rows = append(rows, row)
	}
	sortRows(rows, cq.ret)
	return rows, nil
}

func (g *Graph) satisfies(b map[string]string, preds []predicate) bool {
	for _, p := range preds {
		n := g.nodes[b[p.varName]]
		if nodeField(n, p.field) != p.value {
			return false
		}
	}
	return true
}

func matchesKind(n Node, kind NodeKind) bool { return kind == "" || n.Kind == kind }

// nodeField resolves a node field for WHERE/RETURN: the built-ins id, kind, and
// name, falling back to an Attrs key.
func nodeField(n Node, field string) string {
	switch field {
	case "id":
		return n.ID
	case "kind":
		return string(n.Kind)
	case "name":
		return n.Name
	default:
		return n.Attrs[field]
	}
}

// sortRows orders rows deterministically by their RETURN column values.
func sortRows(rows []Row, cols []retCol) {
	sort.Slice(rows, func(i, j int) bool {
		for _, c := range cols {
			if rows[i][c.expr] != rows[j][c.expr] {
				return rows[i][c.expr] < rows[j][c.expr]
			}
		}
		return false
	})
}
