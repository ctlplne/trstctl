// SPDX-License-Identifier: BUSL-1.1

package featureparity

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
)

type ReportOptions struct {
	Title        string
	ConsoleBase  string
	GeneratedAt  string
	CandidateSHA string
}

type reportStage struct {
	Name   string
	Label  string
	Status StageStatus
	Reason string
	Proof  []string
}

type reportRow struct {
	Item            Item
	Stages          []reportStage
	ConsoleURL      string
	ReportCandidate string
}

type reportTool struct {
	Key      CanonicalTool
	Label    string
	Rows     []reportRow
	Blockers int
	Complete int
}

type reportView struct {
	Title       string
	GeneratedAt string
	Candidate   string
	Total       int
	Blockers    int
	Complete    int
	Partial     int
	Tools       []reportTool
}

var reportToolOrder = []CanonicalTool{
	ToolDiscover, ToolCertificates, ToolWorkloadsMachines, ToolSecrets,
	ToolSoftwareTrust, ToolOperations, ToolPlatformIntegrations,
}

var reportStageOrder = []struct {
	name  string
	label string
}{
	{"discover", "Discover"}, {"understand", "Understand"},
	{"configure", "Configure"}, {"preview", "Preview"},
	{"execute", "Execute"}, {"observe", "Observe"},
	{"recover", "Recover"}, {"verify", "Verify"},
	{"automate", "Automate"},
}

func RenderControlPanel(w io.Writer, catalog Catalog, options ReportOptions) error {
	if err := ValidateCatalog(catalog); err != nil {
		return fmt.Errorf("validate report catalog: %w", err)
	}
	if !exactCandidateSHA.MatchString(options.CandidateSHA) {
		return fmt.Errorf("exact report candidate %q is not a 40-character lowercase SHA", options.CandidateSHA)
	}
	if strings.TrimSpace(options.Title) == "" {
		options.Title = "trstctl frontend parity control panel"
	}
	view := buildReportView(catalog, options)
	if err := controlPanelTemplate.Execute(w, view); err != nil {
		return fmt.Errorf("render frontend parity control panel: %w", err)
	}
	return nil
}

func buildReportView(catalog Catalog, options ReportOptions) reportView {
	byTool := make(map[CanonicalTool][]Item, len(reportToolOrder))
	view := reportView{
		Title: options.Title, GeneratedAt: options.GeneratedAt,
		Candidate: options.CandidateSHA, Total: len(catalog.Items),
	}
	for _, item := range catalog.Items {
		byTool[item.Contract.Tool] = append(byTool[item.Contract.Tool], item)
		if item.Contract.ReleaseBlocking {
			view.Blockers++
		}
		if item.Contract.Maturity == MaturityCompleteVerticalSlice {
			view.Complete++
		} else {
			view.Partial++
		}
	}
	for _, tool := range reportToolOrder {
		items := byTool[tool]
		sort.Slice(items, func(i, j int) bool { return featureIDLess(items[i].FeatureID, items[j].FeatureID) })
		group := reportTool{Key: tool, Label: reportToolLabel(tool)}
		for _, item := range items {
			if item.Contract.ReleaseBlocking {
				group.Blockers++
			}
			if item.Contract.Maturity == MaturityCompleteVerticalSlice {
				group.Complete++
			}
			group.Rows = append(group.Rows, reportRow{
				Item:            item,
				Stages:          orderedReportStages(item.Contract.Stages),
				ConsoleURL:      strings.TrimRight(options.ConsoleBase, "/") + item.Contract.ConsoleRoute,
				ReportCandidate: options.CandidateSHA,
			})
		}
		view.Tools = append(view.Tools, group)
	}
	return view
}

func orderedReportStages(stages StageSet) []reportStage {
	cells := stages.Cells()
	out := make([]reportStage, 0, len(reportStageOrder))
	for _, stage := range reportStageOrder {
		cell := cells[stage.name]
		out = append(out, reportStage{Name: stage.name, Label: stage.label, Status: cell.Status, Reason: cell.Reason, Proof: cell.Evidence})
	}
	return out
}

func featureIDLess(left, right string) bool {
	var leftNumber, rightNumber int
	if _, err := fmt.Sscanf(left, "F%d", &leftNumber); err == nil {
		if _, err := fmt.Sscanf(right, "F%d", &rightNumber); err == nil {
			return leftNumber < rightNumber
		}
	}
	return left < right
}

func reportToolLabel(tool CanonicalTool) string {
	switch tool {
	case ToolDiscover:
		return "Discover"
	case ToolCertificates:
		return "Certificates"
	case ToolWorkloadsMachines:
		return "Workloads & Machines"
	case ToolSecrets:
		return "Secrets"
	case ToolSoftwareTrust:
		return "Software Trust"
	case ToolOperations:
		return "Operations"
	case ToolPlatformIntegrations:
		return "Platform & Integrations"
	default:
		return string(tool)
	}
}

func reportStatusLabel(status StageStatus) string {
	switch status {
	case StageComplete:
		return "Complete"
	case StageNotApplicable:
		return "Not applicable"
	case StageIntentionalAPIOnly:
		return "API/CLI only"
	case StageBlocked:
		return "Blocked"
	case StageMissing:
		return "Missing"
	default:
		return string(status)
	}
}

func shortCandidate(sha string) string {
	if len(sha) < 8 {
		return sha
	}
	return sha[:8]
}

var controlPanelTemplate = template.Must(template.New("frontend-parity-control-panel").Funcs(template.FuncMap{
	"join":        strings.Join,
	"statusLabel": reportStatusLabel,
	"shortSHA":    shortCandidate,
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{color-scheme:light;--ink:#15221f;--muted:#63726d;--paper:#f4f6f3;--surface:#fff;--line:#dce3df;--green:#176b52;--green-soft:#e8f4ee;--amber:#8a5a16;--amber-soft:#fff4df;--red:#9c3b36;--red-soft:#fff0ee;--blue:#315f75;--blue-soft:#eaf2f6;--radius:16px;--shadow:0 10px 28px rgba(24,42,36,.07)}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:var(--blue);text-decoration-thickness:1px;text-underline-offset:3px}code{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.shell{max-width:1540px;margin:auto;padding:40px 28px 80px}.eyebrow{letter-spacing:.12em;text-transform:uppercase;font-size:12px;font-weight:750;color:var(--green)}h1{font-size:clamp(30px,5vw,52px);line-height:1.05;letter-spacing:-.035em;margin:10px 0 14px;max-width:900px}h2{font-size:24px;letter-spacing:-.02em;margin:0}.lede{max-width:850px;color:var(--muted);font-size:17px}.meta{display:flex;gap:12px;flex-wrap:wrap;margin-top:18px;color:var(--muted);font-size:13px}.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:28px 0}.metric{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow)}.metric strong{display:block;font-size:28px;letter-spacing:-.03em}.metric span{color:var(--muted)}.metric.danger strong{color:var(--red)}.metric.good strong{color:var(--green)}.controls{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--paper) 92%,transparent);backdrop-filter:blur(12px);border-block:1px solid var(--line);display:grid;grid-template-columns:minmax(240px,2fr) repeat(2,minmax(160px,1fr)) auto;gap:12px;padding:14px 0;margin:28px 0}.control{display:grid;gap:5px;font-size:12px;font-weight:700;color:var(--muted)}input,select{width:100%;min-height:42px;border:1px solid #cbd5d0;border-radius:10px;background:#fff;color:var(--ink);padding:9px 11px;font:inherit}.check{display:flex;align-items:end;gap:8px;padding-bottom:10px;white-space:nowrap}.check input{width:18px;min-height:18px}.tool{margin:34px 0}.tool-head{display:flex;align-items:end;justify-content:space-between;gap:18px;margin-bottom:12px}.tool-head p{margin:0;color:var(--muted)}.capabilities{display:grid;gap:12px}.capability{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}.capability[hidden],.tool[hidden]{display:none}.cap-head{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:16px;padding:18px 20px}.title-line{display:flex;gap:9px;align-items:center;flex-wrap:wrap}.fid{font:700 12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--blue)}.feature{font-size:18px;font-weight:760;letter-spacing:-.015em}.purpose{color:var(--muted);margin:7px 0 0;max-width:900px}.badges{display:flex;align-items:flex-start;gap:7px;flex-wrap:wrap;justify-content:flex-end}.badge{display:inline-flex;align-items:center;border-radius:999px;padding:5px 9px;font-size:11px;font-weight:750;background:var(--blue-soft);color:var(--blue)}.badge.complete{background:var(--green-soft);color:var(--green)}.badge.blocker,.badge.missing,.badge.blocked{background:var(--red-soft);color:var(--red)}.badge.partial_workflow,.badge.observe_only,.badge.api_cli_only{background:var(--amber-soft);color:var(--amber)}.stage-grid{display:grid;grid-template-columns:repeat(9,minmax(90px,1fr));border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:#fbfcfb}.stage{padding:12px 10px;border-right:1px solid var(--line);min-width:0}.stage:last-child{border-right:0}.stage-name{display:block;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em}.stage-status{display:block;font-size:12px;font-weight:760;margin-top:3px}.stage.complete .stage-status{color:var(--green)}.stage.missing .stage-status,.stage.blocked .stage-status{color:var(--red)}.stage.not_applicable .stage-status,.stage.intentional_api_only .stage-status{color:var(--amber)}details{padding:0 20px}summary{cursor:pointer;padding:13px 0;font-weight:700;color:var(--blue)}.detail-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;padding:0 0 20px}.detail-block{background:#f8faf8;border:1px solid var(--line);border-radius:12px;padding:13px}.detail-block h3{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 8px}.detail-block p{margin:5px 0}.detail-block ul{margin:6px 0;padding-left:18px}.stage-detail{border-top:1px solid var(--line);padding-top:8px;margin-top:8px}.empty{background:var(--surface);border:1px dashed var(--line);border-radius:var(--radius);padding:28px;text-align:center;color:var(--muted)}.legend{margin:34px 0 0;color:var(--muted);font-size:13px}.legend strong{color:var(--ink)}
@media(max-width:1000px){.summary{grid-template-columns:repeat(2,1fr)}.controls{grid-template-columns:1fr 1fr}.stage-grid{grid-template-columns:repeat(3,1fr)}.stage{border-bottom:1px solid var(--line)}.detail-grid{grid-template-columns:1fr 1fr}}
@media(max-width:640px){.shell{padding:26px 14px 60px}.summary,.controls,.detail-grid{grid-template-columns:1fr}.controls{position:static}.cap-head{grid-template-columns:1fr}.badges{justify-content:flex-start}.stage-grid{grid-template-columns:repeat(2,1fr)}.tool-head{display:block}}
</style>
</head>
<body>
<main class="shell">
<header>
<div class="eyebrow">Frontend convergence · canonical schema v3</div>
<h1>{{.Title}}</h1>
<p class="lede">One ledger answers a simple question: can an operator finish the real job, or is the backend still ahead of the console? Maturity is computed from explicit stages. A route, button, or mocked story cannot make a row green by itself.</p>
<div class="meta"><span>Generated {{.GeneratedAt}}</span><span>candidate {{shortSHA .Candidate}}</span><span>offline standalone HTML</span></div>
</header>
<section class="summary" aria-label="Parity summary">
<div class="metric"><strong>{{.Total}}</strong><span>canonical capabilities</span></div>
<div class="metric danger"><strong>{{.Blockers}}</strong><span>{{.Blockers}} release blockers</span></div>
<div class="metric good"><strong>{{.Complete}}</strong><span>{{.Complete}} complete vertical slices</span></div>
<div class="metric"><strong>{{.Partial}}</strong><span>incomplete or deliberately bounded rows</span></div>
</section>
<section class="controls" aria-label="Report filters">
<label class="control">Filter capabilities<input id="search" type="search" placeholder="Feature, purpose, owner, route…"></label>
<label class="control">Tool<select id="tool"><option value="">All tools</option>{{range .Tools}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label>
<label class="control">Maturity<select id="maturity"><option value="">All maturity states</option><option value="complete_vertical_slice">Complete vertical slice</option><option value="partial_workflow">Partial workflow</option><option value="observe_only">Observe only</option><option value="api_cli_only">API/CLI only</option><option value="absent">Absent</option></select></label>
<label class="check"><input id="blockers" type="checkbox">Release blockers only</label>
</section>
<p id="empty" class="empty" hidden>No capabilities match these filters.</p>
{{range .Tools}}
<section class="tool" data-tool-section="{{.Key}}">
<div class="tool-head"><div><div class="eyebrow">Canonical tool</div><h2>{{.Label}}</h2></div><p>{{len .Rows}} capabilities · {{.Blockers}} blockers · {{.Complete}} complete</p></div>
<div class="capabilities">
{{range .Rows}}<article class="capability" data-tool="{{.Item.Contract.Tool}}" data-maturity="{{.Item.Contract.Maturity}}" data-blocker="{{.Item.Contract.ReleaseBlocking}}" data-search="{{.Item.FeatureID}} {{.Item.Feature}} {{.Item.Contract.Purpose}} {{.Item.Contract.Owner}} {{.Item.Contract.ConsoleRoute}}">
<div class="cap-head"><div><div class="title-line"><span class="fid">{{.Item.FeatureID}}</span><span class="feature">{{.Item.Feature}}</span></div><p class="purpose">{{.Item.Contract.Purpose}}</p></div><div class="badges"><span class="badge {{.Item.Contract.Maturity}}">{{.Item.Contract.Maturity}}</span><span class="badge">{{.Item.Contract.Classification}}</span>{{if .Item.Contract.ReleaseBlocking}}<span class="badge blocker">release blocker</span>{{end}}</div></div>
<div class="stage-grid" aria-label="Capability stages">{{range .Stages}}<div class="stage {{.Status}}" title="{{if .Reason}}{{.Reason}}{{else}}{{join .Proof "; "}}{{end}}"><span class="stage-name">{{.Name}}</span><span class="stage-status">{{statusLabel .Status}}</span></div>{{end}}</div>
<details><summary>Evidence, boundaries, and next work</summary><div class="detail-grid">
<div class="detail-block"><h3>Operator entry</h3><p><a href="{{.ConsoleURL}}">{{.Item.Contract.ConsoleRoute}}</a></p><p>Owner: <strong>{{.Item.Contract.Owner}}</strong></p><p>Edition: {{.Item.Contract.Edition}}</p><p>Report candidate: <code>{{.ReportCandidate}}</code></p><p>Contract evidence recorded at: <code>{{.Item.Contract.CandidateSHA}}</code></p></div>
<div class="detail-block"><h3>Security boundary</h3><p>{{.Item.Contract.PermissionAuthority}}</p><p>Effects: {{.Item.Contract.SideEffects}}</p><p>{{.Item.Contract.SecretDataHandling}}</p>{{if .Item.Contract.Dependencies}}<ul>{{range .Item.Contract.Dependencies}}<li>{{.}}</li>{{end}}</ul>{{end}}</div>
<div class="detail-block"><h3>API and CLI</h3>{{if .Item.APISurface}}<p><strong>API</strong></p><ul>{{range .Item.APISurface}}<li><code>{{.}}</code></li>{{end}}</ul>{{else}}<p>{{.Item.APINA}}</p>{{end}}{{if .Item.CLISurface}}<p><strong>CLI</strong></p><ul>{{range .Item.CLISurface}}<li><code>{{.}}</code></li>{{end}}</ul>{{else}}<p>{{.Item.CLINA}}</p>{{end}}</div>
<div class="detail-block"><h3>Current truth</h3><p>{{.Item.CurrentMapping}}</p><p><strong>Target:</strong> {{.Item.TargetMapping}}</p></div>
<div class="detail-block"><h3>Tests and docs</h3><p>{{.Item.AcceptanceTest}}</p>{{if .Item.SourceDocs}}<ul>{{range .Item.SourceDocs}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}</div>
<div class="detail-block"><h3>Stage reasons and proof</h3>{{range .Stages}}<div class="stage-detail"><strong>{{.Label}} · {{statusLabel .Status}}</strong>{{if .Reason}}<p>{{.Reason}}</p>{{else}}<ul>{{range .Proof}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}</div>{{end}}</div>
</div></details>
</article>{{end}}
</div></section>{{end}}
<p class="legend"><strong>How to read this:</strong> green means the stage has explicit evidence; amber is intentionally bounded or not applicable; red is missing or blocked. A primary row stays release-blocking until every applicable stage is complete on one candidate.</p>
</main>
<script>
(()=>{const q=document.querySelector('#search'),tool=document.querySelector('#tool'),maturity=document.querySelector('#maturity'),blockers=document.querySelector('#blockers'),empty=document.querySelector('#empty');const rows=[...document.querySelectorAll('.capability')],sections=[...document.querySelectorAll('.tool')];function apply(){const needle=q.value.trim().toLowerCase();let visible=0;for(const row of rows){const show=(!needle||row.dataset.search.toLowerCase().includes(needle))&&(!tool.value||row.dataset.tool===tool.value)&&(!maturity.value||row.dataset.maturity===maturity.value)&&(!blockers.checked||row.dataset.blocker==='true');row.hidden=!show;if(show)visible++}for(const section of sections)section.hidden=![...section.querySelectorAll('.capability')].some(row=>!row.hidden);empty.hidden=visible!==0}for(const control of[q,tool,maturity,blockers])control.addEventListener('input',apply);apply()})();
</script>
</body></html>`))
