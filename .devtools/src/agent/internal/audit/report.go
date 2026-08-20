package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

const reportFileName = "report.html"

type reportJSON struct {
	GeneratedAt string           `json:"generatedAt"`
	Project     string           `json:"project"`
	Totals      reportTotals     `json:"totals"`
	Users       []reportUserJSON `json:"users"`
}

type reportTotals struct {
	Users   int `json:"users"`
	Chats   int `json:"chats"`
	Prompts int `json:"prompts"`
}

type reportUserJSON struct {
	Email        string           `json:"email"`
	ChatCount    int              `json:"chatCount"`
	PromptCount  int              `json:"promptCount"`
	Tools        []string         `json:"tools"`
	LastActivity string           `json:"lastActivity"`
	Chats        []reportChatJSON `json:"chats"`
}

type reportChatJSON struct {
	SessionID   string             `json:"sessionId"`
	Tool        string             `json:"tool"`
	Branch      string             `json:"branch"`
	Repository  string             `json:"repository"`
	PromptCount int                `json:"promptCount"`
	Start       string             `json:"start"`
	End         string             `json:"end"`
	Prompts     []reportPromptJSON `json:"prompts"`
}

type reportPromptJSON struct {
	Time string `json:"time"`
	Text string `json:"text"`
}

// GenerateReport builds the administrator's self-contained HTML view of the
// committed registry as a drill-down (users -> chats -> prompts) and returns the
// path it wrote. It is read-only and never contacts the network.
func GenerateReport(start, outputPath string) (string, error) {
	repo, err := DiscoverRepository(start)
	if err != nil {
		return "", err
	}
	// Viewing is a request to see prompts, so recover from the local provider
	// transcripts first. On a fresh Codex clone the hook never ran, and this is
	// the moment the worker expects the prompt they just typed to appear.
	recoverForViewingBestEffort(repo)
	// Keep direct-capture delivery available without performing session
	// activation.
	if hookErr := ensurePreCommitHook(repo.Root); hookErr != nil {
		recordLocalHealth(repo.Root, "report warning: pre-commit delivery hook is unavailable")
	}
	if publishErr := publishAllRegistryBackups(repo.Root); publishErr != nil {
		return "", fmt.Errorf("publish prompt registry: %w", publishErr)
	}
	events, err := readRegistryEvents(repo.Root)
	if err != nil {
		return "", err
	}
	if outputPath == "" {
		outputPath = filepath.Join(repo.Root, ".devtools", reportFileName)
	}
	outputPath, err = filepath.Abs(outputPath)
	if err != nil {
		return "", fmt.Errorf("resolve report path: %w", err)
	}
	data := buildReportJSON(repo.Name, events)
	payload, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("encode report data: %w", err)
	}
	if err := writeReportAtomic(repo.Root, outputPath, []byte(renderReportHTML(payload))); err != nil {
		return "", err
	}
	return outputPath, nil
}

func writeReportAtomic(repoRoot, outputPath string, contents []byte) error {
	directory := filepath.Dir(outputPath)
	if pathInRepo(outputPath, repoRoot) {
		if err := validateDirectoryTree(repoRoot, directory); err != nil {
			return fmt.Errorf("validate report directory: %w", err)
		}
		if err := ensureDirectoryDurableUnder(repoRoot, directory, 0o700); err != nil {
			return fmt.Errorf("create report directory: %w", err)
		}
	} else if err := ensureDirectoryDurable(directory, 0o700); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	if _, err := regularFileInfo(outputPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("refuse unsafe report destination: %w", err)
	}
	file, err := os.CreateTemp(directory, ".prompt-audit-report-*.tmp")
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Close(); err != nil {
		return fmt.Errorf("close empty report: %w", err)
	}
	// The report contains every prompt. Apply private permissions before any
	// report bytes are written, just like the authoritative prompt store.
	file, err = openProtectedRegularFile(
		repoRoot,
		temporary,
		os.O_TRUNC|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open protected report: %w", err)
	}
	if _, err = file.Write(contents); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close report: %w", closeErr)
	}
	if err := replaceFile(temporary, outputPath); err != nil {
		return fmt.Errorf("replace report: %w", err)
	}
	if err := protectFile(repoRoot, outputPath); err != nil {
		return fmt.Errorf("protect final report: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync report directory: %w", err)
	}
	return nil
}

func buildReportJSON(project string, events []model.Event) reportJSON {
	byUser := groupBy(events, func(e model.Event) string { return e.UserEmail })
	chatKeys := map[string]struct{}{}
	users := make([]reportUserJSON, 0, len(byUser))
	for _, email := range sortedKeys(byUser) {
		userEvents := byUser[email]
		bySession := groupBy(userEvents, func(e model.Event) string { return e.SessionID })
		toolSet := map[string]struct{}{}
		var lastActivity time.Time
		chats := make([]reportChatJSON, 0, len(bySession))
		for session, sessionEvents := range bySession {
			chatKeys[email+"\n"+session] = struct{}{}
			prompts := dedupeAndSort(sessionEvents)
			rows := make([]reportPromptJSON, 0, len(prompts))
			for _, event := range prompts {
				rows = append(rows, reportPromptJSON{
					Time: event.Timestamp.UTC().Format("2006-01-02 15:04:05"),
					Text: event.Prompt,
				})
			}
			toolSet[prompts[0].Tool] = struct{}{}
			end := prompts[len(prompts)-1].Timestamp
			if end.After(lastActivity) {
				lastActivity = end
			}
			chats = append(chats, reportChatJSON{
				SessionID:   session,
				Tool:        prompts[0].Tool,
				Branch:      prompts[0].Branch,
				Repository:  prompts[0].RepositoryName,
				PromptCount: len(prompts),
				Start:       prompts[0].Timestamp.UTC().Format("2006-01-02 15:04"),
				End:         end.UTC().Format("2006-01-02 15:04"),
				Prompts:     rows,
			})
		}
		// Most recently active chats first.
		sort.SliceStable(chats, func(i, j int) bool { return chats[i].End > chats[j].End })
		tools := make([]string, 0, len(toolSet))
		for tool := range toolSet {
			tools = append(tools, tool)
		}
		sort.Strings(tools)
		lastActivityLabel := ""
		if !lastActivity.IsZero() {
			lastActivityLabel = lastActivity.UTC().Format("2006-01-02 15:04")
		}
		users = append(users, reportUserJSON{
			Email:        email,
			ChatCount:    len(chats),
			PromptCount:  len(userEvents),
			Tools:        tools,
			LastActivity: lastActivityLabel,
			Chats:        chats,
		})
	}
	// Most active users first.
	sort.SliceStable(users, func(i, j int) bool { return users[i].PromptCount > users[j].PromptCount })
	return reportJSON{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Project:     project,
		Totals:      reportTotals{Users: len(byUser), Chats: len(chatKeys), Prompts: len(events)},
		Users:       users,
	}
}

// renderReportHTML embeds the JSON data (already HTML-escaped by json.Marshal, so
// it cannot break out of the <script> tag) and a small self-contained client that
// renders the users -> chats -> prompts drill-down.
func renderReportHTML(payload []byte) string {
	return reportHTMLHead +
		"<script id=\"prompt-audit-data\" type=\"application/json\">" + string(payload) + "</script>\n" +
		reportHTMLApp
}

const reportHTMLHead = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Registro de prompts</title>
<style>
  :root{color-scheme:light dark;--bg:#0f1115;--panel:#191c22;--panel2:#20242c;--ink:#e8eaed;--muted:#9aa4b2;--line:#2a2f37;--accent:#6ea8fe;--chip:#25304a;--row:#1c2029;--rowh:#242a35;}
  @media (prefers-color-scheme:light){:root{--bg:#f5f6f8;--panel:#fff;--panel2:#fafbfc;--ink:#1a1d21;--muted:#5b6470;--line:#e4e7eb;--accent:#2563eb;--chip:#eaf0ff;--row:#fff;--rowh:#f2f5fb;}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  header{position:sticky;top:0;z-index:5;background:var(--panel);border-bottom:1px solid var(--line);padding:16px 22px}
  h1{margin:0;font-size:18px}
  .sub{color:var(--muted);font-size:12px;margin-top:2px}
  .stats{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}
  .stat{background:var(--chip);border-radius:9px;padding:6px 12px;font-size:13px}
  .stat b{font-size:16px;margin-right:4px}
  .search{margin-top:12px;width:100%;max-width:520px;padding:9px 12px;border:1px solid var(--line);border-radius:9px;background:var(--panel2);color:var(--ink);font-size:14px}
  .wrap{max-width:1100px;margin:0 auto;padding:18px 22px}
  nav.crumbs{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:14px;color:var(--muted);font-size:13px}
  nav.crumbs a{color:var(--accent);cursor:pointer;text-decoration:none}
  nav.crumbs a:hover{text-decoration:underline}
  nav.crumbs .sep{opacity:.5}
  table{width:100%;border-collapse:separate;border-spacing:0;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
  thead th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);padding:11px 14px;background:var(--panel2);border-bottom:1px solid var(--line)}
  tbody td{padding:12px 14px;border-top:1px solid var(--line)}
  tbody tr{background:var(--row)}
  tr.click{cursor:pointer}
  tr.click:hover{background:var(--rowh)}
  td.num{font-variant-numeric:tabular-nums;color:var(--muted);width:1%;white-space:nowrap}
  .who{font-weight:600}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--muted);word-break:break-all}
  .chip{display:inline-block;background:var(--chip);border-radius:6px;padding:1px 8px;margin:0 4px 2px 0;font-size:12px}
  .go{color:var(--muted);text-align:right;width:1%}
  .prompts{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
  .p{padding:12px 16px;border-top:1px solid var(--line);display:flex;gap:14px}
  .p:first-child{border-top:none}
  .p .t{color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums;white-space:nowrap;padding-top:1px}
  .p .x{white-space:pre-wrap;word-break:break-word}
  .empty{color:var(--muted);text-align:center;padding:48px 16px}
  mark{background:var(--accent);color:#001;border-radius:3px;padding:0 2px}
</style>
</head>
<body>
<header>
  <h1 id="title">Registro de prompts</h1>
  <div class="sub" id="subtitle"></div>
  <div class="stats" id="stats"></div>
  <input class="search" id="q" type="search" placeholder="Buscar en todos los prompts…" autocomplete="off">
</header>
<div class="wrap">
  <nav class="crumbs" id="crumbs"></nav>
  <div id="content"></div>
</div>
`

const reportHTMLApp = `<script>
(function(){
  var DATA = JSON.parse(document.getElementById('prompt-audit-data').textContent);
  var state = {view:'users', u:null, c:null};
  var content = document.getElementById('content');
  var crumbs = document.getElementById('crumbs');
  var q = document.getElementById('q');

  document.getElementById('title').textContent = 'Registro de prompts' + (DATA.project ? ' · ' + DATA.project : '');
  document.getElementById('subtitle').textContent = 'Generado el ' + DATA.generatedAt + ' — solo prompts del usuario; nunca respuestas de la IA.';
  document.getElementById('stats').innerHTML =
    stat(DATA.totals.users,'usuario(s)') + stat(DATA.totals.chats,'chat(s)') + stat(DATA.totals.prompts,'prompt(s)');

  function stat(n,l){ return '<span class="stat"><b>'+n+'</b>'+l+'</span>'; }
  function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
  function chips(a){ return (a||[]).map(function(t){return '<span class="chip">'+esc(t)+'</span>';}).join(''); }
  function shortId(s){ return s && s.length>18 ? s.slice(0,18)+'…' : (s||''); }
  function hi(text,ql){ var e=esc(text); if(!ql) return e; var i=text.toLowerCase().indexOf(ql); if(i<0) return e; return esc(text.slice(0,i))+'<mark>'+esc(text.slice(i,i+ql.length))+'</mark>'+esc(text.slice(i+ql.length)); }

  function renderCrumbs(){
    var q0 = q.value.trim();
    if(q0){ crumbs.innerHTML = '<span>Resultados de búsqueda</span>'; return; }
    var h = '<a data-nav="users">Usuarios</a>';
    if(state.view==='chats' || state.view==='prompts'){
      h += '<span class="sep">›</span><a data-nav="chats">'+esc(DATA.users[state.u].email)+'</a>';
    }
    if(state.view==='prompts'){
      h += '<span class="sep">›</span><span>Chat '+esc(shortId(DATA.users[state.u].chats[state.c].sessionId))+'</span>';
    }
    crumbs.innerHTML = h;
  }

  function renderUsers(){
    if(!DATA.users.length){ content.innerHTML='<div class="empty">Todavía no hay prompts registrados.</div>'; return; }
    var rows = DATA.users.map(function(u,i){
      return '<tr class="click" data-u="'+i+'">'+
        '<td class="who">'+esc(u.email)+'</td>'+
        '<td>'+chips(u.tools)+'</td>'+
        '<td class="num">'+u.chatCount+'</td>'+
        '<td class="num">'+u.promptCount+'</td>'+
        '<td class="num">'+esc(u.lastActivity)+'</td>'+
        '<td class="go">›</td></tr>';
    }).join('');
    content.innerHTML = '<table><thead><tr><th>Usuario</th><th>Herramientas</th><th>Chats</th><th>Prompts</th><th>Última actividad</th><th></th></tr></thead><tbody>'+rows+'</tbody></table>';
  }

  function renderChats(){
    var u = DATA.users[state.u];
    var rows = u.chats.map(function(c,j){
      return '<tr class="click" data-c="'+j+'">'+
        '<td class="mono">'+esc(c.sessionId)+'</td>'+
        '<td><span class="chip">'+esc(c.tool)+'</span></td>'+
        '<td class="num">'+c.promptCount+'</td>'+
        '<td class="num">'+esc(c.start)+'</td>'+
        '<td class="num">'+esc(c.end)+'</td>'+
        '<td class="go">›</td></tr>';
    }).join('');
    content.innerHTML = '<table><thead><tr><th>Chat</th><th>Herramienta</th><th>Prompts</th><th>Inicio</th><th>Fin</th><th></th></tr></thead><tbody>'+rows+'</tbody></table>';
  }

  function renderPrompts(){
    var c = DATA.users[state.u].chats[state.c];
    var rows = c.prompts.map(function(p){
      return '<div class="p"><div class="t">'+esc(p.time)+'</div><div class="x">'+esc(p.text)+'</div></div>';
    }).join('');
    content.innerHTML = '<div class="prompts">'+rows+'</div>';
  }

  function renderSearch(query){
    var ql = query.toLowerCase();
    var hits = [];
    DATA.users.forEach(function(u){ u.chats.forEach(function(c){ c.prompts.forEach(function(p){
      if(p.text.toLowerCase().indexOf(ql) !== -1){ hits.push({u:u,c:c,p:p}); }
    }); }); });
    if(!hits.length){ content.innerHTML='<div class="empty">Sin coincidencias para “'+esc(query)+'”.</div>'; return; }
    var rows = hits.map(function(h){
      return '<div class="p"><div class="t">'+esc(h.p.time)+'</div><div class="x">'+
        '<div style="color:var(--muted);font-size:12px;margin-bottom:2px">'+esc(h.u.email)+' · <span class="chip">'+esc(h.c.tool)+'</span> · Chat '+esc(shortId(h.c.sessionId))+'</div>'+
        hi(h.p.text, ql)+'</div></div>';
    }).join('');
    content.innerHTML = '<div class="prompts">'+rows+'</div>';
  }

  function render(){
    renderCrumbs();
    var query = q.value.trim();
    if(query){ renderSearch(query); return; }
    if(state.view==='users') renderUsers();
    else if(state.view==='chats') renderChats();
    else renderPrompts();
  }

  content.addEventListener('click', function(ev){
    var ur = ev.target.closest('tr[data-u]');
    if(ur){ state.view='chats'; state.u=+ur.getAttribute('data-u'); state.c=null; render(); return; }
    var cr = ev.target.closest('tr[data-c]');
    if(cr){ state.view='prompts'; state.c=+cr.getAttribute('data-c'); render(); return; }
  });
  crumbs.addEventListener('click', function(ev){
    var a = ev.target.closest('a[data-nav]');
    if(!a) return;
    var nav = a.getAttribute('data-nav');
    if(nav==='users'){ state.view='users'; state.u=null; state.c=null; }
    else if(nav==='chats'){ state.view='chats'; state.c=null; }
    render();
  });
  var timer; q.addEventListener('input', function(){ clearTimeout(timer); timer=setTimeout(render,120); });

  render();
})();
</script>
</body>
</html>
`
