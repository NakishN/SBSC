package engine

const htmlTemplate = `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SBSC — отчёт</title>
<style>
:root{--bg:#0b0f14;--panel:#121821;--panel2:#0f151d;--text:#e6edf3;--muted:#8b98a5;--border:#243040;--red:#ff4d5e;--orange:#ff9f43;--yellow:#f5d76e;--green:#38d39f;--blue:#4da3ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}
header{padding:28px 32px 18px;border-bottom:1px solid var(--border);background:linear-gradient(135deg,#101a26,#0b0f14)}
h1{margin:0 0 6px;font-size:26px;letter-spacing:.2px}h2{margin:32px 0 12px;font-size:19px}
.sub{color:var(--muted)}.wrap{padding:0 32px 40px;max-width:1500px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px 0}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.card .n{font-size:28px;font-weight:700}.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.card.red .n{color:var(--red)}.card.orange .n{color:var(--orange)}.card.yellow .n{color:var(--yellow)}.card.green .n{color:var(--green)}.card.blue .n{color:var(--blue)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);background:var(--panel2)}
tr:last-child td{border-bottom:none}
.path{color:var(--muted);font-size:11px;word-break:break-all;max-width:520px}
.verdict{display:inline-block;padding:3px 9px;border-radius:999px;font-weight:700;font-size:12px;white-space:nowrap}
.verdict.low{background:rgba(56,211,159,.12);color:var(--green);border:1px solid rgba(56,211,159,.35)}
.verdict.medium{background:rgba(245,215,110,.12);color:var(--yellow);border:1px solid rgba(245,215,110,.35)}
.verdict.high{background:rgba(255,159,67,.12);color:var(--orange);border:1px solid rgba(255,159,67,.35)}
.verdict.critical{background:rgba(255,77,94,.13);color:var(--red);border:1px solid rgba(255,77,94,.4)}
.bar{height:7px;background:#1c2633;border-radius:999px;overflow:hidden;margin-bottom:4px;min-width:70px}
.bar span{display:block;height:100%;background:var(--green)}.critical .bar span{background:var(--red)}.high .bar span{background:var(--orange)}.medium .bar span{background:var(--yellow)}
details{background:var(--panel);border:1px solid var(--border);border-radius:12px;margin:10px 0;padding:0 16px}
details[open]{padding-bottom:14px}summary{cursor:pointer;padding:14px 0;font-weight:700}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#1c2633;color:var(--muted);font-size:11px;margin:2px 4px 2px 0}
code{background:#0a0e13;border:1px solid var(--border);padding:2px 5px;border-radius:6px;font-size:12px;word-break:break-all}
ul.ev{margin:6px 0 0;padding-left:18px;color:var(--muted)}ul.ev li{margin:3px 0}
.finding{border-left:3px solid var(--border);padding:8px 12px;margin:8px 0;background:var(--panel2);border-radius:0 8px 8px 0}
.finding.critical{border-left-color:var(--red)}.finding.high{border-left-color:var(--orange)}.finding.medium{border-left-color:var(--yellow)}
pre.snippet{white-space:pre-wrap;background:#0a0e13;border:1px solid var(--border);padding:8px;border-radius:8px;font-size:12px;overflow:auto;max-height:220px}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:6px 20px;color:var(--muted);margin:8px 0 12px}
.kv b{color:var(--text);font-weight:600}
footer{color:var(--muted);border-top:1px solid var(--border);padding:18px 32px;font-size:12px}
.empty{color:var(--muted);padding:20px;text-align:center}

@media(max-width:800px){.wrap{padding:0 14px 30px}header{padding:20px 14px}th:nth-child(4),td:nth-child(4){display:none}}
</style>
</head>
<body>
<header>
  <h1>SBSC</h1>
  <div class="sub">Статический анализ Minecraft-модов: читы, хитбоксы и ghost-клиенты. Отчёт от {{.Generated}}.</div>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card blue"><div class="n">{{.Summary.Total}}</div><div class="l">Всего файлов</div></div>
    <div class="card green"><div class="n">{{.Summary.Clean}}</div><div class="l">Чисто</div></div>
    <div class="card yellow"><div class="n">{{.Summary.Possible}}</div><div class="l">Возможны читы</div></div>
    <div class="card orange"><div class="n">{{.Summary.Suspicious}}</div><div class="l">Подозрительно</div></div>
    <div class="card red"><div class="n">{{.Summary.Cheat}}</div><div class="l">Чит-клиенты</div></div>
    <div class="card"><div class="n">{{.Summary.Errors}}</div><div class="l">Ошибки</div></div>
  </div>

  <h2>Результаты</h2>
  {{if .Rows}}
  <table>
    <thead><tr><th>#</th><th>Файл</th><th>Вердикт</th><th>Риск</th><th>Категории</th><th>Модули</th><th>Тип</th><th>Размер</th></tr></thead>
    <tbody>
    {{range .Rows}}
      <tr class="{{riskClass .Risk}}">
        <td>{{.Index}}</td>
        <td><b>{{.Name}}</b><div class="path">{{.Path}}</div></td>
        <td><span class="verdict {{riskClass .Risk}}">{{.Verdict}}</span></td>
        <td><div class="bar"><span style="width:{{.Risk}}%"></span></div>{{.Risk}}/100<br><span class="path">уверенность {{.Confidence}}%</span></td>
        <td>{{if .Categories}}{{.Categories}}{{else}}—{{end}}</td>
        <td>{{if .Modules}}{{.Modules}}{{else}}—{{end}}</td>
        <td>{{.Kind}}</td>
        <td>{{.Size}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}<div class="empty">Нет результатов.</div>{{end}}

  <h2>Детали</h2>
  {{range .Rows}}
  <details>
    <summary>{{.Name}} — {{.Verdict}} · риск {{.Risk}}/100 · {{.Size}}</summary>
    <div class="kv">
      <div>Путь: <b>{{.Path}}</b></div>
      <div>SHA-256: <b><code>{{.Hash}}</code></b></div>
      <div>Тип: <b>{{.Kind}}</b></div>
      <div>Minecraft: <b>{{if .MCVersion}}{{.MCVersion}}{{else}}—{{end}}</b></div>
      <div>Загрузчик: <b>{{if .Loader}}{{.Loader}}{{else}}—{{end}}</b></div>
      <div>Классов: <b>{{.ClassCount}}</b></div>
      <div>Время: <b>{{.Duration}}</b></div>
      <div>Код: <b>{{.CodeScore}}/100</b></div>
      <div>Контекст: <b>{{.ContextScore}}/100</b></div>
      <div>Доказательство: <b>{{proof .Proof}}</b></div>
      <div>Уверенность: <b>{{.Confidence}}%</b></div>
    </div>
    {{if .Error}}<div class="finding critical"><b>Ошибка:</b> {{.Error}}</div>{{end}}
    {{if .Notes}}<div><b>Заметки:</b><ul class="ev">{{range .Notes}}<li>{{.}}</li>{{end}}</ul></div>{{end}}
    {{if .Categories}}<div style="margin:10px 0"><b>Категории:</b> {{.Categories}}</div>{{end}}
    {{if .Decompiled}}<div style="margin:10px 0">Исходники: <code>{{.Decompiled}}</code></div>{{end}}

    {{if .ModuleList}}
    <h4>Обнаруженные модули ({{len .ModuleList}})</h4>
    <ul class="ev">
    {{range .ModuleList}}
      <li><b>{{.Name}}</b> <span class="badge">{{cat .Category}}</span> <span class="badge">вес {{.Weight}}</span>{{if .QoL}} <span class="badge">QoL</span>{{end}} — {{.NameRU}}{{if .Evidence}}<br><code>{{join .Evidence "; "}}</code>{{end}}</li>
    {{end}}
    </ul>
    {{end}}

    {{if .Findings}}
    <h4>Находки ({{len .Findings}})</h4>
    {{range .Findings}}
      <div class="finding {{riskClass .Weight}}">
        <b>{{.Title}}</b> <span class="badge">{{cat .Category}}</span> <span class="badge">{{sev .Severity}}</span> <span class="badge">вес {{.Weight}}</span>
        {{if .File}}<div class="path">{{.File}}:{{.Line}}</div>{{end}}
        {{if .Description}}<div>{{.Description}}</div>{{end}}
        {{if .Snippet}}<pre class="snippet">{{.Snippet}}</pre>{{end}}
        {{if .Evidence}}<ul class="ev">{{range .Evidence}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}
      </div>
    {{end}}
    {{end}}

    {{if .Natives}}
    <h4>Нативные библиотеки ({{len .Natives}})</h4>
    {{range .Natives}}
      <div class="finding {{riskClass .Risk}}">
        <b>{{.Name}}</b> <span class="badge">{{.Verdict}}</span> <span class="badge">риск {{.Risk}}</span>
        <div class="path">{{.Machine}} · {{.Size}} байт · подпись: {{if .Signed}}да{{else}}нет{{end}} · энтропия {{printf "%.2f" .Entropy}}</div>
        {{if .Notes}}<ul class="ev">{{range .Notes}}<li>{{.}}</li>{{end}}</ul>{{end}}
      </div>
    {{end}}
    {{end}}
  </details>
  {{end}}

  <footer>
    SBSC {{.Version}} · правила: модули, известные читы, поведенческие эвристики, PE-анализ.<br>
    Отчёт носит рекомендательный характер: проверяйте доказательства вручную, особенно для pseudo-модов.
  </footer>
</div>
</body>
</html>`
