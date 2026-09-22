#!/usr/bin/env python3
"""Render the protected Avant crawler control-plane dashboard."""
from __future__ import annotations

import html
import json
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


def esc(value) -> str:
    return html.escape(str(value))


def rows(items: list[dict], columns: list[tuple[str, str]]) -> str:
    if not items:
        return "<tr><td colspan='%d' class='empty'>No results in this window.</td></tr>" % len(columns)
    rendered = []
    for item in items:
        cells = []
        for key, _ in columns:
            if key == 'remove':
                cells.append(f"<td><button class='remove' onclick=\"act('remove','{esc(item.get('ip', ''))}')\">Remove</button></td>")
                continue
            if key == 'ip':
                tooltip = esc(item.get('ip_tooltip', 'Crawlerlist check unavailable'))
                cells.append(f"<td>{esc(item.get('ip', '—'))} <span class='ip-info' data-tooltip='{tooltip}'>ⓘ</span></td>")
                continue
            title = ''
            cells.append(f"<td{title}>{esc(item.get(key, '—'))}</td>")
        rendered.append('<tr>' + ''.join(cells) + '</tr>')
    return ''.join(rendered)


def panel(title: str, subtitle: str, items: list[dict], columns: list[tuple[str, str]]) -> str:
    return f"<section class='panel'><div class='panel-head'><div><h2>{esc(title)}</h2><p>{esc(subtitle)}</p></div><span class='count'>{len(items)}</span></div><div class='table-wrap'><table><thead><tr>{''.join('<th>'+esc(label)+'</th>' for _, label in columns)}</tr></thead><tbody>{rows(items, columns)}</tbody></table></div></section>"


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def main() -> None:
    if len(sys.argv) not in {3, 4}:
        raise SystemExit("usage: render_status.py LATEST OUTPUT [SUMMARY]")
    source, target = map(Path, sys.argv[1:3])
    summary_path = Path(sys.argv[3]) if len(sys.argv) == 4 else Path("/opt/scripts/crawler-guard/state/dashboard-summary.json")
    report = read_json(source, {})
    summary = read_json(summary_path, {})
    generated = datetime.now(ZoneInfo("Europe/Amsterdam")).strftime("%d %b %Y · %H:%M:%S %Z")
    mode = summary.get("mode", report.get("mode", "dry-run"))
    active = summary.get("active_temp_blocks", [])
    permanent = summary.get("permanent_blocks", [])
    nominations = summary.get("recidive_nominations", [])
    transitions = summary.get("recent_transitions", [])
    counts = summary.get("transition_counts_24h", {})
    top_urls = summary.get("top_urls_1h", report.get("top_urls_1h", []))
    patterns = report.get("pattern_alerts", [])

    tooling = summary.get("tooling_enabled", True)
    dry_run = summary.get("dry_run_enabled", False)
    mode_label = "TOOLING DISABLED" if not tooling else ("DRY-RUN ACTIVE" if dry_run else "LIVE ENFORCEMENT ACTIVE")
    controls = f"""<section class='panel'><div class='panel-head'><div><h2>Enforcement control</h2><p><strong>{mode_label}</strong> · Office-only server-side control.</p></div></div><div style='padding:16px;display:flex;gap:8px;flex-wrap:wrap'><button onclick=\"setMode('on',false)\">Enable tooling</button><button onclick=\"setMode('off',false)\">Disable tooling</button><button onclick=\"setMode('on',true)\">Enable dry-run</button><button onclick=\"setMode('on',false)\">Disable dry-run</button><input id='control-ip' placeholder='IP-adres' style='padding:10px;min-width:200px'><button onclick=\"act('urgent')\">Urgent temporary action</button><button onclick=\"act('remove')\">Remove temporary action</button><span id='control-result'></span></div></section>"""
    body = controls + "".join((
        panel("Active temporary blocks", "Lokale control-plane status; in dry-run wordt niets bij Cloudflare afgedwongen.", active, [("ip", "IP"), ("remove", "") , ("level", "Level"), ("until", "Until"), ("owner", "Owner"), ("reason", "Reason"), ("status", "Status")]),
        panel("Permanent blocks", "Alleen voorstellen in dry-run; permanente handhaving is niet automatisch ingeschakeld.", permanent, [("ip", "IP"), ("level", "Level"), ("owner", "Owner"), ("reason", "Reason"), ("status", "Status")]),
        panel("Recidivism nominations", "Nominaties die lokaal in de escalatieladder worden gevolgd.", nominations, [("ip", "IP"), ("level", "Level"), ("until", "Until"), ("owner", "Owner"), ("reason", "Reason")]),
        panel("Recent policy transitions", f"24 hours: {counts.get('temporary_started', 0)} tijdelijk gestart · {counts.get('temporary_expired', 0)} verlopen · {counts.get('permanent_proposed', 0)} permanent voorgesteld.", transitions, [("at", "Tijd"), ("description", "Transitie"), ("ip", "IP"), ("level", "Level"), ("reason", "Reason")]),
        panel("Top 10 dynamic URLs · last hour", "Rolling overzicht uit de lichte incrementele monitor.", top_urls, [("url", "URL"), ("requests", "Requests")]),
        panel("Detected patterns", "Langzame periodieke crawlers en andere detecties.", patterns, [("ip", "IP-adres"), ("reason", "Patroon"), ("avg_interval_seconds", "Gem. interval"), ("matching_intervals", "Passende intervallen"), ("unique_urls", "Unieke URLs")]),
    ))
    target.write_text(f"""<!doctype html><html lang='nl'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Avant · Crawler Security</title><style>:root{{--navy:#091d33;--blue:#0e497b;--cyan:#31d4e7;--lime:#b8dc45;--paper:#f3f6fa;--ink:#102234;--muted:#667789;--line:#dce5ed}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}}.top{{background:linear-gradient(115deg,var(--navy),var(--blue));color:#fff;padding:30px max(24px,calc((100vw - 1280px)/2));border-bottom:4px solid var(--cyan)}}.brand{{display:flex;align-items:center;gap:10px}}.mark{{width:178px;max-height:54px;object-fit:contain;object-position:left center;filter:brightness(0) invert(1)}}.eyebrow{{margin:0;color:var(--cyan);font-size:11px;font-weight:800;letter-spacing:.16em}}h1{{margin:1px 0 0;font-size:26px;letter-spacing:-.03em}}.meta{{display:flex;gap:10px;flex-wrap:wrap;margin-top:21px}}.badge{{padding:6px 10px;border:1px solid #ffffff33;border-radius:99px;background:#ffffff12;font-size:12px}}.layout{{max-width:1280px;margin:25px auto;padding:0 24px 40px}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}}.metric{{background:#fff;border-radius:12px;padding:16px;border:1px solid var(--line)}}.metric span{{color:var(--muted);font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em}}.metric strong{{display:block;font-size:27px;margin-top:4px}}.panel{{background:#fff;border:1px solid var(--line);border-radius:12px;margin:15px 0;overflow:hidden}}.panel-head{{padding:16px 18px;display:flex;justify-content:space-between;gap:15px;align-items:center;border-bottom:1px solid var(--line)}}h2{{font-size:16px;margin:0}}p{{margin:3px 0 0;color:var(--muted);font-size:13px}}.count{{background:#e9f8fb;color:#076577;padding:3px 9px;border-radius:99px;font-weight:800}}.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:600px}}th,td{{padding:10px 14px;text-align:left;border-bottom:1px solid #edf1f5;font-size:13px}}th{{background:#f8fafc;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em}}.empty{{color:var(--muted);text-align:center;padding:20px}}#events{{margin:0;padding:16px 18px;background:#081522;color:#b9e7ee;max-height:360px;overflow:auto;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}}.pulse{{display:inline-block;width:8px;height:8px;background:var(--lime);border-radius:50%;margin-right:6px;box-shadow:0 0 0 4px #b8dc4533}}.refresh{{height:4px;background:#ffffff26;position:relative;margin-top:20px;overflow:hidden;border-radius:99px}}.refresh i{{display:block;height:100%;width:100%;background:linear-gradient(90deg,var(--cyan),var(--lime));transform-origin:left center}}.refresh-label{{margin-top:7px;color:#d5e7f4;font-size:12px}}.ip-info{{position:relative;display:inline-block;color:#0e497b;font-weight:800;cursor:help}}.ip-info:hover::after{{content:attr(data-tooltip);position:absolute;z-index:20;left:50%;top:150%;transform:translateX(-50%);width:300px;padding:9px 11px;border-radius:6px;background:#091d33;color:#fff;font:12px/1.35 system-ui,sans-serif;text-align:left;box-shadow:0 5px 16px #0005}}button{{background:#0e497b;color:#fff;border:0;border-radius:6px;padding:9px 12px;cursor:pointer;font-weight:700}}button.remove{{background:#b42318;padding:6px 9px;font-size:12px}}button:hover{{filter:brightness(1.08)}}@media(max-width:900px){{.grid{{grid-template-columns:repeat(2,1fr)}}}}@media(max-width:760px){{.grid{{grid-template-columns:1fr}}.top{{padding:24px}}.layout{{padding:0 12px}}}}</style></head><body><header class='top'><div class='brand'><img class='mark' src='/cfstatus/avant-webdiensten.svg' alt='Avant Webdiensten'><div><p class='eyebrow'>AVANT · SECURITY OPERATIONS</p><h1>Digisteden Crawler Guard</h1></div></div><div class='meta'><span class='badge'><span class='pulse'></span>Local control plane active</span><span class='badge'>Mode: {esc(mode)}</span><span class='badge'>Log window: {esc(report.get('window_seconds', '?'))} seconds</span><span class='badge'>Updated: {generated}</span></div><div class='refresh'><i id='refresh-bar'></i></div><div class='refresh-label' id='refresh-label'>Next monitor refresh in 60 seconds</div></header><main class='layout'><div class='grid'><div class='metric'><span>Recidivism nominations</span><strong>{len(nominations)}</strong></div><div class='metric'><span>Temporary 403 active</span><strong>{len(active)}</strong></div><div class='metric'><span>Permanent proposals</span><strong>{len(permanent)}</strong></div><div class='metric'><span>Transitions · 24 hours</span><strong>{sum(counts.values())}</strong></div></div>{body}<section class='panel'><div class='panel-head'><div><h2>Live policy event feed</h2><p>Refreshes every 5 seconds; shows readable local control-plane decisions.</p></div><span class='count'>STREAM</span></div><pre id='events'>Eventfeed laden…</pre></section></main><script>function readable(e){{const level=e.level||'—',reason=e.reason?' · '+e.reason:'';if(e.type==='php_fpm_restart')return'PHP-FPM 8.4 herstart uitgevoerd · load '+e.load+' · actieve workers '+e.active+' · Digisteden pool '+e.digisteden_pool+'/'+e.digisteden_pool;if(e.type==='php_fpm_overload_sample')return'PHP-FPM overloadsample · load '+e.load+' · samples '+e.samples+'/3';if(e.type==='temporary_403')return'Tijdelijke 403 gepland: '+e.ip+' · niveau '+level+' · '+((e.duration_seconds||0)/60)+' min'+reason;if(e.type==='temporary_expired')return'Tijdelijke 403 verlopen: '+e.ip+' · niveau '+level;if(e.type==='permanent_block')return'Permanente blokkade voorgesteld: '+e.ip+' · niveau 4'+reason;if(e.type==='temporary_removed')return'Tijdelijke blokkade verwijderd: '+e.ip;return'Onbekende policy-transitie'}}async function poll(){{try{{const r=await fetch('/cfstatus/events?ts='+Date.now(),{{cache:'no-store'}});const t=await r.text();document.getElementById('events').textContent=t.split('\\n').filter(Boolean).slice(-150).reverse().map(line=>{{try{{const e=JSON.parse(line),at=new Date(e.at).toLocaleString('nl-NL',{{timeZone:'Europe/Amsterdam',hour:'2-digit',minute:'2-digit',second:'2-digit'}});return at+' · '+readable(e)}}catch(_){{return line}}}}).join('\\n')||'No policy events yet.'}}catch(e){{document.getElementById('events').textContent='Eventfeed niet beschikbaar: '+e}}}}async function setMode(tooling,dry_run){{const out=document.getElementById('control-result');out.textContent='Updating…';try{{const r=await fetch('/cfstatus/action/mode',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{tooling,dry_run}})}});const d=await r.json();out.textContent=d.ok?'Mode updated':'Error: '+d.error;setTimeout(()=>location.reload(),800)}}catch(e){{out.textContent='Error: '+e}}}}async function act(kind,selected){{const ip=selected||document.getElementById('control-ip').value.trim(),out=document.getElementById('control-result');if(!ip){{out.textContent='Voer een IP in';return}}out.textContent='Bezig…';try{{const r=await fetch('/cfstatus/action/'+kind,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{ip}})}});const d=await r.json();out.textContent=d.ok?'Gelukt: '+ip:'Fout: '+d.error;setTimeout(()=>location.reload(),800)}}catch(e){{out.textContent='Fout: '+e}}}}poll();setInterval(poll,5000);const refreshSeconds=60,started=Date.now();function countdown(){{const elapsed=(Date.now()-started)/1000,remaining=Math.max(0,refreshSeconds-(elapsed%refreshSeconds));document.getElementById('refresh-bar').style.transform='scaleX('+remaining/refreshSeconds+')';document.getElementById('refresh-label').textContent='Next monitor refresh in ','+Math.ceil(remaining)+' seconds'}}countdown();setInterval(countdown,250)</script></body></html>""", encoding="utf-8")


if __name__ == "__main__":
    main()
