#!/usr/bin/env python3
"""kiss-collector web UI - live tail with AX.25 decoding, search/filter,
per-band stats, and a from/to-datetime PCAP exporter. Logic lives in kisslib."""

import os
import struct
import datetime as dt

from flask import Flask, request, jsonify, Response, render_template_string

import kisslib

app = Flask(__name__)


@app.route("/api/meta")
def api_meta():
    return jsonify(kisslib.meta())


@app.route("/api/frames")
def api_frames():
    limit = min(int(request.args.get("limit", 200)), 2000)
    order = "ASC" if request.args.get("since_ts") else "DESC"
    return jsonify(kisslib.search(request.args, limit=limit, order=order))


@app.route("/api/stats")
def api_stats():
    return jsonify(kisslib.stats(request.args))


@app.route("/api/params")
def api_params():
    limit = min(int(request.args.get("limit", 500)), 5000)
    full = kisslib.params(request.args, limit=5000)
    return jsonify({"effective": kisslib.effective_from(full),
                    "history": full[:limit]})


@app.route("/export.pcap")
def export_pcap():
    # PCAP: LINKTYPE_AX25 (3), magic a1b2c3d4, little-endian
    # (matches M0LTE/Ax25Mqtt2pcap). Real packets only: DataFrame / AckMode.
    args = request.args
    ftypes = [args.get("frame_type")] if args.get("frame_type") \
        else ["DataFrameKissCmd", "AckModeKissCmd"]
    callsign = args.get("callsign", "").strip()
    q = args.get("q", "").strip()

    def gen():
        yield struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 3)
        rows = kisslib.query_frames(args, limit=1000000, order="ASC")
        for host, r in rows:
            (_id, ts_unix, _u, _b, _dir, _p, frame_type, payload,
             _tt, _td) = r
            if frame_type not in ftypes:
                continue
            payload = bytes(payload or b"")
            if (callsign or q) and not kisslib.matches_text(
                    kisslib.row_to_dict(host, r), callsign, q):
                continue
            sec = int(ts_unix)
            usec = int(round((ts_unix - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            yield struct.pack("<IIII", sec, usec, len(payload), len(payload)) + payload

    stamp = dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return Response(gen(), mimetype="application/vnd.tcpdump.pcap",
                    headers={"Content-Disposition":
                             "attachment; filename=ax25-capture-%s.pcap" % stamp})


@app.route("/")
def index():
    return render_template_string(PAGE)


PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>KISS / AX.25 traffic</title>
<style>
 :root{color-scheme:dark}
 body{font:13px/1.4 system-ui,sans-serif;margin:0;background:#11141a;color:#dfe3ea;height:100vh;display:flex;flex-direction:column;overflow:hidden}
 header,.ex,#bar{flex:none}
 header{padding:8px 12px;background:#171b22;border-bottom:1px solid #2a2f3a;
        display:flex;flex-wrap:wrap;gap:8px;align-items:center}
 h1{font-size:15px;margin:0 12px 0 0;font-weight:600}
 input,select,button{background:#0d0f14;color:#dfe3ea;border:1px solid #2a2f3a;
        border-radius:5px;padding:4px 7px;font-size:12px}
 button{cursor:pointer;background:#1f6feb;border-color:#1f6feb}
 button.sec{background:#0d0f14;border-color:#2a2f3a}
 label{font-size:11px;color:#9aa4b2;margin-right:3px}
 .grp{display:flex;align-items:center;gap:3px}
 table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
 th,td{padding:3px 8px;border-bottom:1px solid #20242d;text-align:left;white-space:nowrap}
 th{position:sticky;top:0;background:#171b22;font-size:11px;color:#9aa4b2;z-index:1}
 tr:hover td{background:#1a1f28}
 .call{font-weight:600}
 .from{color:#6fd08c}.to{color:#f0a868}.via{color:#8a93a3}
 .dir.RX{color:#6fd08c}.dir.TX{color:#f0a868;font-weight:600}
 tbody tr{cursor:pointer}
 tr.det td{white-space:normal;background:#0d0f14;color:#aab3c2;padding:6px 12px;word-break:break-all}
 tr.det div{margin:2px 0}
 #statspanel h2{font-size:14px;margin:14px 0 6px}#statspanel h3{font-size:12px;margin:0 0 4px;color:#9aa4b2}
 .mono{font-family:ui-monospace,monospace;color:#8a93a3}
 .pill{font-size:10px;padding:1px 6px;border-radius:9px;background:#222835;color:#aab3c2}
 .new{animation:fl 1.2s ease-out}@keyframes fl{from{background:#1f6feb55}to{background:transparent}}
 #wrap{flex:1;min-height:0;overflow:auto}
 #statspanel,#paramspanel{flex:1;min-height:0;overflow:auto;padding:0 12px 16px}
 #paramspanel h2{font-size:14px;margin:14px 0 6px}
 #bar{padding:5px 12px;font-size:11px;color:#9aa4b2;background:#11141a;border-bottom:1px solid #20242d}
 .ex{padding:8px 12px;background:#171b22;border-bottom:1px solid #2a2f3a;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
</style></head><body>
<header>
 <h1>KISS / AX.25 traffic</h1>
 <div class="grp"><label>host</label><select id="host"><option value="">all</option></select></div>
 <div class="grp"><label>band</label><select id="band"><option value="">all</option></select></div>
 <div class="grp"><label>dir</label><select id="direction"><option value="">all</option></select></div>
 <div class="grp"><label>port</label><select id="port"><option value="">all</option></select></div>
 <div class="grp"><label>type</label><select id="frame_type"><option value="">all</option></select></div>
 <div class="grp"><label>call</label><input id="callsign" size="9" placeholder="GB7RDG"></div>
 <div class="grp"><label>text</label><input id="q" size="12" placeholder="search"></div>
 <button id="apply">Apply</button>
 <button id="live" class="sec">Live: on</button>
 <button id="statsbtn" class="sec">Stats</button>
 <button id="paramsbtn" class="sec">Params</button>
</header>
<div class="ex">
 <strong style="font-size:12px">PCAP export</strong>
 <label>from</label><input type="datetime-local" id="pfrom">
 <label>to</label><input type="datetime-local" id="pto">
 <button id="pexp">Download .pcap</button>
 <span class="mono">LINKTYPE_AX25 · DataFrame/AckMode · honours filters above</span>
</div>
<div id="bar">loading...</div>
<div id="wrap"><table id="t"><thead><tr>
 <th>UTC time</th><th>Host</th><th>Band</th><th>From</th><th>To</th><th>Via</th>
 <th>Dir</th><th>Type</th><th>Len</th><th>Tx time</th>
</tr></thead><tbody id="tb"></tbody></table></div>
<div id="statspanel" style="display:none"></div>
<div id="paramspanel" style="display:none"></div>
<script>
const $=id=>document.getElementById(id);
let live=true, latest=0, seen=new Set(), view='live';
const F=()=>({host:$('host').value,band:$('band').value,direction:$('direction').value,
 port:$('port').value,frame_type:$('frame_type').value,callsign:$('callsign').value.trim(),
 q:$('q').value.trim()});
const qs=o=>Object.entries(o).filter(([,v])=>v).map(([k,v])=>k+'='+encodeURIComponent(v)).join('&');
const esc=s=>(s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function dirLabel(x){return x==='fromModem'?'RX':x==='toModem'?'TX':x;}
function row(d){
 const tr=document.createElement('tr');
 const t=new Date(d.ts_unix*1000).toISOString().replace('T',' ').replace('Z','').slice(0,19);
 const tx=d.tx_time_ms!=null?(d.tx_time_ms+' ms'):'';
 const dl=dirLabel(d.direction);
 tr.innerHTML=`<td class=mono>${t}</td><td class=mono>${d.host}</td><td>${d.band}</td>
  <td class="call from">${d.from||'<span class=mono>?</span>'}</td>
  <td class="call to">${d.to||''}</td>
  <td class=via>${d.via||''}</td>
  <td class="dir ${dl}">${dl}</td>
  <td>${d.type||''}</td><td>${d.len}</td>
  <td class=mono title="${d.tx_duration_ms!=null?('airtime '+d.tx_duration_ms+' ms'):''}">${tx}</td>`;
 tr.onclick=()=>toggleDetail(tr,d);
 return tr;
}
function toggleDetail(tr,d){
 const nx=tr.nextSibling;
 if(nx&&nx.classList&&nx.classList.contains('det')){nx.remove();return;}
 const dr=document.createElement('tr');dr.className='det';
 dr.innerHTML=`<td colspan=10><div><b>info:</b> ${esc(d.info)||'<i>none</i>'}</div>
  <div><b>kiss cmd:</b> ${d.frame_type} &nbsp; <b>port:</b> ${d.port}`+
  (d.tx_duration_ms!=null?` &nbsp; <b>airtime:</b> ${d.tx_duration_ms} ms`:'')+`</div>
  <div class=mono><b>hex:</b> ${d.hex}</div></td>`;
 tr.parentNode.insertBefore(dr,tr.nextSibling);
}
function add(list,prepend){
 const tb=$('tb');
 for(const d of list){
   if(seen.has(d.uid))continue; seen.add(d.uid);
   if(d.ts_unix>latest)latest=d.ts_unix;
   const tr=row(d); if(prepend)tr.classList.add('new');
   prepend?tb.insertBefore(tr,tb.firstChild):tb.appendChild(tr);
 }
 while(tb.children.length>1500)tb.removeChild(tb.lastChild);
 $('bar').textContent=`${tb.children.length} frames shown · latest ${latest?new Date(latest*1000).toISOString().slice(11,19)+'Z':'-'} · live ${live?'on':'off'}`;
}
async function reload(){
 seen.clear();latest=0;$('tb').innerHTML='';
 const r=await fetch('/api/frames?limit=300&'+qs(F()));
 add(await r.json(),false);
}
async function poll(){
 if(view!=='live')return;
 if(live&&latest){
   const r=await fetch('/api/frames?since_ts='+latest+'&'+qs(F()));
   const j=await r.json(); if(j.length)add(j,true);
 }
}
async function meta(){
 const m=await(await fetch('/api/meta')).json();
 const fill=(id,arr)=>arr.forEach(v=>{const o=document.createElement('option');o.value=o.textContent=v;$(id).appendChild(o)});
 fill('host',m.hosts);fill('band',m.bands);fill('port',m.ports);fill('frame_type',m.frame_types);
 m.directions.forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=dirLabel(v);$('direction').appendChild(o)});
}
function fmtBytes(n){n=n||0;return n>=1048576?(n/1048576).toFixed(1)+' MB':n>=1024?(n/1024).toFixed(1)+' KB':n+' B';}
async function loadStats(){
 const s=await(await fetch('/api/stats?'+qs(F()))).json();
 const br=s.bands.map(b=>`<tr><td>${b.host}</td><td>${b.band}</td><td>${b.frames}</td><td>${fmtBytes(b.bytes)}</td><td class=mono>${b.first}</td><td class=mono>${b.last}</td></tr>`).join('')||'<tr><td colspan=6>no data</td></tr>';
 const ft=s.frame_types.map(x=>`${x.k}: <b>${x.n}</b>`).join(' &nbsp; ')||'-';
 const dr=s.directions.map(x=>`${x.k}: <b>${x.n}</b>`).join(' &nbsp; ')||'-';
 const tf=s.top_from.map(x=>`<tr><td class="call from">${x.call}</td><td>${x.n}</td></tr>`).join('')||'';
 const tt=s.top_to.map(x=>`<tr><td class="call to">${x.call}</td><td>${x.n}</td></tr>`).join('')||'';
 $('statspanel').innerHTML=`<h2>Per-band &mdash; ${s.total} frames total</h2>
  <table><thead><tr><th>Host</th><th>Band</th><th>Frames</th><th>Bytes</th><th>First heard</th><th>Last heard</th></tr></thead><tbody>${br}</tbody></table>
  <h2>Frame types</h2><div>${ft}</div><h2>Directions</h2><div>${dr}</div>
  <div style="display:flex;gap:48px;flex-wrap:wrap">
   <div><h2>Top sources (from)</h2><table><tbody>${tf}</tbody></table></div>
   <div><h2>Top destinations (to)</h2><table><tbody>${tt}</tbody></table></div></div>`;
}
async function loadParams(){
 const r=await(await fetch('/api/params?limit=500&'+qs(F()))).json();
 const eff=r.effective||{columns:[],rows:[]}, hist=r.history||[];
 const cols=eff.columns;
 const ehead='<tr><th>Host</th><th>Band</th><th>Port</th>'+cols.map(c=>`<th>${c}</th>`).join('')+'</tr>';
 const erows=eff.rows.map(row=>{
   const cells=cols.map(c=>{const v=row.params[c];return v?`<td title="set ${v.time}">${esc(v.formatted)}</td>`:'<td class=mono>·</td>';}).join('');
   return `<tr><td class=mono>${row.host}</td><td>${row.band}</td><td>${row.port}</td>${cells}</tr>`;
 }).join('')||`<tr><td colspan=${cols.length+3}>no modem parameters seen yet</td></tr>`;
 const hrows=hist.map(d=>`<tr><td class=mono>${d.time}</td><td class=mono>${d.host}</td><td>${d.band}</td><td>${d.port}</td><td class="dir ${d.direction}">${d.direction}</td><td><b>${d.param}</b></td><td>${esc(d.formatted)}</td></tr>`).join('')||'<tr><td colspan=7>no modem parameters recorded</td></tr>';
 $('paramspanel').innerHTML=`<h2>Effective parameters &mdash; per host / port</h2>
  <table><thead>${ehead}</thead><tbody>${erows}</tbody></table>
  <h2>History &mdash; sent host &rarr; modem</h2>
  <table><thead><tr><th>UTC time</th><th>Host</th><th>Band</th><th>Port</th><th>Dir</th><th>Param</th><th>Value</th></tr></thead><tbody>${hrows}</tbody></table>`;
}
function setView(v){
 view=(view===v&&v!=='live')?'live':v;
 $('wrap').style.display=view==='live'?'':'none';
 $('bar').style.display=view==='live'?'':'none';
 $('statspanel').style.display=view==='stats'?'':'none';
 $('paramspanel').style.display=view==='params'?'':'none';
 $('statsbtn').textContent=view==='stats'?'Live view':'Stats';
 $('paramsbtn').textContent=view==='params'?'Live view':'Params';
 if(view==='stats')loadStats();
 if(view==='params')loadParams();
}
$('statsbtn').onclick=()=>setView('stats');
$('paramsbtn').onclick=()=>setView('params');
$('apply').onclick=()=>{view==='stats'?loadStats():view==='params'?loadParams():reload();};
$('live').onclick=()=>{live=!live;$('live').textContent='Live: '+(live?'on':'off');};
['callsign','q'].forEach(id=>$(id).addEventListener('keydown',e=>{if(e.key==='Enter')reload();}));
$('pexp').onclick=()=>{
 const o=F();
 const toTs=s=>s?(new Date(s).getTime()/1000):'';
 if($('pfrom').value)o.from_ts=toTs($('pfrom').value);
 if($('pto').value)o.to_ts=toTs($('pto').value);
 location='/export.pcap?'+qs(o);
};
meta().then(reload);
setInterval(poll,2000);
</script></body></html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("WEB_PORT", "8080")))
