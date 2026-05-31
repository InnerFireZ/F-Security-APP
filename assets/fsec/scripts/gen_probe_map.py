#!/usr/bin/env python3
# Standalone probe map generator. Called by probe_sniffer.sh and directly by the app.
# Usage: PROBE_JSONL=<input.jsonl> PROBE_HTML=<output.html> python3 gen_probe_map.py
import sys, json, os, hashlib, colorsys
from collections import defaultdict

jsonl = os.environ.get('PROBE_JSONL') or (sys.argv[1] if len(sys.argv) > 1 else None)
outf  = os.environ.get('PROBE_HTML')  or (sys.argv[2] if len(sys.argv) > 2 else None)
if not jsonl or not outf:
    sys.exit('Usage: PROBE_JSONL=x PROBE_HTML=y gen_probe_map.py')

def load_probes(path):
    probes = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                obj = json.loads(line)
                if 'event' in obj: continue
                if not isinstance(obj.get('gps'), dict): continue
                lat = obj['gps'].get('lat'); lon = obj['gps'].get('lon')
                if lat is None or lon is None or (lat == 0 and lon == 0): continue
                probes.append(obj)
            except: pass
    return probes

def mac_color(mac):
    d = int(hashlib.md5(mac.encode()).hexdigest()[:8], 16)
    r, g, b = colorsys.hls_to_rgb((d % 360) / 360.0, 0.58, 0.80)
    return '#{:02x}{:02x}{:02x}'.format(int(r*255), int(g*255), int(b*255))

def grp_color(gid):
    r, g, b = colorsys.hls_to_rgb(((gid * 137.508) % 360) / 360.0, 0.55, 0.92)
    return '#{:02x}{:02x}{:02x}'.format(int(r*255), int(g*255), int(b*255))

def build_summary(probes):
    macs = defaultdict(lambda: {
        'count': 0, 'ssids': set(), 'vendor': '?', 'rand': False,
        'first_ts': '', 'last_ts': '', 'rssi_vals': [],
        'first_epoch': None, 'last_epoch': None, 'epochs': [],
    })
    for p in probes:
        mac = p['mac']; m = macs[mac]
        m['count'] += 1
        m['vendor'] = p.get('vendor', '?'); m['rand'] = p.get('rand', False)
        s = p.get('ssid', '')
        if s and s not in ('<wildcard>', ''): m['ssids'].add(s)
        ts = p.get('ts', '')
        if not m['first_ts'] or ts < m['first_ts']: m['first_ts'] = ts
        if ts > m['last_ts']: m['last_ts'] = ts
        rssi = p.get('rssi', -999)
        if isinstance(rssi, (int, float)) and rssi != -999: m['rssi_vals'].append(rssi)
        ep = p.get('epoch')
        if ep is not None:
            if m['first_epoch'] is None or ep < m['first_epoch']: m['first_epoch'] = ep
            if m['last_epoch']  is None or ep > m['last_epoch']:  m['last_epoch']  = ep
            m['epochs'].append(ep)
    result = {}
    for mac, m in macs.items():
        avg = round(sum(m['rssi_vals']) / len(m['rssi_vals'])) if m['rssi_vals'] else None
        fe = m['first_epoch'] or 0; le = m['last_epoch'] or 0; dur = int(le - fe)
        is_t = False
        if dur >= 600 and avg is not None and avg >= -80 and m['count'] >= 5:
            eps = sorted(m['epochs'])
            is_t = max((eps[i+1]-eps[i] for i in range(len(eps)-1)), default=0) <= 180
        result[mac] = {
            'count': m['count'], 'vendor': m['vendor'], 'rand': m['rand'],
            'ssids': sorted(m['ssids']), 'first_ts': m['first_ts'], 'last_ts': m['last_ts'],
            'avg_rssi': avg, 'color': mac_color(mac), 'duration_secs': dur,
            'is_tracker': is_t, 'corr_group': None, 'corr_color': None, 'corr_shared': [],
        }
    return result

def correlate(summary):
    macs = list(summary.keys()); parent = {m: m for m in macs}
    def find(x):
        while parent[x] != x: parent[x] = parent[parent[x]]; x = parent[x]
        return x
    def union(a, b): parent[find(a)] = find(b)
    for i, a in enumerate(macs):
        sa = set(summary[a]['ssids'])
        if len(sa) < 2: continue
        for b in macs[i+1:]:
            sb = set(summary[b]['ssids'])
            if len(sb) >= 2 and len(sa & sb) >= 2: union(a, b)
    groups = defaultdict(list)
    for m in macs: groups[find(m)].append(m)
    gid = 0
    for members in groups.values():
        if len(members) < 2: continue
        gid += 1; col = grp_color(gid)
        shared = set(summary[members[0]]['ssids'])
        for m in members[1:]: shared &= set(summary[m]['ssids'])
        for m in members:
            summary[m].update({'corr_group': gid, 'corr_color': col,
                                'corr_shared': sorted(shared), 'color': col})
    return summary

def dedup_probes(probes):
    # One dot per MAC per ~55m cell. Position = centroid of all fixes in cell (WiGLE approach).
    # Metadata (vendor/ssid/rssi shown in popup) comes from the best-RSSI probe in the cell.
    CELL = 0.0005
    groups = {}
    for p in probes:
        mac = p['mac']
        glat = int(p['gps']['lat'] / CELL)
        glon = int(p['gps']['lon'] / CELL)
        key = (mac, glat, glon)
        if key not in groups:
            groups[key] = {'members': [], 'best': p, 'best_rssi': p.get('rssi', -999)}
        groups[key]['members'].append(p)
        nr = p.get('rssi', -999); cr = groups[key]['best_rssi']
        if isinstance(nr, (int, float)) and nr != -999:
            if not isinstance(cr, (int, float)) or cr == -999 or nr > cr:
                groups[key]['best'] = p; groups[key]['best_rssi'] = nr
    result = []
    for g in groups.values():
        rep = dict(g['best'])
        lats = [m['gps']['lat'] for m in g['members']]
        lons = [m['gps']['lon'] for m in g['members']]
        rep['gps'] = {'lat': sum(lats) / len(lats), 'lon': sum(lons) / len(lons)}
        result.append(rep)
    return result

# Leaflet CDN tags kept verbatim — Flutter's _loadHtmlContent() replaces them with bundled assets.
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>Probe Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
html,body{height:100%;margin:0;padding:0;overflow:hidden}
*{box-sizing:border-box}
body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9}
#map{position:fixed;inset:0;z-index:0}
#menu-btn{position:fixed;top:10px;left:10px;z-index:2000;width:42px;height:42px;
  border-radius:50%;background:#161b22;border:1.5px solid #30363d;color:#58a6ff;
  font-size:20px;cursor:pointer;display:flex;align-items:center;justify-content:center;
  box-shadow:0 2px 10px rgba(0,0,0,.55);-webkit-tap-highlight-color:transparent}
#backdrop{position:fixed;inset:0;z-index:999;background:rgba(0,0,0,.45);
  display:none;opacity:0;transition:opacity .2s}
#backdrop.open{display:block;opacity:1}
#sidebar{position:fixed;top:0;left:0;bottom:0;z-index:1000;
  width:min(310px,92vw);display:flex;flex-direction:column;
  background:#161b22;border-right:1px solid #30363d;
  transform:translateX(-100%);transition:transform .22s ease;
  box-shadow:5px 0 24px rgba(0,0,0,.65)}
#sidebar.open{transform:translateX(0)}
#sb-head{padding:50px 12px 10px;background:#0d1117;border-bottom:1px solid #30363d}
#sb-head h1{font-size:11px;color:#58a6ff;letter-spacing:1.5px;font-weight:bold}
.stats{font-size:10px;color:#8b949e;margin-top:4px;line-height:1.7}
#sb-filter{padding:7px;border-bottom:1px solid #30363d}
#search{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;
  color:#c9d1d9;font-family:monospace;font-size:12px;border-radius:4px}
#search:focus{outline:none;border-color:#58a6ff}
#device-list{flex:1;overflow-y:auto;padding:5px;-webkit-overflow-scrolling:touch}
.dc{padding:9px 10px;margin-bottom:4px;border:1px solid #21262d;border-radius:6px;cursor:pointer;
  -webkit-tap-highlight-color:transparent;transition:background .1s}
.dc.active{background:#1f2937;border-color:#58a6ff}
.dc.tc{border-color:#ff4444}
.dc-mac{font-weight:bold;display:flex;align-items:center;gap:5px;flex-wrap:wrap;
  font-size:11px;word-break:break-all}
.dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;border:2px solid}
.badge{padding:1px 4px;border-radius:3px;font-size:9px;white-space:nowrap;
  background:#21262d;border:1px solid}
.b-r{color:#f0883e;border-color:#f0883e}
.b-t{color:#ff4444;border-color:#ff4444}
.b-g{color:#bc8cff;border-color:#bc8cff}
.dc-meta{color:#8b949e;margin-top:3px;font-size:10px}
.dc-ss{color:#58a6ff;margin-top:2px;font-size:10px;word-break:break-all}
.no-r{color:#8b949e;font-size:11px;padding:12px;text-align:center}
#ctrl{position:fixed;bottom:18px;right:10px;z-index:1000;display:flex;flex-direction:column;gap:6px}
.cb{background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:8px 12px;
  border-radius:4px;font-size:11px;cursor:pointer;font-family:monospace;
  -webkit-tap-highlight-color:transparent}
.cb.on{border-color:#58a6ff;color:#58a6ff}
#st{position:fixed;bottom:18px;left:10px;z-index:1000;
  background:rgba(13,17,23,.88);border:1px solid #30363d;
  padding:5px 9px;border-radius:4px;font-size:10px;color:#8b949e;pointer-events:none}
#st span{color:#c9d1d9}
.leaflet-popup-content-wrapper{background:#161b22;color:#c9d1d9;
  border:1px solid #30363d;border-radius:6px;font-family:monospace;
  font-size:11px;box-shadow:0 4px 16px rgba(0,0,0,.55);min-width:200px;max-width:260px}
.leaflet-popup-tip{background:#161b22}
.leaflet-popup-close-button{color:#8b949e!important;font-size:18px!important;
  top:6px!important;right:8px!important}
.pm{font-size:12px;font-weight:bold;margin-bottom:7px;word-break:break-all}
.pr{display:flex;justify-content:space-between;gap:8px;margin:2px 0;font-size:11px}
.pl{color:#8b949e}
.pss{margin-top:7px;color:#58a6ff;border-top:1px solid #30363d;padding-top:6px;
  font-size:10px;word-break:break-all}
@keyframes tp{0%{box-shadow:0 0 0 0 rgba(255,68,68,.7)}
  70%{box-shadow:0 0 0 9px rgba(255,68,68,0)}100%{box-shadow:0 0 0 0 rgba(255,68,68,0)}}
.ti{animation:tp 1.5s infinite;border-radius:50%}
.leaflet-control-zoom a{background:#161b22!important;color:#58a6ff!important;
  border-color:#30363d!important;width:36px!important;height:36px!important;
  line-height:36px!important;font-size:18px!important}
.leaflet-control-attribution{background:rgba(13,17,23,.7)!important;
  color:#6e7681!important;font-size:9px}
@keyframes mlPulse{0%{transform:scale(1);opacity:.55}65%{transform:scale(3.2);opacity:0}100%{transform:scale(3.2);opacity:0}}
.ml-ring{border-radius:50%;background:rgba(66,133,244,.35);animation:mlPulse 2.4s ease-out infinite;pointer-events:none}
#loc-btn{position:fixed;bottom:116px;right:10px;z-index:1001;width:38px;height:38px;
  border-radius:50%;background:#161b22;border:1.5px solid #30363d;color:#8b949e;
  font-size:17px;cursor:pointer;display:flex;align-items:center;justify-content:center;
  box-shadow:0 2px 10px rgba(0,0,0,.55);-webkit-tap-highlight-color:transparent;
  transition:border-color .2s,color .2s}
#loc-btn.follow{border-color:#4285f4;color:#4285f4}
#loc-btn svg{pointer-events:none}
#ssid-target-wrap{padding:7px;border-bottom:1px solid #30363d}
#ssid-target-wrap label{font-size:9px;color:#8b949e;letter-spacing:1px;display:block;margin-bottom:4px}
#ssid-target-row{display:flex;gap:5px}
#ssid-input{flex:1;padding:7px 9px;background:#0d1117;border:1px solid #30363d;
  color:#c9d1d9;font-family:monospace;font-size:12px;border-radius:4px;min-width:0}
#ssid-input:focus{outline:none;border-color:#f0883e}
#ssid-set-btn{padding:7px 10px;background:#0d1117;border:1px solid #30363d;color:#f0883e;
  font-family:monospace;font-size:11px;border-radius:4px;cursor:pointer;white-space:nowrap;
  -webkit-tap-highlight-color:transparent}
#ssid-set-btn:active{background:#21262d}
#ssid-active-bar{display:none;padding:5px 7px;background:rgba(240,136,62,.12);
  border-bottom:1px solid rgba(240,136,62,.35);align-items:center;gap:5px}
#ssid-active-bar span{flex:1;font-size:10px;color:#f0883e;word-break:break-all}
#ssid-clear-btn{background:none;border:none;color:#f0883e;font-size:14px;cursor:pointer;
  padding:0 2px;line-height:1;-webkit-tap-highlight-color:transparent}
#ssid-map-badge{position:fixed;top:10px;left:62px;z-index:1500;
  background:rgba(240,136,62,.9);color:#0d1117;font-family:monospace;
  font-size:10px;font-weight:bold;padding:4px 8px;border-radius:12px;
  display:none;letter-spacing:.5px;pointer-events:none;
  box-shadow:0 2px 8px rgba(0,0,0,.5)}
</style>
</head>
<body>
<div id="map"></div>
<div id="backdrop" onclick="closeSB()"></div>
<button id="menu-btn" onclick="toggleSB()">&#9776;</button>
<button id="loc-btn" title="My location" onclick="toggleFollow()"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg></button>
<div id="ssid-map-badge"></div>
<div id="sidebar">
  <div id="sb-head">
    <h1>&#9678; PROBE SNIFFER MAP</h1>
    <div class="stats">
      <b id="stt">__TOTAL__</b> probes &nbsp;|&nbsp; <b id="stc">__CLIENTS__</b> clients &nbsp;|&nbsp; <b id="str">__RAND__</b> rand MAC
    </div>
    <div class="stats" style="color:#6e7681" id="sts">__SOURCE__</div>
  </div>
  <div id="sb-filter">
    <input id="search" type="text"
           placeholder="MAC / vendor / SSID / tracker / grp N"
           oninput="filt()"/>
  </div>
  <div id="ssid-target-wrap">
    <label>&#9654; TARGET SSID FILTER</label>
    <div id="ssid-target-row">
      <input id="ssid-input" type="text" placeholder="e.g. HomeNetwork"
             onkeydown="if(event.key==='Enter')setTargetSSID()"/>
      <button id="ssid-set-btn" onclick="setTargetSSID()">Hunt</button>
    </div>
  </div>
  <div id="ssid-active-bar">
    <span id="ssid-active-label"></span>
    <button id="ssid-clear-btn" onclick="clearTargetSSID()" title="Clear filter">&#10005;</button>
  </div>
  <div id="device-list"></div>
</div>
<div id="st">Showing <span id="vc">__TOTAL__</span> probes</div>
<div id="ctrl">
  <button class="cb" onclick="resetV()">&#8635; All</button>
  <button class="cb" id="sb2" onclick="toggleSat()">&#9732; Sat</button>
</div>
<script>
const PROBES=__PROBES__;
const SUMMARY=__SUMMARY__;
const map=L.map('map',{zoomControl:false,tap:true,tapTolerance:15})
           .setView([__CENTER_LAT__,__CENTER_LON__],15);
L.control.zoom({position:'bottomright'}).addTo(map);
const osmL=L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
  {attribution:'&copy; OSM &copy; CARTO',subdomains:'abcd',maxZoom:20});
const satL=L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
  {attribution:'&copy; Esri',maxZoom:19});
osmL.addTo(map);let isSat=false;
function mkIcon(col,rand,isTrk,corr){
  const s=isTrk?14:11,fill=rand?'none':col,sc=isTrk?'#ff4444':col,sw=isTrk?3.5:2.5;
  const da=corr?'stroke-dasharray="4,2"':'';
  const ir=isTrk?`<circle cx="${s}" cy="${s}" r="${Math.max(s-5,2)}" fill="none" stroke="#ff000088" stroke-width="1.5"/>`:'';
  return L.divIcon({
    html:`<svg xmlns="http://www.w3.org/2000/svg" width="${s*2}" height="${s*2}"><circle cx="${s}" cy="${s}" r="${s-2}" fill="${fill}" stroke="${sc}" stroke-width="${sw}" ${da} opacity=".9"/>${ir}</svg>`,
    className:isTrk?'ti':'',iconSize:[s*2,s*2],iconAnchor:[s,s],popupAnchor:[0,-s-2]
  });
}
function rc(v){return v>-60?'#ff4444':v>-75?'#f0883e':'#3fb950'}
function fd(s){if(s<60)return s+'s';const m=Math.floor(s/60),r=s%60;return m+'m'+(r?r+'s':'')}
const lg=L.layerGroup().addTo(map),bm={},allLL=[];
let aC=null,_targetSSID=null;
function setTargetSSID(){
  const v=document.getElementById('ssid-input').value.trim();
  if(!v)return;
  _targetSSID=v.toLowerCase();
  const bar=document.getElementById('ssid-active-bar');
  document.getElementById('ssid-active-label').textContent='Hunting: '+v;
  bar.style.display='flex';
  const badge=document.getElementById('ssid-map-badge');
  badge.textContent='SSID: '+v; badge.style.display='block';
  filt(); closeSB();
}
function clearTargetSSID(){
  _targetSSID=null;
  document.getElementById('ssid-input').value='';
  document.getElementById('ssid-active-bar').style.display='none';
  document.getElementById('ssid-map-badge').style.display='none';
  filt();
}
const _placed=new Set(),MCELL=0.0005;
function _am(p,s){
  const mk=L.marker([p.lat,p.lon],{icon:mkIcon(p.color,p.rand,s.is_tracker,s.corr_group!==null)});
  mk._origLL=[p.lat,p.lon];
  const rs=(p.rssi&&p.rssi!==-999)?`<span style="color:${rc(p.rssi)}">${p.rssi} dB</span>`:'?';
  const tRow=s.is_tracker?`<div class="pr"><span class="pl" style="color:#ff4444">&#9888; TRACKER</span><span style="color:#ff4444">${fd(s.duration_secs)}</span></div>`:'';
  const cRow=s.corr_group!==null?`<div class="pr"><span class="pl">Corr grp</span><span style="color:${s.corr_color}">#${s.corr_group} &mdash; ${s.corr_shared.join(', ')}</span></div>`:'';
  const ssAll=s.ssids.length?s.ssids.join(', '):'&lt;wildcard&gt;';
  mk.bindPopup(`<div class="pm" style="color:${p.color}">${p.mac}</div>
    <div class="pr"><span class="pl">Vendor</span><span>${p.vendor}</span></div>
    <div class="pr"><span class="pl">SSID</span><span>${p.ssid||'&lt;wc&gt;'}</span></div>
    <div class="pr"><span class="pl">RSSI</span>${rs}</div>
    <div class="pr"><span class="pl">Time</span><span>${p.ts}</span></div>
    ${tRow}${cRow}${s.ssids.length>1?`<div class="pss"><b>All SSIDs (${s.ssids.length}):</b><br>${ssAll}</div>`:''}`);
  mk._mac=p.mac;if(!bm[p.mac])bm[p.mac]=[];
  bm[p.mac].push(mk);lg.addLayer(mk);allLL.push([p.lat,p.lon]);
  _placed.add(`${p.mac}:${Math.floor(p.lat/MCELL)}:${Math.floor(p.lon/MCELL)}`);
}
function updateMap(np,ns,st){
  let added=0;
  np.forEach(p=>{
    if(!ns[p.mac])return;
    const key=`${p.mac}:${Math.floor(p.lat/MCELL)}:${Math.floor(p.lon/MCELL)}`;
    if(!_placed.has(key)){_am(p,ns[p.mac]);added++;}
  });
  for(const k in SUMMARY)delete SUMMARY[k];Object.assign(SUMMARY,ns);
  const g=id=>document.getElementById(id);
  document.getElementById('vc').textContent=np.length;
  if(g('stt'))g('stt').textContent=st.total;
  if(g('stc'))g('stc').textContent=st.clients;
  if(g('str'))g('str').textContent=st.rand;
  if(g('sts'))g('sts').textContent=st.source;
  if(added>0){filt();setTimeout(applyJitter,50);}
}
PROBES.forEach(p=>_am(p,SUMMARY[p.mac]));
const dl=document.getElementById('device-list');
function renderCards(macs){
  dl.innerHTML='';
  if(!macs.length){dl.innerHTML='<div class="no-r">No results</div>';return}
  macs.sort((a,b)=>{
    const ta=SUMMARY[a].is_tracker?1:0,tb=SUMMARY[b].is_tracker?1:0;
    return ta!==tb?tb-ta:SUMMARY[b].count-SUMMARY[a].count;
  });
  macs.forEach(mac=>{
    const s=SUMMARY[mac];const card=document.createElement('div');
    card.className='dc'+(s.is_tracker?' tc':'');card.dataset.mac=mac;
    const ds=s.rand?`background:transparent;border-color:${s.color}`:`background:${s.color};border-color:${s.color}`;
    const de=s.corr_group!==null?`;outline:2px dashed ${s.corr_color};outline-offset:2px`:'';
    card.innerHTML=`<div class="dc-mac"><span class="dot" style="${ds}${de}"></span>${mac}`
      +(s.rand?'<span class="badge b-r">RAND</span>':'')
      +(s.is_tracker?`<span class="badge b-t">&#9888; ${fd(s.duration_secs)}</span>`:'')
      +(s.corr_group!==null?`<span class="badge b-g">GRP${s.corr_group}</span>`:'')+`</div>`
      +`<div class="dc-meta">${s.vendor} | ${s.count} probes`+(s.avg_rssi!==null?' | avg '+s.avg_rssi+' dB':'')+`</div>`
      +(s.ssids.length?`<div class="dc-ss">${s.ssids.slice(0,3).join(', ')}${s.ssids.length>3?'…':''}</div>`:'');
    card.addEventListener('click',()=>{focusDev(mac,card);closeSB()});
    dl.appendChild(card);
  });
}
function focusDev(mac,card){
  if(aC)aC.classList.remove('active');aC=card;card.classList.add('active');
  const s=SUMMARY[mac];
  const gm=s.corr_group!==null?Object.keys(SUMMARY).filter(m=>SUMMARY[m].corr_group===s.corr_group):[mac];
  const fs=new Set(gm);const mks=[];fs.forEach(m=>{if(bm[m])mks.push(...bm[m])});
  if(mks.length)map.fitBounds(L.featureGroup(mks).getBounds().pad(0.4));
  Object.entries(bm).forEach(([m,a])=>a.forEach(mk=>mk.setOpacity(fs.has(m)?1:.12)));
}
function filt(){
  const q=document.getElementById('search').value.toLowerCase().trim();
  const macs=Object.keys(SUMMARY).filter(mac=>{
    const s=SUMMARY[mac];
    if(_targetSSID&&!s.ssids.some(ss=>ss.toLowerCase().includes(_targetSSID)))return false;
    if(!q)return true;
    if(q==='tracker')return s.is_tracker;
    if(q.startsWith('grp')){const n=parseInt(q.replace('grp','').trim());return!isNaN(n)&&s.corr_group===n}
    return mac.includes(q)||s.vendor.toLowerCase().includes(q)||s.ssids.some(ss=>ss.toLowerCase().includes(q));
  });
  renderCards(macs);
  const vis=new Set(macs);let cnt=0;
  Object.entries(bm).forEach(([mac,mks])=>{
    const sh=vis.has(mac);mks.forEach(mk=>{if(sh){lg.addLayer(mk);cnt++}else lg.removeLayer(mk)});
  });
  document.getElementById('vc').textContent=cnt;
  Object.values(bm).flat().forEach(mk=>mk.setOpacity(1));aC=null;
}
function resetV(){
  document.getElementById('search').value='';filt();
  if(allLL.length)map.fitBounds(allLL,{padding:[50,50]});
}
function toggleSat(){
  isSat=!isSat;
  isSat?(map.removeLayer(osmL),satL.addTo(map)):(map.removeLayer(satL),osmL.addTo(map));
  const b=document.getElementById('sb2');b.classList.toggle('on',isSat);
  b.textContent=isSat?'✲ Street':'✲ Sat';
}
function toggleSB(){
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('backdrop').classList.toggle('open');
}
function closeSB(){
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('backdrop').classList.remove('open');
}
function applyJitter(){
  // Sort MACs so same-location clusters always get the same angles → deterministic across sessions.
  // Use _origLL (centroid from Python) not getLatLng() so repeated calls don't compound drift.
  const CR=0.00005,JR=0.00009;
  const done=new Set(),macs=Object.keys(bm).sort();
  for(let i=0;i<macs.length;i++){
    const a=macs[i];if(done.has(a)||!bm[a].length)continue;
    const la=bm[a][0]._origLL;
    const cl=[a];
    for(let j=i+1;j<macs.length;j++){
      const b=macs[j];if(done.has(b)||!bm[b].length)continue;
      const lb=bm[b][0]._origLL;
      const dlat=la[0]-lb[0],dlng=la[1]-lb[1];
      if(dlat*dlat+dlng*dlng<CR*CR)cl.push(b);
    }
    if(cl.length>1){
      cl.forEach((m,k)=>{
        const ang=(k/cl.length)*2*Math.PI;
        const dl=Math.sin(ang)*JR,dg=Math.cos(ang)*JR;
        bm[m].forEach(mk=>{mk.setLatLng([mk._origLL[0]+dl,mk._origLL[1]+dg])});
        done.add(m);
      });
    }
  }
}
renderCards(Object.keys(SUMMARY));
if(allLL.length>1)map.fitBounds(allLL,{padding:[50,50]});
setTimeout(()=>{map.invalidateSize();applyJitter();},150);

// ── My Location ──────────────────────────────────────────────────────────────
let _myMk=null,_myAcc=null,_myPulse=null,_follow=false,_userPanned=false;
map.on('dragstart',()=>{if(_follow){_follow=false;document.getElementById('loc-btn').classList.remove('follow');}});
function updateMyLocation(lat,lon,acc){
  const ll=[lat,lon],r=Math.min(acc||20,200);
  if(!_myMk){
    _myAcc=L.circle(ll,{radius:r,color:'#4285f4',weight:1,
      fillColor:'#4285f4',fillOpacity:0.08,interactive:false}).addTo(map);
    _myPulse=L.marker(ll,{icon:L.divIcon({
      html:'<div class="ml-ring" style="width:20px;height:20px;margin:-10px 0 0 -10px"></div>',
      className:'',iconSize:[0,0],iconAnchor:[0,0]}),
      interactive:false,zIndexOffset:8998}).addTo(map);
    _myMk=L.circleMarker(ll,{radius:8,color:'#fff',weight:2.5,
      fillColor:'#4285f4',fillOpacity:1,zIndexOffset:9000,interactive:false}).addTo(map);
    // First fix: fly to location and auto-enable follow
    _follow=true;
    document.getElementById('loc-btn').classList.add('follow');
    map.flyTo(ll,17,{animate:true,duration:0.9,easeLinearity:0.4});
  } else {
    _myMk.setLatLng(ll);
    if(_myAcc){_myAcc.setLatLng(ll);_myAcc.setRadius(r);}
    if(_myPulse)_myPulse.setLatLng(ll);
    if(_follow)map.panTo(ll,{animate:true,duration:0.4,easeLinearity:0.5,noMoveStart:true});
  }
}
function toggleFollow(){
  _follow=!_follow;
  const b=document.getElementById('loc-btn');
  b.classList.toggle('follow',_follow);
  if(_follow&&_myMk)map.panTo(_myMk.getLatLng(),{animate:true,duration:0.4});
}
window._geoFresh=0;
if(navigator.geolocation){
  navigator.geolocation.watchPosition(
    p=>{window._geoFresh=Date.now();
        updateMyLocation(p.coords.latitude,p.coords.longitude,p.coords.accuracy);},
    ()=>{},
    {enableHighAccuracy:true,maximumAge:3000,timeout:20000}
  );
}
</script>
</body>
</html>"""

probes = load_probes(jsonl)
if not probes: sys.exit(1)
summary = build_summary(probes)
summary = correlate(summary)
display = dedup_probes(probes)
lats = [p['gps']['lat'] for p in display]
lons = [p['gps']['lon'] for p in display]
if not lats: sys.exit(1)
clat = sum(lats) / len(lats); clon = sum(lons) / len(lons)
js_probes = [{
    'mac':    p['mac'],    'vendor': p.get('vendor', '?'),
    'ssid':   p.get('ssid', ''), 'rssi': p.get('rssi', -999),
    'rand':   p.get('rand', False), 'ts': p.get('ts', ''),
    'lat':    p['gps']['lat'], 'lon': p['gps']['lon'],
    'color':  summary[p['mac']]['color'],
} for p in display]
rand_ct = sum(1 for m in summary.values() if m['rand'])
with open(jsonl, encoding='utf-8') as _sf:
    sess_ct = sum(1 for _l in _sf if '"event":"start"' in _l)
source_str = '{} session{} · {} GPS points'.format(
    sess_ct, 's' if sess_ct != 1 else '', len(probes))
html_out = (HTML
    .replace('__PROBES__',      json.dumps(js_probes,  separators=(',', ':')))
    .replace('__SUMMARY__',     json.dumps(summary,    separators=(',', ':')))
    .replace('__CENTER_LAT__',  f'{clat:.6f}')
    .replace('__CENTER_LON__',  f'{clon:.6f}')
    .replace('__TOTAL__',       str(len(probes)))
    .replace('__CLIENTS__',     str(len(summary)))
    .replace('__RAND__',        str(rand_ct))
    .replace('__SOURCE__',      source_str)
)
with open(outf, 'w', encoding='utf-8') as f: f.write(html_out)
live_path = os.path.join(os.path.dirname(outf), 'probe_live.json')
# Most recent GPS fix — for Dart injection as browser-geolocation fallback
_gps_probes = sorted(probes, key=lambda p: p.get('epoch', 0))
my_lat = _gps_probes[-1]['gps']['lat'] if _gps_probes else None
my_lon = _gps_probes[-1]['gps']['lon'] if _gps_probes else None
with open(live_path, 'w', encoding='utf-8') as f:
    json.dump({'probes': js_probes, 'summary': summary,
               'total': len(probes), 'clients': len(summary),
               'rand': rand_ct, 'source': source_str,
               'my_lat': my_lat, 'my_lon': my_lon}, f, separators=(',', ':'))
print(len(summary))
