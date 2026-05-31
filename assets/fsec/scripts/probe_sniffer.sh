#!/usr/bin/env bash
source "$(dirname "$0")/../lib.sh"

set -uo pipefail

banner "PROBE SNIFFER" "WiFi probe request capture · client profiler · burst detection · GPS"

require_tool tshark "apt install tshark"
require_tool iw     "apt install iw"

outdir="$(make_outdir)"

# ── Singleton guard ────────────────────────────────────────────────────────────
# Prevent multiple live loops writing to the same probe_map.html / probe_live.json.
_SINGLETON_PID_FILE="$(cd "$(dirname "$0")/.." && pwd)/results/.probe_pid"
if [[ -f "$_SINGLETON_PID_FILE" ]]; then
  _old_pid=$(cat "$_SINGLETON_PID_FILE" 2>/dev/null)
  if [[ -n "$_old_pid" ]] && kill -0 "$_old_pid" 2>/dev/null; then
    printf '  %s[!]%s Probe sniffer already running (PID %s).\n' "${RED}" "${RESET}" "$_old_pid"
    printf '  %s[!]%s Stop the existing session first before starting a new one.\n' "${RED}" "${RESET}"
    exit 1
  fi
  rm -f "$_SINGLETON_PID_FILE"
fi

# ── Interface selection ────────────────────────────────────────────────────────
section "WIRELESS INTERFACE"

mapfile -t _wifi < <(iw dev 2>/dev/null | awk '/Interface/{print $2}')
if [[ ${#_wifi[@]} -eq 0 ]]; then
  printf '  %s[!]%s No wireless interfaces found%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
fi

for i in "${!_wifi[@]}"; do
  printf '  %s[%02d]%s  %s\n' "${CYAN}" "$((i+1))" "${RESET}" "${_wifi[$i]}"
done

if [[ -n "${SESSION_DIR:-}" ]]; then
  IFACE="$(resolve_iface wifi)"
  CHANNELS="1,36,6,149,11,40,44,48,153,157,161,165"; DWELL="0.3"
  printf '  %s[CHAIN]%s Interface: %s  Channels: all common  Dwell: 0.3s  (pipeline auto)%s\n\n' \
    "${CYAN}" "${RESET}" "$IFACE" "${RESET}"
else
  printf '\n  %s>>%s Interface [1-%d]: ' "${CYAN}" "${RESET}" "${#_wifi[@]}"
  read -r _sel; _sel="${_sel:-1}"
  if ! [[ "$_sel" =~ ^[0-9]+$ ]] || (( _sel < 1 || _sel > ${#_wifi[@]} )); then
    printf '  %s[!]%s Invalid selection%s\n' "${RED}" "${RESET}" "${RESET}"; exit 1
  fi
  IFACE="${_wifi[$((_sel-1))]}"
  printf '\n  %s>>%s Channels (comma-sep) [1,36,6,149,11,40,44,48,153,157,161,165]: ' "${CYAN}" "${RESET}"
  read -r _ch; CHANNELS="${_ch:-1,36,6,149,11,40,44,48,153,157,161,165}"
  printf '  %s>>%s Channel dwell in seconds [0.3]: ' "${CYAN}" "${RESET}"
  read -r _dw; DWELL="${_dw:-0.3}"
fi

printf '\n  %s[SYS]%s Interface : %s%s%s\n' "${CYAN}" "${RESET}" "${GREEN}" "$IFACE" "${RESET}"
printf '  %s[SYS]%s Channels  : %s%s%s\n\n' "${CYAN}" "${RESET}" "${DIM}" "$CHANNELS" "${RESET}"

# ── Script config ─────────────────────────────────────────────────────────────
BURST_THRESHOLD=5; BURST_WINDOW=10; PERSISTENT_SECS=600

RED='\033[0;31m'; BRED='\033[1;31m'; YEL='\033[1;33m'
GRN='\033[0;32m'; CYN='\033[0;36m'; BLD='\033[1m'
DIM='\033[2m'; NC='\033[0m'

LOG_FILE="$outdir/probes_$(date +%Y%m%d_%H%M%S).jsonl"
MON_IFACE=""; ORIGINAL_MODE=""; HOP_PID=""; GPS_PID=""; _LIVE_PID=""; _LIVE_TMP=""
GPS_AVAILABLE=0; GPS_STAMPED=0; TOTAL_PROBES=0; LAST_DRAW=0; LAST_EVENT=""

CHANNEL_FILE="/tmp/probe_ch.$$"; GPS_FILE="/tmp/probe_gps.$$"
echo "?" > "$CHANNEL_FILE"
_PROBE_PID_FILE="$_SINGLETON_PID_FILE"

declare -A C_FIRST C_LAST C_RSSI_F C_RSSI_L C_CNT C_VND C_SSIDS C_RAND
declare -A C_BWS C_BWC C_BMAX C_BMAX_TS
declare -a C_ORDER

_gen_map() {
  local jsonl="$1" html="$2"
  command -v python3 &>/dev/null || return 1
  grep -q '"lat"' "$jsonl" 2>/dev/null || return 1
  PROBE_JSONL="$jsonl" PROBE_HTML="$html" \
    python3 "$(dirname "$0")/gen_probe_map.py" 2>/dev/null
  return $?
}
# ── DEAD CODE BELOW — kept only as reference, never executed ──────────────────
_gen_map_legacy_heredoc_DO_NOT_USE() {
  PROBE_JSONL="" PROBE_HTML="" python3 << 'PYEOF'
import sys, json, os, hashlib, colorsys
from collections import defaultdict

jsonl = os.environ['PROBE_JSONL']
outf  = os.environ['PROBE_HTML']

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

# HTML uses __PLACEHOLDER__ substitution to avoid any f-string / brace escaping issues.
# Leaflet CDN tags are kept verbatim so Flutter's _loadHtml() can inject bundled assets.
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
</style>
</head>
<body>
<div id="map"></div>
<div id="backdrop" onclick="closeSB()"></div>
<button id="menu-btn" onclick="toggleSB()">&#9776;</button>
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
let aC=null;
const _placed=new Set(),MCELL=0.0002; // same grid as Python dedup
function _am(p,s){
  const mk=L.marker([p.lat,p.lon],{icon:mkIcon(p.color,p.rand,s.is_tracker,s.corr_group!==null)});
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
  // Only add genuinely new dots — never touch existing markers (no flash)
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
    if(!q)return true;const s=SUMMARY[mac];
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
// Jitter MACs that are within ~5m of each other so every dot is individually tappable.
// Uses proximity detection (not exact-position) to handle GPS drift between readings.
function applyJitter(){
  const CR=0.00005,JR=0.00009;  // cluster radius ~5m, jitter radius ~9m
  const done=new Set(),macs=Object.keys(bm);
  for(let i=0;i<macs.length;i++){
    const a=macs[i];if(done.has(a)||!bm[a].length)continue;
    const la=bm[a][0].getLatLng();
    const cl=[a];
    for(let j=i+1;j<macs.length;j++){
      const b=macs[j];if(done.has(b)||!bm[b].length)continue;
      const lb=bm[b][0].getLatLng();
      const dlat=la.lat-lb.lat,dlng=la.lng-lb.lng;
      if(dlat*dlat+dlng*dlng<CR*CR)cl.push(b);
    }
    if(cl.length>1){
      cl.forEach((m,k)=>{
        const ang=(k/cl.length)*2*Math.PI;
        const dl=Math.sin(ang)*JR,dg=Math.cos(ang)*JR;
        bm[m].forEach(mk=>{const ll=mk.getLatLng();mk.setLatLng([ll.lat+dl,ll.lng+dg])});
        done.add(m);
      });
    }
  }
}
renderCards(Object.keys(SUMMARY));
if(allLL.length>1)map.fitBounds(allLL,{padding:[50,50]});
setTimeout(()=>{map.invalidateSize();applyJitter();},150);
</script>
</body>
</html>"""

def dedup_probes(probes):
    # One dot per MAC per ~22m grid cell; keep strongest RSSI within each cell
    CELL = 0.0002
    best = {}
    for p in probes:
        mac = p['mac']
        glat = int(p['gps']['lat'] / CELL)
        glon = int(p['gps']['lon'] / CELL)
        key = (mac, glat, glon)
        if key not in best:
            best[key] = p
        else:
            nr = p.get('rssi', -999); cr = best[key].get('rssi', -999)
            if isinstance(nr, (int, float)) and nr != -999:
                if not isinstance(cr, (int, float)) or cr == -999 or nr > cr:
                    best[key] = p
    return list(best.values())

probes = load_probes(jsonl)
if not probes: sys.exit(1)
summary = build_summary(probes)
summary = correlate(summary)
display = dedup_probes(probes)  # deduplicated for map display; summary keeps all data
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
with open(live_path, 'w', encoding='utf-8') as f:
    json.dump({'probes': js_probes, 'summary': summary,
               'total': len(probes), 'clients': len(summary),
               'rand': rand_ct, 'source': source_str}, f, separators=(',', ':'))
print(len(summary))
PYEOF
} # end _gen_map_legacy_heredoc_DO_NOT_USE

cleanup() {
  tput rmcup 2>/dev/null; tput cnorm 2>/dev/null; echo ""
  # Kill tracked children first, then the whole process group to catch any orphans
  [[ -n "$HOP_PID" ]] && kill "$HOP_PID" 2>/dev/null
  [[ -n "$GPS_PID" ]] && kill "$GPS_PID" 2>/dev/null
  kill -- -$$ 2>/dev/null || true
  rm -f "$CHANNEL_FILE" "$GPS_FILE" 2>/dev/null; sleep 0.3
  printf "${CYN}[*]${NC} Restoring %s to managed mode...\n" "$IFACE"
  [[ "$MON_IFACE" == *mon ]] && command -v airmon-ng &>/dev/null \
    && airmon-ng stop "$MON_IFACE" &>/dev/null || true
  ip link set "$IFACE" down 2>/dev/null; iw dev "$IFACE" set type managed 2>/dev/null
  ip link set "$IFACE" up 2>/dev/null
  command -v systemctl &>/dev/null && { systemctl restart NetworkManager 2>/dev/null &
    systemctl restart wpa_supplicant 2>/dev/null & }
  sleep 0.5
  iw dev "$IFACE" info 2>/dev/null | grep -q "type managed" \
    && printf "${GRN}[+]${NC} Managed mode restored\n" \
    || printf "${GRN}[+]${NC} Interface restored\n"
  printf '{"event":"stop","ts":"%s","total_probes":%d,"clients":%d}\n' \
    "$(date -Iseconds)" "$TOTAL_PROBES" "${#C_ORDER[@]}" >> "$LOG_FILE"
  printf "${GRN}[+]${NC} %d probes (%d GPS-stamped), %d clients | Log: %s\n" \
    "$TOTAL_PROBES" "$GPS_STAMPED" "${#C_ORDER[@]}" "$LOG_FILE"

  # Stop live map loop before final generation to avoid file race
  [[ -n "$_LIVE_PID" ]] && kill "$_LIVE_PID" 2>/dev/null; sleep 0.3
  [[ -n "$_LIVE_TMP" ]] && rm -f "$_LIVE_TMP"

  # Append session log to cumulative data file and regenerate persistent map
  local _persist_dir; _persist_dir="$(cd "$(dirname "$0")/.." && pwd)/results"
  local _persist_jsonl="$_persist_dir/probe_data.jsonl"
  local _persist_html="$_persist_dir/probe_map.html"
  cat "$LOG_FILE" >> "$_persist_jsonl"
  local _mc
  _mc=$(_gen_map "$_persist_jsonl" "$_persist_html" 2>/dev/null)
  if [[ -n "$_mc" && "$_mc" -gt 0 ]] 2>/dev/null; then
    printf "${GRN}[+]${NC} Cumulative map updated: %s (%s devices)\n" "$_persist_html" "$_mc"
  elif (( GPS_STAMPED == 0 )); then
    printf "${DIM}[~] No GPS data — map skipped (connect GPS for mapping)${NC}\n"
  fi

  rm -f "$_PROBE_PID_FILE" 2>/dev/null
  mark_done "$outdir"
  exit 0
}
trap cleanup INT TERM

setup_monitor() {
  local phy; phy=$(iw dev "$IFACE" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
  [[ -z "$phy" ]] && { printf "${RED}[!]${NC} Cannot get phy\n"; exit 1; }
  iw phy "$phy" info 2>/dev/null | grep -q "monitor" \
    || { printf "${RED}[!]${NC} Monitor not supported\n"; exit 1; }
  ORIGINAL_MODE=$(iw dev "$IFACE" info 2>/dev/null | awk '/type/{print $2}')
  if [[ "$ORIGINAL_MODE" == "monitor" ]]; then
    MON_IFACE="$IFACE"; printf "${GRN}[+]${NC} Already in monitor mode\n"
  else
    if command -v airmon-ng &>/dev/null; then
      airmon-ng check kill &>/dev/null || true
      airmon-ng start "$IFACE" &>/dev/null || true
      ip link show "${IFACE}mon" &>/dev/null && MON_IFACE="${IFACE}mon" || MON_IFACE="$IFACE"
    else
      pkill -9 wpa_supplicant 2>/dev/null || true; MON_IFACE="$IFACE"
    fi
    if ! iw dev "$MON_IFACE" info 2>/dev/null | grep -q "type monitor"; then
      ip link set "$IFACE" down
      iw dev "$IFACE" set type monitor || { printf "${RED}[!]${NC} Monitor failed\n"; exit 1; }
      ip link set "$IFACE" up; MON_IFACE="$IFACE"
    fi
  fi
  ip link set "$MON_IFACE" up 2>/dev/null || true; sleep 0.3
  iw dev "$MON_IFACE" info 2>/dev/null | grep -q "type monitor" \
    || { printf "${RED}[!]${NC} Monitor failed\n"; exit 1; }
}

channel_hop() {
  IFS=',' read -ra CHS <<< "$CHANNELS"
  while true; do
    for ch in "${CHS[@]}"; do
      echo "$ch" > "$CHANNEL_FILE"; iw dev "$MON_IFACE" set channel "$ch" 2>/dev/null; sleep "$DWELL"
    done
  done
}

_live_map_loop() {
  local _persist_dir; _persist_dir="$(cd "$(dirname "$0")/.." && pwd)/results"
  local _persist_jsonl="$_persist_dir/probe_data.jsonl"
  local _persist_html="$_persist_dir/probe_map.html"
  local _tmp; _tmp=$(mktemp /tmp/probe_live_XXXXXX.jsonl)
  _LIVE_TMP="$_tmp"
  while true; do
    sleep 5
    { [[ -f "$_persist_jsonl" ]] && cat "$_persist_jsonl"; cat "$LOG_FILE" 2>/dev/null; } > "$_tmp"
    grep -q '"lat"' "$_tmp" 2>/dev/null && _gen_map "$_tmp" "$_persist_html" >/dev/null 2>&1
  done
}

find_oui_db() {
  for p in /usr/share/ieee-data/oui.txt /usr/share/wireshark/manuf /var/lib/ieee-data/oui.txt; do
    [[ -f "$p" ]] && { echo "$p"; return; }
  done
}
OUI_DB="$(find_oui_db)"

oui_lookup() {
  local mac="${1,,}"; [[ -z "$OUI_DB" ]] && { echo "?"; return; }
  local prefix="${mac:0:8}" key="${mac:0:8}"; key="${key//:/}"
  if [[ "$OUI_DB" == *oui.txt ]]; then
    grep -i "^$key" "$OUI_DB" 2>/dev/null | head -1 | sed 's/.*)\s*//' | cut -c1-11
  else
    grep -i "^$prefix" "$OUI_DB" 2>/dev/null | head -1 | awk '{print $2}' | cut -c1-11
  fi
}

is_rand() { local b="0x${1:0:2}"; (( b & 0x02 )) && echo 1 || echo 0; }

hex_to_ascii() {
  local hc="${1//:/}"
  if [[ "$hc" =~ ^[0-9a-fA-F]+$ ]] && (( ${#hc}%2==0 && ${#hc}>=2 )); then
    local i; for (( i=0; i<${#hc}; i+=2 )); do [[ "${hc:$i:2}" == "00" ]] && { echo "$1"; return; }; done
    local d; d=$(echo "$hc" | xxd -r -p 2>/dev/null)
    [[ -n "$d" && "$d" =~ ^[[:print:]]+$ ]] && echo "$d" || echo "$1"
  else echo "$1"; fi
}

add_ssid() {
  local mac="$1" ssid="$2"; [[ -z "$ssid" ]] && return
  local ex="${C_SSIDS[$mac]:-}"
  if [[ -z "$ex" ]]; then C_SSIDS[$mac]="$ssid"
  else
    local IFS=$'\t' s found=0
    for s in $ex; do [[ "$s" == "$ssid" ]] && found=1; done
    (( found==0 )) && C_SSIDS[$mac]+=$'\t'"$ssid"
  fi
}

ssid_count() { local raw="${C_SSIDS[$1]:-}"; [[ -z "$raw" ]] && echo 0 && return; local IFS=$'\t' a=($raw); echo ${#a[@]}; }

ssid_disp() {
  local raw="${C_SSIDS[$1]:-}" max="${2:-22}"
  [[ -z "$raw" ]] && echo "<wildcard>" && return
  local j="${raw//$'\t'/, }"; (( ${#j}>max )) && echo "${j:0:$((max-1))}…" || echo "$j"
}

GPS_HOST="127.0.0.1"; GPS_PORT="10110"; GPS_METHOD=""

parse_nmea() {
  local raw="$1"; local line="${raw%%\**}"; line="${line%$'\r'}"
  [[ "$line" != \$* ]] && return
  local lat lon alt="0"
  case "$line" in
    \$G?GGA,*)
      IFS=',' read -ra f <<< "$line"; [[ "${f[6]:-0}" == "0" || -z "${f[2]}" ]] && return
      lat=$(awk -v r="${f[2]}" -v d="${f[3]}" 'BEGIN{deg=int(r/100);lat=deg+(r-deg*100)/60;if(d=="S")lat=-lat;printf "%.6f",lat}')
      lon=$(awk -v r="${f[4]}" -v d="${f[5]}" 'BEGIN{deg=int(r/100);lon=deg+(r-deg*100)/60;if(d=="W")lon=-lon;printf "%.6f",lon}')
      alt="${f[9]:-0}";;
    \$G?RMC,*)
      IFS=',' read -ra f <<< "$line"; [[ "${f[2]}" != "A" ]] && return
      lat=$(awk -v r="${f[3]}" -v d="${f[4]}" 'BEGIN{deg=int(r/100);lat=deg+(r-deg*100)/60;if(d=="S")lat=-lat;printf "%.6f",lat}')
      lon=$(awk -v r="${f[5]}" -v d="${f[6]}" 'BEGIN{deg=int(r/100);lon=deg+(r-deg*100)/60;if(d=="W")lon=-lon;printf "%.6f",lon}');;
    *) return;;
  esac
  [[ -n "$lat" && -n "$lon" && "$lat" != "0.000000" ]] && echo "${lat},${lon},${alt}" > "$GPS_FILE"
}

gps_check() {
  local data
  if command -v socat &>/dev/null; then
    data=$(timeout 7 socat -u -T6 "TCP:${GPS_HOST}:${GPS_PORT}" - 2>/dev/null | head -3)
    [[ "$data" == *'$GP'* || "$data" == *'$GN'* ]] && { GPS_METHOD="tcp-socat"; return 0; }
    data=$(timeout 4 socat -u -T3 "UDP4-RECV:${GPS_PORT},reuseaddr" - 2>/dev/null | head -3)
    [[ "$data" == *'$GP'* || "$data" == *'$GN'* ]] && { GPS_METHOD="udp-socat"; return 0; }
  fi
  if command -v nc &>/dev/null; then
    data=$(timeout 7 nc -w6 "$GPS_HOST" "$GPS_PORT" </dev/null 2>/dev/null | head -3)
    [[ "$data" == *'$GP'* || "$data" == *'$GN'* ]] && { GPS_METHOD="tcp-nc"; return 0; }
  fi
  return 1
}

gps_poll_bg() {
  case "$GPS_METHOD" in
    tcp-socat) while true; do socat -u "TCP:${GPS_HOST}:${GPS_PORT}" - 2>/dev/null; sleep 3; done;;
    tcp-nc)    while true; do nc -w60 "$GPS_HOST" "$GPS_PORT" </dev/null 2>/dev/null; sleep 3; done;;
    udp-socat) while true; do socat "UDP4-RECV:${GPS_PORT},reuseaddr" - 2>/dev/null; sleep 1; done;;
    udp-nc)    while true; do nc -u -l -p "$GPS_PORT" 2>/dev/null; done;;
  esac | while IFS= read -r line; do parse_nmea "$line"; done
}

fmt_age() {
  local d=$(( $(date +%s) - ${1%.*} ))
  (( d<60 )) && echo "${d}s" && return
  (( d<3600 )) && echo "$(( d/60 ))m" && return
  echo "$(( d/3600 ))h"
}

fmt_dur() {
  local d=$(( ${2%.*} - ${1%.*} ))
  (( d<60 )) && echo "${d}s" && return
  (( d<3600 )) && printf "%dm%ds" $(( d/60 )) $(( d%60 )) && return
  printf "%dh%dm" $(( d/3600 )) $(( (d%3600)/60 ))
}

rssi_trend() {
  [[ -z "$1" || -z "$2" || "$1" == "-999" || "$2" == "-999" ]] && echo "" && return
  local d=$(( $2 - $1 ))
  (( d>5 )) && echo "↑ approach" && return
  (( d<-5 )) && echo "↓ leaving" && return
  echo "~ static"
}

burst_update() {
  local mac="$1" ep="${2%.*}"
  local ws="${C_BWS[$mac]:-$ep}"
  if (( ep-ws>BURST_WINDOW )); then C_BWS[$mac]=$ep; C_BWC[$mac]=1
  else
    C_BWC[$mac]=$(( ${C_BWC[$mac]:-0} + 1 ))
    local mx="${C_BMAX[$mac]:-0}"
    if (( C_BWC[$mac]>mx )); then C_BMAX[$mac]="${C_BWC[$mac]}"; C_BMAX_TS[$mac]="$2"; fi
  fi
}

log_json() {
  local mac="$1" ssid="$2" rssi="${3:--999}" ep="$4"
  local ts; ts=$(date -d "@${ep%.*}" "+%Y-%m-%dT%H:%M:%S" 2>/dev/null || date "+%Y-%m-%dT%H:%M:%S")
  local rand=false; [[ "${C_RAND[$mac]}" == "1" ]] && rand=true
  local gps="null"
  if [[ -f "$GPS_FILE" ]]; then
    local lat lon alt; IFS=',' read -r lat lon alt < "$GPS_FILE"
    [[ -n "$lat" ]] && { gps="{\"lat\":${lat},\"lon\":${lon},\"alt\":${alt:-0}}"; (( GPS_STAMPED++ )); }
  fi
  printf '{"ts":"%s","epoch":%s,"mac":"%s","vendor":"%s","ssid":"%s","rssi":%s,"rand":%s,"gps":%s}\n' \
    "$ts" "${ep%.*}" "$mac" "${C_VND[$mac]:-?}" "${ssid//\"/\\\"}" "$rssi" "$rand" "$gps" >> "$LOG_FILE"
}

draw_table() {
  local now; now=$(date +%s); (( now-LAST_DRAW<1 )) && return; LAST_DRAW=$now
  local cols rows; cols=$(tput cols 2>/dev/null || echo 80); rows=$(tput lines 2>/dev/null || echo 24)
  local EL CUP; EL=$(tput el 2>/dev/null || printf '\033[K'); CUP=$(tput cup 0 0 2>/dev/null || printf '\033[H')
  local ch; ch=$(cat "$CHANNEL_FILE" 2>/dev/null || echo "?")
  local sep; sep=$(printf '─%.0s' $(seq 1 "$cols"))
  local gps_str="GPS:n/a"
  if (( GPS_AVAILABLE )) && [[ -f "$GPS_FILE" ]]; then
    local glat glon; IFS=',' read -r glat glon _ < "$GPS_FILE"
    [[ -n "$glat" ]] && gps_str="GPS:${glat:0:7},${glon:0:8} [${GPS_STAMPED}/${TOTAL_PROBES}]" \
      || gps_str="GPS:no fix"
  fi
  local -a L=()
  L+=( "${BLD}${CYN}$(printf ' PROBE SNIFFER | %-9s | ch:%-4s | clients:%-3s | probes:%-5s | %s' \
      "$MON_IFACE" "$ch" "${#C_ORDER[@]}" "$TOTAL_PROBES" "$gps_str")${NC}" )
  L+=( "${BLD}$(printf ' %-17s %-2s %-11s %-22s %6s %5s %5s' "MAC" "?" "VENDOR" "PROBED SSIDs" "RSSI" "CNT" "AGE")${NC}" )
  L+=( "${DIM}${sep:0:$cols}${NC}" )
  local max_rows=$(( rows-8 )) row=0 p_mac="" p_secs=0
  for mac in "${C_ORDER[@]}"; do
    local dur=$(( now-${C_FIRST[$mac]%.*} )); (( dur>p_secs )) && { p_secs=$dur; p_mac=$mac; }
  done
  for mac in "${C_ORDER[@]}"; do
    (( row>=max_rows )) && break
    local dur=$(( now-${C_FIRST[$mac]%.*} )) rssi="${C_RSSI_L[$mac]}"
    local cnt="${C_CNT[$mac]:-0}" rand="${C_RAND[$mac]:-0}"
    local age; age=$(fmt_age "${C_LAST[$mac]}"); local ssids; ssids=$(ssid_disp "$mac" 22)
    local rc="${NC}" sym="  "
    [[ "$mac" == "$p_mac" && $p_secs -ge $PERSISTENT_SECS ]] && { rc="${RED}"; sym=" P"; } \
      || [[ "$rand" == "1" ]] && sym="~ "
    local rssi_c="${NC}" rssi_d="${rssi:--?}"
    if [[ -n "$rssi" && "$rssi" != "-999" ]]; then
      rssi_d="${rssi}dB"
      (( rssi>-60 )) && rssi_c="${BRED}"
      (( rssi<=-60 && rssi>-75 )) && rssi_c="${YEL}"
      (( rssi<=-75 )) && rssi_c="${GRN}"
    fi
    L+=( "${rc}$(printf ' %-17s %-2s %-11s %-22s' "$mac" "$sym" "${C_VND[$mac]:-?}" "$ssids")${rssi_c}$(printf ' %6s' "$rssi_d")${rc}$(printf ' %5s %5s' "$cnt" "$age")${NC}" )
    (( row++ ))
  done
  while (( row<max_rows )); do L+=( "" ); (( row++ )); done
  L+=( "${DIM}${sep:0:$cols}${NC}" )
  if [[ -n "$p_mac" && $p_secs -ge 60 ]]; then
    local dur_str; dur_str=$(fmt_dur "${C_FIRST[$p_mac]}" "$now")
    local first_ts; first_ts=$(date -d "@${C_FIRST[$p_mac]%.*}" "+%H:%M:%S" 2>/dev/null)
    local trend; trend=$(rssi_trend "${C_RSSI_F[$p_mac]}" "${C_RSSI_L[$p_mac]}")
    local pc="${YEL}"; (( p_secs>=PERSISTENT_SECS )) && pc="${RED}"
    local hdr="${pc}${BLD} PROFILER: ${p_mac} (${C_VND[$p_mac]:-?}) — ${dur_str}${NC}"
    (( p_secs>=PERSISTENT_SECS )) && hdr+=" ${BRED}[PERSISTENT DEVICE]${NC}"
    L+=( "$hdr" )
    L+=( "${DIM}  SSIDs ($(ssid_count "$p_mac")):${NC} ${C_SSIDS[$p_mac]//$'\t'/, }" )
    L+=( "${DIM}  RSSI: ${NC}${C_RSSI_F[$p_mac]:--?}dB → ${C_RSSI_L[$p_mac]:--?}dB  ${trend:-—}   ${DIM}First: ${NC}${first_ts:-?}${NC}" )
    local bmax="${C_BMAX[$p_mac]:-0}"
    if (( bmax>=BURST_THRESHOLD )); then
      local bts; bts=$(date -d "@${C_BMAX_TS[$p_mac]%.*}" "+%H:%M:%S" 2>/dev/null)
      L+=( "${DIM}  Burst:${NC} ${YEL}${bmax} probes/${BURST_WINDOW}s${NC} ${DIM}at ${bts:-?} — aggressive scan${NC}" )
    else L+=( "${DIM}  Burst: none${NC}" ); fi
  else L+=( "${DIM} Profiler: waiting for devices tracked > 1 min...${NC}" ); L+=( "" "" "" ); fi
  L+=( "${DIM}${sep:0:$cols}${NC}" )
  L+=( " ${LAST_EVENT:-Listening for probe requests...}" )
  local out="${CUP}" i
  for i in "${!L[@]}"; do out+="${L[$i]}${EL}"$'\n'; done
  printf "%b" "$out"
}

process_probe() {
  local ep="$1" mac="$2" ssid_raw="$3" rssi="$4"
  [[ -z "$mac" ]] && return; mac="${mac,,}"
  local ssid=""; [[ -n "$ssid_raw" ]] && ssid=$(hex_to_ascii "$ssid_raw")
  if [[ -z "${C_FIRST[$mac]:-}" ]]; then
    C_ORDER+=("$mac"); C_FIRST[$mac]="$ep"; C_RSSI_F[$mac]="${rssi:--999}"
    C_RAND[$mac]=$(is_rand "$mac"); C_VND[$mac]=$(oui_lookup "$mac")
  fi
  C_LAST[$mac]="$ep"; C_RSSI_L[$mac]="${rssi:--999}"; (( C_CNT[$mac]=${C_CNT[$mac]:-0}+1 ))
  (( TOTAL_PROBES++ )); [[ -n "$ssid" ]] && add_ssid "$mac" "$ssid"
  burst_update "$mac" "$ep"; log_json "$mac" "${ssid:-<wildcard>}" "${rssi:--999}" "$ep"
  local ts_str; ts_str=$(date -d "@${ep%.*}" "+%H:%M:%S" 2>/dev/null || echo "??:??:??")
  local rsym=""; [[ "${C_RAND[$mac]}" == "1" ]] && rsym="~"
  LAST_EVENT="${ts_str}  ${rsym}${mac}  ${C_VND[$mac]:-?}  \"${ssid:-<wildcard>}\"  ${rssi:--?}dB"
}

# ── Start ─────────────────────────────────────────────────────────────────────
printf '  %s[*]%s Setting up monitor mode on %s...\n' "${CYAN}" "${RESET}" "$IFACE"
setup_monitor
printf '  %s[+]%s Monitor: %s\n' "${GREEN}" "${RESET}" "$MON_IFACE"

printf '  %s[*]%s Checking GPS (%s:%s)...\n' "${CYAN}" "${RESET}" "$GPS_HOST" "$GPS_PORT"
if gps_check; then
  GPS_AVAILABLE=1
  printf '  %s[+]%s GPS via %s — coordinates will be logged\n' "${GREEN}" "${RESET}" "$GPS_METHOD"
  gps_poll_bg & GPS_PID=$!
else
  printf '  %s[!]%s GPS not available (optional — running without)\n\n' "${YELLOW}" "${RESET}"
fi

channel_hop & HOP_PID=$!
_live_map_loop & _LIVE_PID=$!
printf '{"event":"start","ts":"%s","iface":"%s","channels":"%s","gps_enabled":%d}\n' \
  "$(date -Iseconds)" "$MON_IFACE" "$CHANNELS" "$GPS_AVAILABLE" >> "$LOG_FILE"
printf '  %s[*]%s Log: %s\n' "${CYAN}" "${RESET}" "$LOG_FILE"
printf '  %s[*]%s Press Ctrl+C to stop\n' "${CYAN}" "${RESET}"
echo $$ > "$_PROBE_PID_FILE"
sleep 1

tput smcup 2>/dev/null; tput civis 2>/dev/null; clear; draw_table

while IFS='|' read -r ep mac ssid rssi; do
  [[ -z "$mac" ]] && continue
  process_probe "$ep" "$mac" "$ssid" "$rssi"
  draw_table
done < <(tshark -i "$MON_IFACE" -l -n \
  -Y "wlan.fc.type_subtype == 0x04" \
  -T fields \
  -e frame.time_epoch -e wlan.sa -e wlan.ssid -e radiotap.dbm_antsignal \
  -E separator='|' -E occurrence=f 2>/dev/null)
