export function $(id){ return document.getElementById(id); }
export function createEl(tag, html="", cls=""){ const e=document.createElement(tag); if(html) e.innerHTML=html; if(cls) e.className=cls; return e; }

// ts may be seconds or milliseconds; be tolerant
export function tsFormat(ts){
  if(!ts) return new Date().toLocaleString();
  // if very large, assume ms
  let t = Number(ts);
  if (t > 1e12) t = Math.floor(t/1000);
  // if t looks like seconds already (e.g. 1.6e9), keep it
  return new Date(t*1000).toLocaleString();
}
