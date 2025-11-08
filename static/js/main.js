
// static/js/main.js
// Header highlighting helper used on result + report pages

function escapeHtml(s){
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function highlightHeader(rawHeader){
  if(!rawHeader) return;
  const el = document.getElementById('rawHeader') || document.getElementById('rawReport');
  if(!el) return;
  const lines = rawHeader.split('\n');
  const highlightWords = ['spf=fail','spf=softfail','dkim=fail','dkim=none','dmarc=fail','dmarc=none','return-path','reply-to:','filename=','duplicate headers','from:'];
  const colored = lines.map(line=>{
    let l = line.toLowerCase();
    let out = escapeHtml(line);
    for (const w of highlightWords){
      if(l.includes(w)){
        return `<mark class="mark-fail">${out}</mark>`;
      }
    }
    // minor highlight for headers of interest
    if(l.startsWith('from:') || l.startsWith('return-path:') || l.startsWith('subject:')){
      return `<mark class="mark-weak">${out}</mark>`;
    }
    return out;
  });
  el.innerHTML = colored.join('\n');
}

// add small styles for marks
(function addMarkStyles(){
  const s = document.createElement('style');
  s.innerHTML = `
    mark.mark-fail{ background: rgba(255,82,82,0.12); padding:0 6px; display:block; border-left:4px solid rgba(255,82,82,0.2); margin-bottom:4px;}
    mark.mark-weak{ background: rgba(255,179,0,0.06); padding:0 6px; display:block; border-left:4px solid rgba(255,179,0,0.09); margin-bottom:4px;}
  `;
  document.head.appendChild(s);
})();
