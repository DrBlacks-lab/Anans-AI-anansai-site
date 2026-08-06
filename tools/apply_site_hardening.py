from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

PATH = Path("index.html")
s = PATH.read_text(encoding="utf-8")

if "Compare recorded states" in s and "fonts.googleapis.com" not in s:
    raise SystemExit("SITE_HARDENING_ALREADY_APPLIED")

s = re.sub(r'<link rel="preconnect" href="https://fonts\.googleapis\.com">\n', "", s)
s = re.sub(r'<link rel="preconnect" href="https://fonts\.gstatic\.com" crossorigin>\n', "", s)
s = re.sub(r'<link href="https://fonts\.googleapis\.com/css2\?[^\n]+ rel="stylesheet">\n', "", s)

s = s.replace("--f-display:'Archivo',system-ui,sans-serif;", "--f-display:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif;")
s = s.replace("--f-body:'Newsreader',Georgia,serif;", "--f-body:ui-serif,Georgia,Cambria,'Times New Roman',serif;")
s = s.replace("--f-mono:'IBM Plex Mono',ui-monospace,monospace;", "--f-mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;")

s = s.replace('<p style="margin-top:1.4rem">', '<p class="post-verify">')
s = s.replace('<section class="sec" style="border-bottom:0">', '<section class="sec sec-last">')
s = s.replace('<p style="margin-top:1.5rem"><a href="mailto:hello@anansai.org">', '<p class="contact-link"><a href="mailto:hello@anansai.org">')

anchor = '.ck-step h3 .n{font-family:var(--f-mono);font-size:.7rem;color:#5E6C67;margin-right:.7rem;font-weight:400}\n'
css = '''
/* recorded-state comparison */
.compare{margin-top:2.4rem;padding-top:2.4rem;border-top:1px solid #2C3733}
.compare-head{display:flex;justify-content:space-between;align-items:flex-end;gap:1rem;flex-wrap:wrap;margin-bottom:1.2rem}
.compare-head h3{margin:0;color:#F0F3F0;font-family:var(--f-display);font-size:1.22rem}
.compare-head p{margin:0;color:#7C8A85;font-family:var(--f-mono);font-size:.68rem}
.fixture-nav{display:flex;gap:.5rem;flex-wrap:wrap;margin:0 0 1rem;padding:0;list-style:none}
.fixture-nav button{font-family:var(--f-mono);font-size:.68rem;letter-spacing:.06em;text-transform:uppercase;background:none;border:1px solid #3E4B47;color:#C9D2CD;padding:.55rem .75rem;cursor:pointer}
.fixture-nav button[aria-current="true"]{background:#C9D2CD;color:var(--screen)}
.fixture{display:block;background:var(--screen-2);border:1px solid #2C3733;padding:1.1rem;margin-top:1rem}
.fixture h4{margin:0 0 .55rem;color:#F0F3F0;font-family:var(--f-display);font-size:1.05rem}
.fixture .fixture-action{font-family:var(--f-mono);font-size:.66rem;color:#7C8A85;margin:.8rem 0 0}
html:not(.js) .fixture-nav{display:none}
html:not(.js) .fixture + .fixture{margin-top:1.3rem}
html.js .fixture{display:none}
html.js .fixture.is-on{display:block}
.post-verify{margin-top:1.4rem}
.sec-last{border-bottom:0}
.contact-link{margin-top:1.5rem}
'''
if anchor not in s:
    raise SystemExit("CSS_ANCHOR_MISSING")
s = s.replace(anchor, anchor + css)

old = '''        <div class="ck-foot">
          <button class="ck-btn" id="ck-prev" type="button">&larr; Back</button>
          <span class="ck-count" id="ck-count"></span>
          <button class="ck-btn" id="ck-next" type="button">Next &rarr;</button>
        </div>
      </div>
    </div>
  </div>
</section>'''
new = '''        <div class="ck-foot">
          <button class="ck-btn" id="ck-prev" type="button">&larr; Back</button>
          <span class="ck-count" id="ck-count"></span>
          <button class="ck-btn" id="ck-next" type="button">Next &rarr;</button>
        </div>
      </div>
    </div>

    <section class="compare" aria-labelledby="compare-h">
      <div class="compare-head">
        <h3 id="compare-h">Compare recorded states</h3>
        <p>Frozen demonstrations only · no live execution</p>
      </div>
      <ul class="fixture-nav" id="fixture-nav" aria-label="Recorded state fixtures"></ul>
      <div id="fixture-screen">
        <article class="fixture">
          <h4>Lawful completion</h4>
          <pre class="ck-panel">AUTHORITY           PRESENT
GRAPH               2 DECLARED BLOCKS
RESULT              <span class="ok">COMPLETE</span>
REPLAY              <span class="no">DENIED</span>
PRODUCTION          <span class="no">WITHHELD</span></pre>
          <p class="fixture-action">View recorded execution · inspect receipt chain</p>
        </article>
        <article class="fixture">
          <h4>Fail-closed refusal</h4>
          <pre class="ck-panel">RECEIPT CONTRACT    <span class="no">MISSING</span>
EXECUTION ENTERED   NO
OUTPUTS CREATED     0
DECISION            <span class="no">DENY_FAIL_CLOSED</span>
REFUSAL RECEIPT     ISSUED</pre>
          <p class="fixture-action">Inspect refusal · compare authority boundary</p>
        </article>
        <article class="fixture">
          <h4>Uncommissioned repair</h4>
          <pre class="ck-panel">REPAIR              <span class="wa">LOCALLY ATTESTED</span>
AUTHORITATIVE SOURCE <span class="no">UNCOMMISSIONED</span>
LIVE USE             <span class="no">PROHIBITED</span>
NEXT GATE            SOURCE-CUSTODY PREREQUISITE
PRODUCTION           <span class="no">WITHHELD</span></pre>
          <p class="fixture-action">Inspect admission state · view next lawful gate</p>
        </article>
      </div>
    </section>
  </div>
</section>'''
if old not in s:
    raise SystemExit("COCKPIT_ANCHOR_MISSING")
s = s.replace(old, new)

old_js = '''  show(0);
})();
</script>'''
new_js = '''  show(0);

  var fixtureScreen=document.getElementById('fixture-screen');
  var fixtures=[].slice.call(fixtureScreen.querySelectorAll('.fixture'));
  var fixtureNav=document.getElementById('fixture-nav');
  fixtures.forEach(function(fixture,i){
    var li=document.createElement('li'), b=document.createElement('button');
    b.type='button';
    b.textContent=fixture.querySelector('h4').textContent;
    b.addEventListener('click',function(){showFixture(i);});
    li.appendChild(b); fixtureNav.appendChild(li);
  });
  function showFixture(i){
    fixtures.forEach(function(f,j){f.classList.toggle('is-on',j===i);});
    [].slice.call(fixtureNav.querySelectorAll('button')).forEach(function(b,j){
      b.setAttribute('aria-current',j===i?'true':'false');
    });
  }
  showFixture(0);
})();
</script>'''
if old_js not in s:
    raise SystemExit("SCRIPT_ANCHOR_MISSING")
s = s.replace(old_js, new_js)

if "style=" in s:
    raise SystemExit("INLINE_STYLE_REMAINS")

style = re.search(r"<style>\n?(.*?)</style>", s, re.S)
if not style:
    raise SystemExit("STYLE_BLOCK_MISSING")
scripts = re.findall(r"<script>(.*?)</script>", s, re.S)
if len(scripts) != 2:
    raise SystemExit(f"SCRIPT_BLOCK_COUNT_{len(scripts)}")

def digest(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")

csp = (
    "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
    "form-action 'none'; img-src 'self' data:; font-src 'self'; connect-src 'none'; media-src 'none'; "
    f"style-src 'sha256-{digest(style.group(1))}'; "
    + "script-src " + " ".join(f"'sha256-{digest(script)}'" for script in scripts)
    + "; manifest-src 'self'; upgrade-insecure-requests"
)
meta = f'<meta http-equiv="Content-Security-Policy" content="{csp}">\n'
needle = '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
if needle not in s:
    raise SystemExit("VIEWPORT_ANCHOR_MISSING")
s = s.replace(needle, needle + meta, 1)

PATH.write_text(s, encoding="utf-8")
print("ANANSAI_SITE_HARDENING_APPLIED")
