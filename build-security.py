"""Regenerate CSP hashes, hosting headers and the deployment ZIP after editing index.html.
Run with Python 3: python build-security.py
"""
from pathlib import Path
import base64,hashlib,json,re,zipfile

root=Path(__file__).resolve().parent
page=root/'index.html'
html=page.read_text(encoding='utf-8').replace('\r\n','\n')
scripts=re.findall(r'<script>([\s\S]*?)</script>',html)
assert len(scripts)==1, 'Expected exactly one application script.'
digest=base64.b64encode(hashlib.sha256(scripts[0].encode('utf-8')).digest()).decode('ascii')
policy=(f"default-src 'none'; script-src 'sha256-{digest}'; script-src-attr 'none'; "
        "style-src 'unsafe-inline'; img-src data:; font-src 'none'; connect-src 'none'; "
        "media-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; "
        "frame-src 'none'; worker-src 'none'; manifest-src 'none'")
# Preserve a readable HTML layout, including after running a formatter.
meta_pattern=r'(?m)^([ \t]*)<meta\s+http-equiv="Content-Security-Policy"\s+content="[^"]*"\s*/?>'
def policy_meta(indent):
 return (indent+'<meta\n'+indent+'  http-equiv="Content-Security-Policy"\n'
         +indent+'  content="'+policy+'"\n'+indent+'/>' )
if re.search(meta_pattern,html):
 html=re.sub(meta_pattern,lambda match:policy_meta(match.group(1)),html,count=1)
else:
 charset_pattern=r'(?m)^([ \t]*)<meta\s+charset="utf-8"\s*/?>'
 assert re.search(charset_pattern,html), 'Missing UTF-8 charset declaration.'
 html=re.sub(charset_pattern,lambda match:match.group(0)+'\n'+policy_meta(match.group(1)),html,count=1)
page.write_text(html,encoding='utf-8',newline='\n')
headers={
 'Content-Security-Policy':policy+"; frame-ancestors 'none'",
 'X-Content-Type-Options':'nosniff',
 'X-Frame-Options':'DENY',
 'Referrer-Policy':'no-referrer',
 'Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
 'Strict-Transport-Security':'max-age=31536000',
 'Cache-Control':'no-cache',
}
(root/'_headers').write_text('/*\n'+''.join(f'  {key}: {value}\n' for key,value in headers.items()),encoding='utf-8')
(root/'vercel.json').write_text(json.dumps({'$schema':'https://openapi.vercel.sh/vercel.json','headers':[{'source':'/(.*)','headers':[{'key':key,'value':value} for key,value in headers.items()]}]},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
with zipfile.ZipFile(root/'thiep-trung-thu-deploy.zip','w',zipfile.ZIP_DEFLATED) as archive:
 for name in ['index.html','_headers','vercel.json']:
  archive.write(root/name,name)
print('Generated CSP, _headers, vercel.json, and thiep-trung-thu-deploy.zip')
