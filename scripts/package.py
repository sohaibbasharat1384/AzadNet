"""Local packaging from pinned, verified runtime downloads."""
from pathlib import Path
import hashlib,json,shutil,zipfile,tarfile,io,os,time,gzip,sys

ROOT=Path(__file__).resolve().parent.parent
DIST=ROOT/'dist'
VERSION=json.loads((ROOT/'package.json').read_text())['version']
ELECTRON=json.loads((ROOT/'node_modules/electron/package.json').read_text())['version']
DIST.mkdir(exist_ok=True)

def sha(path): return hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
def app_contents(target,linux=False):
    app=target/'resources/app'
    shutil.copytree(ROOT/'desktop',app/'desktop',dirs_exist_ok=True)
    (app/'package.json').write_text(json.dumps({'name':'azadnet-desktop','version':VERSION,'main':'desktop/main.cjs','dependencies':{'yaml':'2.9.1'}}),encoding='utf8')
    shutil.copytree(ROOT/'node_modules/yaml',app/'node_modules/yaml',dirs_exist_ok=True)
    core=target/'resources/core';core.mkdir(parents=True,exist_ok=True)
    origin=ROOT/('resources/linux-core' if linux else 'resources/core')
    for file in origin.iterdir():
        if file.is_file(): shutil.copy2(file,core/file.name)
    shutil.copytree(ROOT/'resources/licenses',target/'licenses',dirs_exist_ok=True)
    for name in ('README.fa.md','THIRD_PARTY_NOTICES.md','LICENSE'):
        if (ROOT/name).exists():shutil.copy2(ROOT/name,target/name)
    shutil.copytree(ROOT/'resources/custom-core',target/'core-source',dirs_exist_ok=True,ignore=shutil.ignore_patterns('mihomo-windows-amd64.exe','mihomo-linux-amd64'))
    source=target/'source'
    source.mkdir(exist_ok=True)
    for name in ('desktop','scripts','tests'):
        shutil.copytree(ROOT/name,source/name,dirs_exist_ok=True)
    for name in ('package.json','package-lock.json','README.fa.md','THIRD_PARTY_NOTICES.md','LICENSE'):
        if(ROOT/name).exists():shutil.copy2(ROOT/name,source/name)

win=DIST/f'AzadNet-{VERSION}-windows-x64'
if win.exists():raise SystemExit(f'Refusing to overwrite existing package directory: {win}')
shutil.copytree(ROOT/'node_modules/electron/dist',win)
(win/'electron.exe').rename(win/'AzadNet.exe')
app_contents(win)
archive=DIST/f'{win.name}.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for f in sorted(win.rglob('*')):
        if f.is_file():z.write(f,f.relative_to(DIST))
print(f'Windows: {archive}',flush=True)
if '--windows-only' in sys.argv:
    (DIST/f'SHA256SUMS-{VERSION}.txt').write_text(f'{sha(archive)}  {archive.name}\n',encoding='utf8')
    raise SystemExit(0)

linuxzip=ROOT/'.tools/electron-linux.zip'
expected=next(line.split()[0] for line in (ROOT/'.tools/electron-SHASUMS256.txt').read_text().splitlines() if line.endswith(f'electron-v{ELECTRON}-linux-x64.zip'))
if sha(linuxzip)!=expected:raise SystemExit('Electron Linux SHA256 mismatch')
linux=DIST/f'AzadNet-{VERSION}-linux-x64'
if linux.exists():raise SystemExit(f'Refusing to overwrite existing package directory: {linux}')
linux.mkdir()
with zipfile.ZipFile(linuxzip) as z:
    for entry in z.infolist():
        p=Path(entry.filename)
        if p.is_absolute() or '..' in p.parts:raise ValueError('Unsafe archive path')
        z.extract(entry,linux)
(linux/'electron').rename(linux/'azadnet')
app_contents(linux,True)
(linux/'run-azadnet.sh').write_text('#!/bin/sh\ncd "$(dirname "$0")" || exit 1\nexec ./azadnet "$@"\n',encoding='utf8',newline='\n')
desktop='[Desktop Entry]\nName=AzadNet\nName[fa]=آزادنت\nComment=Persian desktop proxy and VPN client\nExec=/opt/azadnet/azadnet\nIcon=/opt/azadnet/resources/app/desktop/icon.svg\nType=Application\nCategories=Network;\nTerminal=false\n'
(linux/'azadnet.desktop').write_text(desktop,encoding='utf8',newline='\n')

def mode_for(name):
    if name.endswith('chrome-sandbox'):return 0o4755
    if Path(name).name in ('azadnet','mihomo','chrome_crashpad_handler','run-azadnet.sh'):return 0o755
    return 0o644
def add_file(tar,file,arcname):
    info=tar.gettarinfo(str(file),arcname)
    info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=0
    info.mode=0o755 if file.is_dir() else mode_for(arcname)
    if file.is_file():
        with file.open('rb') as h:tar.addfile(info,h)
    else:tar.addfile(info)

portable=DIST/f'{linux.name}.tar.gz'
with tarfile.open(portable,'w:gz',compresslevel=6) as t:
    add_file(t,linux,linux.name)
    for f in sorted(linux.rglob('*')):add_file(t,f,linux.name+'/'+f.relative_to(linux).as_posix())
print(f'Linux portable: {portable}',flush=True)

control=f'''Package: azadnet
Version: {VERSION}
Section: net
Priority: optional
Architecture: amd64
Maintainer: AzadNet local build
Depends: libgtk-3-0, libnss3, libxss1, libxtst6, libatspi2.0-0, libdrm2, libgbm1, libasound2t64 | libasound2, libx11-xcb1, libcups2t64 | libcups2
Description: Independent Persian desktop proxy client
 Reconstructed from observed InternetAzad369 Android behavior.
 Includes Mihomo and an Electron interface. TUN needs network privileges.
'''
ctrl=io.BytesIO()
with tarfile.open(fileobj=ctrl,mode='w:gz') as t:
    b=control.encode();i=tarfile.TarInfo('./control');i.size=len(b);i.mode=0o644;t.addfile(i,io.BytesIO(b))
datafile=DIST/'.deb-data.tar.gz'
with tarfile.open(datafile,'w:gz',compresslevel=6) as t:
    for f in [linux,*sorted(linux.rglob('*'))]:add_file(t,f,'./opt/azadnet'+('/'+f.relative_to(linux).as_posix() if f!=linux else ''))
    b=desktop.encode();i=tarfile.TarInfo('./usr/share/applications/azadnet.desktop');i.size=len(b);i.mode=0o644;t.addfile(i,io.BytesIO(b))
deb=DIST/f'azadnet_{VERSION}_amd64.deb'
with deb.open('wb') as f:
    f.write(b'!<arch>\n')
    def ar(name,data):
        header=f'{name+"/":<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(data):<10}`\n'.encode('ascii')
        if len(header)!=60:raise ValueError('Invalid ar header')
        f.write(header);f.write(data)
        if len(data)%2:f.write(b'\n')
    ar('debian-binary',b'2.0\n');ar('control.tar.gz',ctrl.getvalue());ar('data.tar.gz',datafile.read_bytes())
datafile.unlink()
print(f'Ubuntu Debian package: {deb}',flush=True)
outputs=[archive,portable,deb]
(DIST/'SHA256SUMS.txt').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in outputs),encoding='utf8')
