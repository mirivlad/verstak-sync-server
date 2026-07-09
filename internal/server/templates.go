package server

import (
	"fmt"
	"html"
	"strings"
)

func userRegisterHTML(locale string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verstak Sync — %s</title>
<style>body{font-family:sans-serif;background:#13131f;color:#e4e4ef;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
form{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:32px;width:320px}
h1{font-size:20px;margin:0 0 20px;text-align:center}
p{text-align:center;font-size:12px;color:#666;margin-top:16px}
a{color:#6366f1}
label{display:block;font-size:12px;color:#888;margin-bottom:4px}
input{width:100%%;padding:8px 12px;border:1px solid #2a2a3c;background:#13131f;color:#e4e4ef;border-radius:6px;font-size:14px;margin-bottom:16px;box-sizing:border-box}
button{width:100%%;padding:10px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer}
button:hover{background:#4f46e5}
.hint{font-size:11px;color:#666;margin-top:-12px;margin-bottom:16px;text-align:center}
</style>
</head><body>
<form method="POST">
<h1>%s</h1>
<label>%s</label>
<input type="text" name="username" autofocus required>
<label>%s</label>
<input type="email" name="email" required>
<label>%s</label>
<input type="password" name="password" required minlength="8" maxlength="256">
<button>%s</button>
<p>%s <a href="/login">%s</a></p>
</form>
</body></html>`,
		t(locale, "server.registerTitle"),
		t(locale, "server.register"),
		t(locale, "server.username"),
		t(locale, "server.email"),
		t(locale, "server.password"),
		t(locale, "server.registerBtn"),
		t(locale, "server.alreadyHaveAccount"),
		t(locale, "server.loginBtn"),
	)
}

func userLoginHTML(locale string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verstak Sync — %s</title>
<style>body{font-family:sans-serif;background:#13131f;color:#e4e4ef;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
form{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:32px;width:320px}
h1{font-size:20px;margin:0 0 20px;text-align:center}
p{text-align:center;font-size:12px;color:#666;margin-top:16px}
a{color:#6366f1}
label{display:block;font-size:12px;color:#888;margin-bottom:4px}
input{width:100%%;padding:8px 12px;border:1px solid #2a2a3c;background:#13131f;color:#e4e4ef;border-radius:6px;font-size:14px;margin-bottom:16px;box-sizing:border-box}
button{width:100%%;padding:10px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer}
button:hover{background:#4f46e5}
.links{margin-top:16px;text-align:center;font-size:12px;color:#666;line-height:1.8}
.links a{color:#6366f1;text-decoration:none}
.links a:hover{text-decoration:underline}</style>
</head><body>
<form method="POST">
<h1>Verstak Sync</h1>
<label>%s</label>
<input type="text" name="username" autofocus required>
<label>%s</label>
<input type="password" name="password" required>
<button>%s</button>
<div class="links">
<a href="/forgot">%s</a><br>
<a href="/register">%s</a> · <a href="/admin/login">%s</a>
</div>
</form>
</body></html>`,
		t(locale, "server.loginTitle"),
		t(locale, "server.usernameOrEmail"),
		t(locale, "server.password"),
		t(locale, "server.loginBtn"),
		t(locale, "server.forgotPassword"),
		t(locale, "server.registerBtn"),
		t(locale, "server.adminLink"),
	)
}

func confirmedHTML(locale string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verstak Sync — %s</title>
<style>body{font-family:sans-serif;background:#13131f;color:#e4e4ef;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:32px;width:320px;text-align:center}
h1{font-size:20px;margin:0 0 12px;color:#34d399}
p{font-size:13px;color:#b0b0c0;margin:0 0 20px}
a{color:#6366f1;text-decoration:none}
.btn{display:inline-block;padding:10px 24px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer;text-decoration:none}
.btn:hover{background:#4f46e5}</style>
</head><body>
<div class="box">
<h1>%s</h1>
<p>%s</p>
<a href="/login" class="btn">%s</a>
</div>
</body></html>`,
		t(locale, "server.emailConfirmed"),
		t(locale, "server.emailConfirmed"),
		t(locale, "server.emailConfirmedMessage"),
		t(locale, "server.loginBtn"),
	)
}

func registrationOKHTML(locale string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verstak Sync — %s</title>
<style>body{font-family:sans-serif;background:#13131f;color:#e4e4ef;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:32px;width:360px;text-align:center}
h1{font-size:20px;margin:0 0 12px;color:#34d399}
p{font-size:13px;color:#b0b0c0;margin:0 0 6px;line-height:1.5}
a{color:#6366f1;text-decoration:none}
.btn{display:inline-block;padding:10px 24px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer;text-decoration:none;margin-top:16px}
.btn:hover{background:#4f46e5}</style>
</head><body>
<div class="box">
<h1>%s</h1>
<p>%s</p>
<p>%s</p>
<a href="/login" class="btn">%s</a>
</div>
</body></html>`,
		t(locale, "server.registerTitle"),
		t(locale, "server.registrationSuccess"),
		t(locale, "server.registrationEmailSent"),
		t(locale, "server.registrationCheckEmail"),
		t(locale, "server.loginBtn"),
	)
}

func registrationAutoHTML(locale string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verstak Sync — %s</title>
<style>body{font-family:sans-serif;background:#13131f;color:#e4e4ef;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:32px;width:360px;text-align:center}
h1{font-size:20px;margin:0 0 12px;color:#34d399}
p{font-size:13px;color:#b0b0c0;margin:0 0 6px;line-height:1.5}
a{color:#6366f1;text-decoration:none}
.btn{display:inline-block;padding:10px 24px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer;text-decoration:none;margin-top:16px}
.btn:hover{background:#4f46e5}</style>
</head><body>
<div class="box">
<h1>%s</h1>
<p>%s</p>
<a href="/login" class="btn">%s</a>
</div>
</body></html>`,
		t(locale, "server.registerTitle"),
		t(locale, "server.registrationSuccess"),
		t(locale, "server.registrationAutoMessage"),
		t(locale, "server.loginBtn"),
	)
}

func forgotPasswordHTML(locale string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>body{font-family:sans-serif;background:#13131f;color:#e4e4ef;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
form{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:32px;width:320px}
h1{font-size:18px;margin:0 0 8px;text-align:center}
p{font-size:12px;color:#888;text-align:center;margin:0 0 20px}
label{display:block;font-size:12px;color:#888;margin-bottom:4px}
input{width:100%%;padding:8px 12px;border:1px solid #2a2a3c;background:#13131f;color:#e4e4ef;border-radius:6px;font-size:14px;margin-bottom:16px;box-sizing:border-box}
button{width:100%%;padding:10px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer}
button:hover{background:#4f46e5}
.links{text-align:center;font-size:12px;color:#666;margin-top:16px}
.links a{color:#6366f1;text-decoration:none}
.links a:hover{text-decoration:underline}</style>
</head><body>
<form method="POST">
<h1>%s</h1>
<p>%s</p>
<label>%s</label>
<input type="email" name="email" autofocus required>
<button>%s</button>
<div class="links"><a href="/login">%s</a></div>
</form>
</body></html>`,
		t(locale, "server.resetPasswordTitle"),
		t(locale, "server.resetPassword"),
		t(locale, "server.resetInstruction"),
		t(locale, "server.email"),
		t(locale, "server.sendLink"),
		t(locale, "server.backToLogin"),
	)
}

func forgotSentHTML(locale string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>body{font-family:sans-serif;background:#13131f;color:#e4e4ef;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:32px;width:360px;text-align:center}
h1{font-size:18px;margin:0 0 12px;color:#34d399}
p{font-size:13px;color:#b0b0c0;margin:0 0 6px;line-height:1.5}
a{color:#6366f1;text-decoration:none}
.btn{display:inline-block;padding:10px 24px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer;text-decoration:none;margin-top:16px}
.btn:hover{background:#4f46e5}</style>
</head><body>
<div class="box">
<h1>%s</h1>
<p>%s</p>
<a href="/login" class="btn">%s</a>
</div>
</body></html>`,
		t(locale, "server.emailSentTitle"),
		t(locale, "server.emailSent"),
		t(locale, "server.emailSentMessage"),
		t(locale, "server.goHome"),
	)
}

func resetPasswordHTML(locale string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>body{font-family:sans-serif;background:#13131f;color:#e4e4ef;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
form{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:32px;width:320px}
h1{font-size:18px;margin:0 0 20px;text-align:center}
label{display:block;font-size:12px;color:#888;margin-bottom:4px}
input{width:100%%;padding:8px 12px;border:1px solid #2a2a3c;background:#13131f;color:#e4e4ef;border-radius:6px;font-size:14px;margin-bottom:16px;box-sizing:border-box}
button{width:100%%;padding:10px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer}
button:hover{background:#4f46e5}
.hint{font-size:11px;color:#666;text-align:center;margin-top:12px}</style>
</head><body>
<form method="POST">
<h1>%s</h1>
<input type="hidden" name="token" value="{TOKEN}">
<label>%s</label>
<input type="password" name="password" minlength="8" maxlength="256" required autofocus>
	<label>%s</label>
	<input type="password" name="confirm" minlength="8" maxlength="256" required>
<button style="margin-top:8px">%s</button>
</form>
</body></html>`,
		t(locale, "server.newPasswordTitle"),
		t(locale, "server.newPassword"),
		t(locale, "server.password"),
		t(locale, "server.passwordConfirm"),
		t(locale, "server.save"),
	)
}

func resetDoneHTML(locale string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verstak Sync — %s</title>
<style>body{font-family:sans-serif;background:#13131f;color:#e4e4ef;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:32px;width:360px;text-align:center}
h1{font-size:18px;margin:0 0 12px;color:#34d399}
p{font-size:13px;color:#b0b0c0;margin:0 0 6px;line-height:1.5}
.btn{display:inline-block;padding:10px 24px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer;text-decoration:none;margin-top:16px}
.btn:hover{background:#4f46e5}</style>
</head><body>
<div class="box">
<h1>%s</h1>
<p>%s</p>
<a href="/login" class="btn">%s</a>
</div>
</body></html>`,
		t(locale, "server.passwordChanged"),
		t(locale, "server.passwordChanged"),
		t(locale, "server.passwordChangedMessage"),
		t(locale, "server.loginBtn"),
	)
}

func adminDashboardHTML(locale string, deviceCount, opsCount int, smtpHost, smtpPort, smtpUser, smtpFrom, smtpSecurity, srvURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%[1]s</title>
<style>
body{font-family:sans-serif;background:#13131f;color:#e4e4ef;padding:24px;max-width:860px;margin:0 auto}
a{color:#6366f1}
h1{border-bottom:1px solid #2a2a3c;padding-bottom:12px}
h2{margin-top:24px;font-size:16px}
.stat{background:#1a1a28;border:1px solid #2a2a3c;padding:12px 16px;border-radius:8px;margin:8px 0}
table{width:100%%;border-collapse:collapse;margin-top:8px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #2a2a3c}
th{font-size:12px;color:#888;text-transform:uppercase}
.key-cell{max-width:360px;overflow:hidden;text-overflow:ellipsis;font-family:monospace;font-size:12px;color:#b0b0c0}
.btn{font-family:inherit;font-size:12px;padding:6px 12px;border-radius:6px;border:1px solid #2a2a3c;background:#1a1a28;color:#ccc;cursor:pointer;display:inline-flex;align-items:center;gap:4px}
.btn:hover{background:#222233}
.btn-primary{background:#6366f1;border-color:#6366f1;color:#fff}
.btn-primary:hover{background:#4f46e5}
.btn-danger{color:#ff6b6b;border-color:#4a2222}
.btn-danger:hover{background:#3a2222}
.copy-btn{padding:2px 8px;font-size:11px;margin-left:6px}
input{font-family:inherit;font-size:14px;padding:8px 12px;border:1px solid #2a2a3c;background:#13131f;color:#e4e4ef;border-radius:6px;margin:0;box-sizing:border-box}
input:focus{outline:none;border-color:#6366f1}
.form-row{display:flex;gap:8px;margin-bottom:8px;align-items:center}
.form-row label{font-size:12px;color:#888;min-width:80px;flex-shrink:0}
.form-row input{flex:1}
.toolbar{display:flex;gap:8px;margin:16px 0;flex-wrap:wrap}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100}
.modal{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:24px;width:420px;max-width:90vw;position:relative;max-height:80vh;overflow-y:auto}
.modal h2{margin-top:0}
.modal-close{position:absolute;top:10px;right:14px;font-size:20px;cursor:pointer;background:none;border:none;color:#888}
.modal-close:hover{color:#e4e4ef}
pre{background:#13131f;border:1px solid #2a2a3c;border-radius:8px;padding:12px;overflow-x:auto;white-space:pre-wrap}
</style>
</head><body>
<h1>Verstak Sync Server</h1>
<div style="display:flex;gap:20px;flex-wrap:wrap">
<div class="stat" style="margin:0"><strong>%[2]s</strong> <span id="dev-count">%[40]d</span></div>
<div class="stat" style="margin:0"><strong>%[3]s</strong> <span id="op-count">%[41]d</span></div>
</div>

<div class="toolbar">
<button class="btn btn-primary" onclick="openSMTP()">%[15]s</button>
<a href="/admin/users" style="text-decoration:none"><button class="btn" type="button">%[16]s</button></a>
<button class="btn" onclick="openHealth()">%[17]s</button>
</div>

<h2>%[4]s</h2>
<div id="devices"></div>
<script>
fetch('/admin/api/devices').then(r=>r.json()).then(devices=>{
  const div=document.getElementById('devices')
  if(!devices.length){div.innerHTML='<p>%[5]s</p>';return}
  div.innerHTML='<table><tr><th>%[6]s</th><th>%[7]s</th><th>%[8]s</th><th>%[9]s</th><th>%[10]s</th><th></th></tr>'+
    devices.map(d=>{
      var status=d.revoked_at?'<span style="color:#ff6b6b">%[12]s</span>':'<span style="color:#34d399">%[11]s</span>'
      var ls=d.last_seen||'\u2014'
      var revBtn=''
      if(!d.revoked_at) revBtn='<button class="btn btn-danger" onclick="revokeDevice(\''+d.id+'\')">%[13]s</button>'
      return '<tr><td>'+d.name+'</td><td>'+(d.user||'\u2014')+'</td><td>'+(d.client_version||'\u2014')+'</td><td>'+status+'</td><td>'+ls+'</td><td>'+revBtn+'</td></tr>'
    }).join('')+'</table>'
  document.getElementById('dev-count').textContent=devices.length
})
fetch('/admin/api/stats').then(r=>r.json()).then(stats=>{
  document.getElementById('op-count').textContent=stats.ops||'0'
})
function revokeDevice(id){
  if(!confirm('%[31]s'))return
  fetch('/admin/api/keys/'+id,{method:'DELETE'}).then(()=>location.reload())
}
function openSMTP(){document.getElementById('smtp-modal').style.display='flex';document.getElementById('smtp-test-result').textContent=''}
function closeSMTP(e){if(!e||e.target.id==='smtp-modal')document.getElementById('smtp-modal').style.display='none'}
function openHealth(){var m=document.getElementById('health-modal');m.style.display='flex';document.getElementById('health-result').textContent='%[14]s';fetch('/api/v1/health').then(function(r){return r.text()}).then(function(t){document.getElementById('health-result').textContent=t})}
function closeHealth(e){if(!e||e.target.id==='health-modal')document.getElementById('health-modal').style.display='none'}
function testSMTP(){
  var f=document.querySelector('#smtp-modal form')
  var fd=new FormData(f)
  var obj={};for(var e of fd.entries()){obj[e[0]]=e[1]}
  var r=document.getElementById('smtp-test-result')
  r.textContent='%[29]s';r.style.color='#888'
  fetch('/admin/api/smtp/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj)}).then(function(r2){return r2.json()}).then(function(d){
    r.textContent=d.ok?'%[30]s':'\u2717 '+d.error
    r.style.color=d.ok?'#4ade80':'#ff6b6b'
  }).catch(function(e){r.textContent='\u2717 '+e;r.style.color='#ff6b6b'})
}
</script>

<div id="smtp-modal" class="modal-overlay" style="display:none" onclick="closeSMTP(event)">
<div class="modal">
<button class="modal-close" onclick="closeSMTP()">&times;</button>
<h2>%[28]s</h2>
<form action="/admin/api/smtp" method="POST">
<div class="form-row"><label>%[18]s</label><input name="smtp_host" value="%[32]s" placeholder="smtp.example.com"></div>
<div class="form-row"><label>%[19]s</label><input name="smtp_port" value="%[33]s" placeholder="587"></div>
<div class="form-row"><label>%[20]s</label><select name="smtp_security" style="font-family:inherit;font-size:14px;padding:8px 12px;border:1px solid #2a2a3c;background:#13131f;color:#e4e4ef;border-radius:6px;flex:1;box-sizing:border-box">
<option value="starttls"%[34]s>STARTTLS</option>
<option value="tls"%[35]s>TLS</option>
<option value="none"%[36]s>%[21]s</option>
</select></div>
<div class="form-row"><label>%[22]s</label><input name="smtp_user" value="%[37]s" placeholder="user@example.com"></div>
<div class="form-row"><label>%[23]s</label><input type="password" name="smtp_pass" placeholder="••••••••"></div>
<div class="form-row"><label>%[24]s</label><input name="smtp_from" value="%[38]s" placeholder="noreply@example.com"></div>
<div class="form-row"><label>%[25]s</label><input name="server_url" value="%[39]s" placeholder="https://example.com:47732"></div>
<div style="margin-top:12px;display:flex;gap:8px;align-items:center">
<button class="btn btn-primary">%[26]s</button>
<button class="btn" type="button" onclick="testSMTP()">%[27]s</button>
<span id="smtp-test-result" style="font-size:12px"></span>
</div>
</form>
</div>
</div>

<div id="health-modal" class="modal-overlay" style="display:none" onclick="closeHealth(event)">
<div class="modal">
<button class="modal-close" onclick="closeHealth()">&times;</button>
<h2>%[17]s</h2>
<pre id="health-result">%[14]s</pre>
</div>
</div>

</body></html>`,
		t(locale, "admin.dashboard"),
		t(locale, "admin.deviceCount"),
		t(locale, "admin.opsCount"),
		t(locale, "admin.devices"),
		t(locale, "admin.noDevices"),
		t(locale, "admin.device"),
		t(locale, "admin.user"),
		t(locale, "admin.version"),
		t(locale, "admin.status"),
		t(locale, "admin.lastSeen"),
		t(locale, "admin.active"),
		t(locale, "admin.revoked"),
		t(locale, "admin.revoke"),
		t(locale, "common.loading"),
		t(locale, "admin.smtp"),
		t(locale, "admin.users"),
		t(locale, "admin.healthCheck"),
		t(locale, "admin.smtpServer"),
		t(locale, "admin.smtpPort"),
		t(locale, "admin.smtpType"),
		t(locale, "admin.smtpNoEncryption"),
		t(locale, "admin.smtpUsername"),
		t(locale, "admin.smtpPassword"),
		t(locale, "admin.smtpFrom"),
		t(locale, "admin.smtpServerURL"),
		t(locale, "admin.smtpSave"),
		t(locale, "admin.smtpTest"),
		t(locale, "admin.smtpTitle"),
		t(locale, "admin.smtpTesting"),
		t(locale, "admin.smtpPassed"),
		t(locale, "admin.revokeConfirm"),
		smtpHost,
		smtpPort,
		sel(smtpSecurity, "starttls"),
		sel(smtpSecurity, "tls"),
		sel(smtpSecurity, "none"),
		smtpUser,
		smtpFrom,
		srvURL,
		deviceCount,
		opsCount,
	)
}

func userDashboardHTML(locale, username, deviceRows string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verstak Sync — %[1]s</title>
<style>
body{font-family:sans-serif;background:#13131f;color:#e4e4ef;padding:24px;max-width:800px;margin:0 auto}
h1{border-bottom:1px solid #2a2a3c;padding-bottom:12px}
h2{margin-top:24px;font-size:16px}
table{width:100%%;border-collapse:collapse;margin-top:8px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #2a2a3c}
th{font-size:12px;color:#888;text-transform:uppercase}
.btn{font-family:inherit;font-size:12px;padding:6px 12px;border-radius:6px;border:1px solid #2a2a3c;background:#1a1a28;color:#ccc;cursor:pointer;display:inline-flex;align-items:center;gap:4px}
.btn:hover{background:#222233}
.btn-primary{background:#6366f1;border-color:#6366f1;color:#fff}
.btn-primary:hover{background:#4f46e5}
.btn-danger{color:#ff6b6b;border-color:#4a2222}
.btn-danger:hover{background:#3a2222}
.btn-sm{padding:2px 8px;font-size:11px}
.top{display:flex;justify-content:space-between;align-items:center}
a{color:#6366f1}
</style>
</head><body>
<div class="top">
<h1>Verstak Sync</h1>
<span>%[1]s · <a href="/logout">%[2]s</a></span>
</div>
<h2>%[3]s</h2>
<table><tr><th>%[4]s</th><th>%[5]s</th><th>%[6]s</th><th>%[7]s</th><th>%[8]s</th></tr>%[9]s</table>

<div style="margin-top:24px;padding:16px;background:#1a1a28;border:1px solid #2a2a3c;border-radius:8px">
<h2 style="margin-top:0">%[10]s</h2>
<p style="font-size:13px;color:#888">%[11]s</p>
</div>

<script>
function revokeDevice(id){
  if(!confirm('%[12]s'))return
  var pw=prompt('%[13]s')
  if(!pw)return
  fetch('/api/client/revoke-device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_id:id,password:pw})}).then(function(r){return r.json()}).then(function(d){
    if(d.status==='revoked'){location.reload()}else{alert(d.error||'error')}
  })
}
</script>
</body></html>`,
		username,
		t(locale, "server.logout"),
		t(locale, "userDashboard.devices"),
		t(locale, "userDashboard.device"),
		t(locale, "userDashboard.status"),
		t(locale, "userDashboard.connected"),
		t(locale, "userDashboard.lastSeen"),
		t(locale, "userDashboard.version"),
		deviceRows,
		t(locale, "userDashboard.connectNew"),
		t(locale, "userDashboard.connectNewHint"),
		t(locale, "userDashboard.revokeConfirm"),
		t(locale, "userDashboard.revokePrompt"),
	)
}

func adminCreateUserHTML(locale string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%[1]s</title>
<style>body{font-family:sans-serif;background:#13131f;color:#e4e4ef;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
form{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:32px;width:320px}
h1{font-size:20px;margin:0 0 20px;text-align:center}
p{text-align:center;font-size:12px;color:#666;margin-top:16px}
a{color:#6366f1}
label{display:block;font-size:12px;color:#888;margin-bottom:4px}
input{width:100%%;padding:8px 12px;border:1px solid #2a2a3c;background:#13131f;color:#e4e4ef;border-radius:6px;font-size:14px;margin-bottom:16px;box-sizing:border-box}
button{width:100%%;padding:10px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer}
button:hover{background:#4f46e5}
.hint{font-size:11px;color:#666;margin-top:-12px;margin-bottom:16px;text-align:center}
</style>
</head><body>
<form method="POST">
<h1>%[2]s</h1>
<label>%[3]s</label>
<input type="text" name="username" autofocus required>
<label>%[4]s</label>
<input type="email" name="email" required>
<label>%[5]s</label>
<input type="password" name="password" required minlength="8" maxlength="256">
<button>%[6]s</button>
<p><a href="/admin/users">%[7]s</a></p>
</form>
</body></html>`,
		t(locale, "admin.createUser"),
		t(locale, "admin.createUser"),
		t(locale, "server.username"),
		t(locale, "server.email"),
		t(locale, "server.password"),
		t(locale, "admin.createUserBtn"),
		t(locale, "server.dashboard"),
	)
}

func errorPageHTML(locale, title, msg, backURL string) string {
	title = html.EscapeString(title)
	msg = html.EscapeString(msg)
	backURL = html.EscapeString(backURL)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verstak Sync — %s</title>
<style>body{font-family:sans-serif;background:#13131f;color:#e4e4ef;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:32px;text-align:center;max-width:360px}
h1{font-size:18px;margin:0 0 12px;color:#ff6b6b}
p{font-size:13px;color:#b0b0c0;margin:0 0 16px}
a{color:#6366f1;text-decoration:none}
a:hover{text-decoration:underline}</style>
</head><body>
<div class="box">
<h1>%s</h1>
<p>%s</p>
<a href="%s">%s</a>
</div>
</body></html>`, title, title, msg, backURL, t(locale, "server.back"))
}

func adminUsersHTML(locale string) string {
	newPassResult := t(locale, "server.newPasswordResult")
	newPassParts := strings.SplitN(newPassResult, "%s", 2)
	newPassPrefix := newPassParts[0]
	newPassSuffix := ""
	if len(newPassParts) > 1 {
		newPassSuffix = strings.ReplaceAll(newPassParts[1], "\n", "\\n")
	}

	deleteMsg := t(locale, "admin.deleteUserMessage")
	deleteMsgParts := strings.SplitN(deleteMsg, "%s", 2)
	delMsgPrefix := deleteMsgParts[0]
	delMsgSuffix := ""
	if len(deleteMsgParts) > 1 {
		delMsgSuffix = deleteMsgParts[1]
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%[1]s</title>
<style>
body{font-family:sans-serif;background:#13131f;color:#e4e4ef;padding:24px;max-width:960px;margin:0 auto}
a{color:#6366f1}
h1{border-bottom:1px solid #2a2a3c;padding-bottom:12px}
table{width:100%%;border-collapse:collapse;margin-top:12px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #2a2a3c}
th{font-size:12px;color:#888;text-transform:uppercase;cursor:pointer;user-select:none}
th:hover{color:#b0b0c0}
th.sorted{color:#6366f1}
.btn{font-family:inherit;font-size:12px;padding:6px 12px;border-radius:6px;border:1px solid #2a2a3c;background:#1a1a28;color:#ccc;cursor:pointer;display:inline-flex;align-items:center;gap:4px}
.btn:hover{background:#222233}
.btn-primary{background:#6366f1;border-color:#6366f1;color:#fff}
.btn-primary:hover{background:#4f46e5}
.btn-danger{color:#ff6b6b;border-color:#4a2222}
.btn-danger:hover{background:#3a2222}
.btn-sm{padding:2px 8px;font-size:11px}
input{font-family:inherit;font-size:14px;padding:8px 12px;border:1px solid #2a2a3c;background:#13131f;color:#e4e4ef;border-radius:6px;box-sizing:border-box}
input:focus{outline:none;border-color:#6366f1}
.toolbar{display:flex;gap:8px;margin:12px 0;flex-wrap:wrap;align-items:center}
.pagination{display:flex;gap:8px;margin-top:12px;align-items:center;justify-content:center}
.pagination span{padding:4px 8px;font-size:12px;color:#888}
.badge{padding:2px 8px;border-radius:4px;font-size:11px}
.badge-green{background:#064e3b;color:#34d399}
.badge-red{background:#4a2222;color:#ff6b6b}
.badge-yellow{background:#4a3e00;color:#fbbf24}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100}
.modal{background:#1a1a28;border:1px solid #2a2a3c;border-radius:12px;padding:24px;width:400px;max-width:90vw;position:relative}
.modal h2{margin-top:0;font-size:16px}
.modal-close{position:absolute;top:10px;right:14px;font-size:20px;cursor:pointer;background:none;border:none;color:#888}
.modal-close:hover{color:#e4e4ef}
.form-row{display:flex;gap:8px;margin-bottom:12px;align-items:center}
.form-row label{font-size:12px;color:#888;min-width:80px;flex-shrink:0}
.form-row input{flex:1}
</style>
</head><body>
<h1>%[2]s</h1>
<p><a href="/admin/dashboard">%[3]s</a></p>

<div class="toolbar">
<input id="filter-input" placeholder="%[4]s" style="width:200px" onkeyup="loadUsers()">
<a href="/admin/create-user" style="text-decoration:none"><button class="btn btn-primary" type="button">%[39]s</button></a>
</div>

<table>
<thead><tr>
<th onclick="sortBy('username')">%[5]s <span id="s-username"></span></th>
<th onclick="sortBy('email')">%[6]s <span id="s-email"></span></th>
<th onclick="sortBy('confirmed')">%[7]s <span id="s-confirmed"></span></th>
<th onclick="sortBy('devices')">%[8]s <span id="s-devices"></span></th>
<th onclick="sortBy('last_seen')">%[9]s <span id="s-last_seen"></span></th>
<th>%[10]s</th>
</tr></thead>
<tbody id="users-tbody"></tbody>
</table>

<div class="pagination" id="pagination"></div>

<div id="confirm-modal" class="modal-overlay" style="display:none">
<div class="modal">
<button class="modal-close" onclick="closeConfirm()">&times;</button>
<h2 id="confirm-title">%[11]s</h2>
<p id="confirm-text"></p>
<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
<button class="btn" onclick="closeConfirm()">%[12]s</button>
<button class="btn btn-danger" id="confirm-btn" onclick="confirmAction()">%[13]s</button>
</div>
</div>
</div>

<div id="edit-modal" class="modal-overlay" style="display:none">
<div class="modal">
<button class="modal-close" onclick="closeEdit()">&times;</button>
<h2>%[14]s</h2>
<div class="form-row"><label>%[15]s</label><input id="edit-username"></div>
<div class="form-row"><label>%[16]s</label><input id="edit-email" type="email"></div>
<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
<button class="btn" onclick="closeEdit()">%[17]s</button>
<button class="btn btn-primary" onclick="saveEdit()">%[18]s</button>
</div>
</div>
</div>

<div id="result-modal" class="modal-overlay" style="display:none">
<div class="modal" style="width:320px">
<button class="modal-close" onclick="closeResult()">&times;</button>
<h2 id="result-title">%[19]s</h2>
<p id="result-text" style="white-space:pre-wrap"></p>
<button class="btn btn-primary" onclick="closeResult()" style="margin-top:8px">%[20]s</button>
</div>
</div>

<script>
var currentPage=1,currentSort='',currentOrder='',editUserId='',pendingAction=''

function loadUsers(){
  var f=document.getElementById('filter-input').value
  var u='/admin/api/users?page='+currentPage+'&per_page=20&filter='+encodeURIComponent(f)
  if(currentSort){u+='&sort='+currentSort+'&order='+currentOrder}
  fetch(u).then(function(r){return r.json()}).then(function(d){
    var tbody=document.getElementById('users-tbody')
    tbody.innerHTML=''
    d.users.forEach(function(u){
      var status=u.confirmed?'<span class="badge badge-green">%[21]s</span>':'<span class="badge badge-yellow">%[22]s</span>'
      if(u.blocked){status='<span class="badge badge-red">%[23]s</span>'}
      var lastSeen=u.last_seen?new Date(u.last_seen).toLocaleString():'-'
      var blockText=u.blocked?'%[24]s':'%[25]s'
      var tr=document.createElement('tr')
      tr.innerHTML='<td>'+esc(u.username)+'</td><td>'+esc(u.email)+'</td><td>'+status+'</td><td>'+u.devices+'</td><td>'+lastSeen+'</td>'+
        '<td><button class="btn btn-sm" onclick="editUser(\''+u.id+'\',\''+escJS(u.username)+'\',\''+escJS(u.email)+'\')">✎</button> '+
        '<button class="btn btn-sm" onclick="askBlock(\''+u.id+'\','+u.blocked+')">'+blockText+'</button> '+
        '<button class="btn btn-sm" onclick="askReset(\''+u.id+'\')">%[26]s</button> '+
        '<button class="btn btn-sm btn-danger" onclick="askDelete(\''+u.id+'\',\''+escJS(u.username)+'\')">✕</button></td>'
      tbody.appendChild(tr)
    })
    if(!d.users.length){tbody.innerHTML='<tr><td colspan="6" style="text-align:center;color:#666">%[27]s</td></tr>'}
    var totalPages=Math.ceil(d.total/d.per_page)
    var pag=document.getElementById('pagination')
    pag.innerHTML=''
    if(totalPages>1){
      var prev=document.createElement('button')
      prev.className='btn btn-sm';prev.textContent='←';prev.onclick=function(){if(currentPage>1){currentPage--;loadUsers()}}
      pag.appendChild(prev)
      var s=document.createElement('span')
      s.textContent=d.page+' / '+totalPages
      pag.appendChild(s)
      var next=document.createElement('button')
      next.className='btn btn-sm';next.textContent='→';next.onclick=function(){if(currentPage<totalPages){currentPage++;loadUsers()}}
      pag.appendChild(next)
    }
  })
}
function sortBy(col){
  if(currentSort===col){currentOrder=currentOrder==='asc'?'desc':'asc'}
  else{currentSort=col;currentOrder='asc'}
  document.querySelectorAll('th').forEach(function(th){th.classList.remove('sorted')})
  var el=document.getElementById('s-'+col)
  if(el){el.parentElement.classList.add('sorted');el.textContent=currentOrder==='asc'?' ▲':' ▼'}
  loadUsers()
}
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function escJS(s){return s.replace(/'/g,"\\'").replace(/"/g,'&quot;')}
function editUser(id,username,email){
  editUserId=id;document.getElementById('edit-username').value=username;document.getElementById('edit-email').value=email;document.getElementById('edit-modal').style.display='flex'}
function closeEdit(){document.getElementById('edit-modal').style.display='none'}
function saveEdit(){
  var un=document.getElementById('edit-username').value,em=document.getElementById('edit-email').value
  if(!un||!em)return
  fetch('/admin/api/users/'+editUserId+'/edit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:un,email:em})}).then(function(r){return r.json()}).then(function(d){closeEdit();if(d.status==='ok')loadUsers()})
}
function askBlock(id,blocked){
  pendingAction=function(){fetch('/admin/api/users/'+id+'/block',{method:'POST'}).then(function(r){return r.json()}).then(function(d){loadUsers()})}
  document.getElementById('confirm-title').textContent=blocked?'%[35]s':'%[36]s'
  document.getElementById('confirm-text').textContent=blocked?'%[37]s':'%[38]s'
  document.getElementById('confirm-btn').textContent=blocked?'%[24]s':'%[25]s'
  document.getElementById('confirm-modal').style.display='flex'}
function askReset(id){
  pendingAction=function(){
    fetch('/admin/api/users/'+id+'/reset-password',{method:'POST'}).then(function(r){return r.json()}).then(function(d){
      document.getElementById('confirm-modal').style.display='none'
      document.getElementById('result-title').textContent='%[28]s'
      document.getElementById('result-text').textContent='%[29]s' + d.new_password + '%[30]s'
      document.getElementById('result-modal').style.display='flex'})}
  document.getElementById('confirm-title').textContent='%[31]s'
  document.getElementById('confirm-text').textContent='%[32]s'
  document.getElementById('confirm-btn').textContent='%[33]s'
  document.getElementById('confirm-modal').style.display='flex'}
function askDelete(id,username){
  pendingAction=function(){fetch('/admin/api/users/'+id,{method:'DELETE'}).then(function(r){return r.json()}).then(function(d){loadUsers()})}
  document.getElementById('confirm-title').textContent='%[34]s'
  document.getElementById('confirm-text').textContent='%[35]s' + username + '%[36]s'
  document.getElementById('confirm-btn').textContent='%[37]s'
  document.getElementById('confirm-modal').style.display='flex'}
function closeConfirm(){document.getElementById('confirm-modal').style.display='none';pendingAction=''}
function confirmAction(){if(pendingAction){pendingAction();pendingAction=''}}
function closeResult(){document.getElementById('result-modal').style.display='none'}
loadUsers()
</script>
</body></html>`,
		t(locale, "admin.users"),
		t(locale, "admin.usersHeading"),
		t(locale, "server.dashboard"),
		t(locale, "admin.filterPlaceholder"),
		t(locale, "admin.username"),
		t(locale, "admin.email"),
		t(locale, "admin.status"),
		t(locale, "admin.devices"),
		t(locale, "admin.lastSeen"),
		t(locale, "admin.actions"),
		t(locale, "admin.confirmTitle"),
		t(locale, "admin.modalCancel"),
		t(locale, "admin.modalConfirm"),
		t(locale, "admin.editUser"),
		t(locale, "admin.username"),
		t(locale, "admin.email"),
		t(locale, "admin.modalCancel"),
		t(locale, "admin.editBtn"),
		t(locale, "admin.resultTitle"),
		t(locale, "common.ok"),
		t(locale, "admin.confirmed"),
		t(locale, "admin.unconfirmed"),
		t(locale, "admin.blocked"),
		t(locale, "admin.unblock"),
		t(locale, "admin.block"),
		t(locale, "admin.resetPassword"),
		t(locale, "admin.noUsers"),
		t(locale, "server.newPassword"),
		newPassPrefix,
		newPassSuffix,
		t(locale, "admin.resetPasswordConfirm"),
		t(locale, "admin.resetPasswordMessage"),
		t(locale, "admin.resetBtn"),
		t(locale, "admin.deleteUser"),
		delMsgPrefix,
		delMsgSuffix,
		t(locale, "admin.deleteBtn"),
		t(locale, "admin.unblockUserTitle"),
		t(locale, "admin.blockUserTitle"),
		t(locale, "admin.unblockUserMessage"),
		t(locale, "admin.blockUserMessage"),
		t(locale, "admin.createUser"),
	)
}
