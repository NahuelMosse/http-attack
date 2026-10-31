# Windows PowerShell 5.1 end to end: the request body comes from a file, and a legitimate write passes.
# alice and bob are the two test users hard-coded in fixtures/fixed-server.mjs; they are not credentials.
$ErrorActionPreference = 'Stop'
$PSVersionTable.PSVersion

$port = 3917
$target = "http://127.0.0.1:$port"
$database = Join-Path $env:RUNNER_TEMP 'app.db'
$bodyFile = Join-Path $env:RUNNER_TEMP 'body.json'
$reportFile = Join-Path $env:RUNNER_TEMP 'report.json'

$server = Start-Process node -ArgumentList 'skills/http-attack/fixtures/fixed-server.mjs', $port, $database -PassThru
try {
  $deadline = (Get-Date).AddSeconds(30)
  while (-not (Test-NetConnection 127.0.0.1 -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { throw "the fixture server did not listen on port $port" }
    Start-Sleep -Milliseconds 200
  }

  Set-Content -Path $bodyFile -Value '{"name":"Ana","email":"ana@example.com"}'
  $attack = @(
    'skills/http-attack/scripts/http-attack.mjs', $target
    '--header', 'Authorization: Bearer alice'
    '--other-header', 'Authorization: Bearer bob'
    '--write', "POST /items @$bodyFile"
    '--format', 'json'
  )
  node @attack | Out-File $reportFile -Encoding utf8
  $exitCode = $LASTEXITCODE
} finally {
  Stop-Process -Id $server.Id -ErrorAction SilentlyContinue
}

$report = Get-Content $reportFile -Raw | ConvertFrom-Json
if (-not ($report.rows | Where-Object { $_.id -eq 'ok:legit-write:POST /items' })) { throw 'the legitimate write from the body file did not pass' }
if ($exitCode -ne 0) { throw "unexpected findings, exit $exitCode" }
