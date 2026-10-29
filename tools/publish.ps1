<#
Create the GitHub repository GHC and push this tree to it.

Run from anywhere:   powershell -ExecutionPolicy Bypass -File X:\GHC\tools\publish.ps1
Options:             -Visibility public   (default is private)
                     -Name OTHERNAME      (default GHC)

Needs git and the GitHub CLI (gh), signed in:  gh auth login
To push the CI workflow your gh token needs the "workflow" scope:
                     gh auth refresh -s workflow

What it does, in order, and stops at the first problem:
  1. removes the live demo\.git (it holds a fsmonitor payload and git cannot push a
     nested .git anyway; demo\make_demo.py rebuilds it on demand)
  2. refuses to go on if any other nested .git directory is found
  3. runs the detonation gate and the full suite (tools\run_gate.py)
  4. copies docs\ci.yml.example to .github\workflows\ci.yml
  5. git init, commit, then gh repo create <Name> --source . --push
#>
param(
    [string]$Name = "GHC",
    [ValidateSet("private", "public")] [string]$Visibility = "private"
)
$ErrorActionPreference = "Stop"

function Step($text) { Write-Host ""; Write-Host "== $text" -ForegroundColor Cyan }
function Must($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
Write-Host "Repository root: $root"

foreach ($tool in "git", "gh", "python") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is not on PATH" }
}
gh auth status
Must "gh auth status (run: gh auth login)"

Step "1. Remove the live demo .git (demo\make_demo.py rebuilds it on demand)"
$demoGit = Join-Path $root "demo\.git"
if (Test-Path -LiteralPath $demoGit) {
    try {
        # git marks some of its files read-only; clear that, then delete. The demo is throwaway.
        Get-ChildItem -LiteralPath $demoGit -Recurse -Force | ForEach-Object { $_.Attributes = "Normal" }
        Remove-Item -LiteralPath $demoGit -Recurse -Force -ErrorAction Stop
        Write-Host "Removed demo\.git"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host ""
        Write-Host "Windows would not let this script remove demo\.git (wrong owner, or a program has it open)." -ForegroundColor Yellow
        Write-Host "Close any editor or terminal inside X:\GHC\demo, then in an ADMINISTRATOR PowerShell run:"
        Write-Host '  takeown /f X:\GHC\demo\.git /r /d y'
        Write-Host '  icacls X:\GHC\demo\.git /grant "$env:USERNAME:(OI)(CI)F" /t'
        Write-Host '  Remove-Item -LiteralPath X:\GHC\demo\.git -Recurse -Force'
        Write-Host "and then run publish.ps1 again."
        throw "demo\.git could not be removed"
    }
} else {
    Write-Host "No demo\.git present."
}

Step "2. Look for any other nested .git"
$nested = Get-ChildItem -LiteralPath $root -Recurse -Force -Directory -Filter ".git" -ErrorAction SilentlyContinue
if ($nested) {
    $nested | ForEach-Object { Write-Host "  found: $($_.FullName)" -ForegroundColor Red }
    throw "nested .git directories found; remove or move them first"
}
if (Test-Path -LiteralPath (Join-Path $root "fired.txt")) { throw "fired.txt exists in the tree; delete it first" }

Step "3. Gate and full suite"
python tools\run_gate.py
Must "the gate / suite"

Step "4. CI workflow"
New-Item -ItemType Directory -Force -Path ".github\workflows" | Out-Null
Copy-Item -LiteralPath "docs\ci.yml.example" -Destination ".github\workflows\ci.yml" -Force

Step "5. Commit and push"
if (-not (Test-Path -LiteralPath ".git")) { git init -b main; Must "git init" }
git add -A
Must "git add"
git status --short
git commit -m "sinkcheck 1.0.1: read-only scanner for git config execution sinks"
Must "git commit (set your identity with: git config --global user.name / user.email)"
$meta = (git log -1 --format="%an%n%ae%n%cn%n%ce%n%B") -join "`n"
if ($meta -match "(?i)claude|anthropic|co-authored-by") {
    throw "commit metadata mentions an author or co-author you did not intend; fix it (git commit --amend --reset-author) and re-run"
}
gh repo create $Name "--$Visibility" --source . --remote origin --push
Must "gh repo create"

Write-Host ""
Write-Host "Done. Repository: $Name ($Visibility)" -ForegroundColor Green
