param(
    [Parameter(Mandatory)][string] $RunDirectory,
    [switch] $RemoveRun
)
$ErrorActionPreference = 'Stop'
$primaryPython = if ($IsWindows) { 'python' } else { 'python3' }
$fallbackPython = if ($IsWindows) { 'python3' } else { 'python' }
$python = Get-Command $primaryPython -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $python) {
    $python = Get-Command $fallbackPython -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
}
if (-not $python) { throw 'Python 3 is required for cleanup.' }
$arguments = @(
    (Join-Path $PSScriptRoot 'scripts/deploy.py'), 'cleanup',
    '--run-directory', $RunDirectory
)
if ($RemoveRun) { $arguments += '--remove-run' }
& $python.Source @arguments
if ($LASTEXITCODE -ne 0) { throw "Dracut cleanup failed (exit $LASTEXITCODE)." }
