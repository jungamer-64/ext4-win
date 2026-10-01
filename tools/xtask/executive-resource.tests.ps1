$ErrorActionPreference = 'Stop'
$repository = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$compiler = Get-Command clang.exe -ErrorAction Stop
$directory = Join-Path ([IO.Path]::GetTempPath()) ('ext4win-resource-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory | Out-Null
$executable = Join-Path $directory 'resource-tests.exe'
try {
    # The oracle needs neither a C runtime nor WDK imports; every assertion traps on failure.
    & $compiler.Source --target=x86_64-pc-windows-msvc -std=c11 -Wall -Wextra -Werror `
        -nostdlib -fuse-ld=lld -Xlinker /entry:main -Xlinker /subsystem:console `
        (Join-Path $repository 'crates/ext4-driver/native/executive_resource.tests.c') `
        -o $executable
    if ($LASTEXITCODE -ne 0) { throw 'executive resource contract compilation failed' }
    & $executable
    if ($LASTEXITCODE -ne 0) { throw "executive resource APC ownership failed: $LASTEXITCODE" }
    Write-Host 'executive resource APC ownership: PASS'
}
finally {
    if (Test-Path -LiteralPath $executable) { Remove-Item -LiteralPath $executable }
    [IO.Directory]::Delete($directory, $false)
}
