param(
    [Parameter(Mandatory)][string]$RemotePath,
    [Parameter(Mandatory)][string]$Destination,
    [string]$McpUrl,
    [string]$Token = $env:DEXMCP_TOKEN
)
$ErrorActionPreference = 'Stop'
if (-not $McpUrl -or -not $Token) {
    $configPath = Join-Path $env:USERPROFILE '.codex/config.toml'
    if (Test-Path -LiteralPath $configPath) {
        $config = Get-Content -LiteralPath $configPath -Raw
        $section = [regex]::Match($config, '(?ms)^\[mcp_servers\.dexmcp\].*?(?=^\[(?!mcp_servers\.dexmcp\.)|\z)').Value
        if (-not $McpUrl) { $McpUrl = [regex]::Match($section, '(?m)^url\s*=\s*"([^"]+)"').Groups[1].Value }
        if (-not $Token) { $Token = [regex]::Match($section, 'Authorization\s*=\s*"Bearer ([^"]+)"').Groups[1].Value }
    }
}
if (-not $McpUrl -or -not $Token) { throw 'Specify -McpUrl and DEXMCP_TOKEN, or configure mcp_servers.dexmcp in Codex.' }
function Invoke-PhoneTool([string]$Name, [hashtable]$Arguments) {
    $payload = @{jsonrpc='2.0';id=1;method='tools/call';params=@{name=$Name;arguments=$Arguments}} | ConvertTo-Json -Depth 8 -Compress
    $reply = Invoke-RestMethod -Uri $McpUrl -Method Post -Headers @{Authorization="Bearer $Token";Accept='application/json, text/event-stream'} -ContentType 'application/json' -Body $payload -TimeoutSec 120
    if ($reply.error) { throw ($reply.error | ConvertTo-Json -Compress) }
    if ($reply.result.isError) { throw ($reply.result.structuredContent | ConvertTo-Json -Compress) }
    return $reply.result.structuredContent
}
$target = [IO.Path]::GetFullPath($Destination)
$parent = [IO.Path]::GetDirectoryName($target)
[IO.Directory]::CreateDirectory($parent) | Out-Null
$temporary = $target + '.' + [guid]::NewGuid().ToString('N') + '.part'
$export = $null
try {
    $export = Invoke-PhoneTool android_system_export_file @{path=$RemotePath}
    $output = [IO.File]::Create($temporary)
    try {
        [long]$offset = 0
        do {
            $chunk = Invoke-PhoneTool android_system_read_export @{export_id=$export.export_id;offset=$offset;max_bytes=65536}
            $bytes = [Convert]::FromBase64String($chunk.content_base64)
            if ($chunk.offset -ne $offset -or $bytes.Length -ne $chunk.bytes_read -or $chunk.next_offset -ne ($offset + $bytes.Length)) { throw 'Invalid download chunk' }
            if (-not $chunk.eof -and $bytes.Length -eq 0) { throw 'Empty non-final download chunk' }
            $output.Write($bytes, 0, $bytes.Length)
            $offset += $bytes.Length
        } while (-not $chunk.eof)
    } finally { $output.Dispose() }
    if ((Get-Item -LiteralPath $temporary).Length -ne $export.size) { throw 'Downloaded size mismatch' }
    if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ne $export.sha256) { throw 'Downloaded SHA-256 mismatch' }
    Move-Item -LiteralPath $temporary -Destination $target -Force
    Write-Output "Saved: $target ($($export.size) bytes; SHA-256 verified)"
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
    if ($export) {
        try { Invoke-PhoneTool android_system_delete_export @{export_id=$export.export_id} | Out-Null }
        catch { Write-Warning 'Download cleanup on phone failed; temporary copy remains in App cache.' }
    }
}
