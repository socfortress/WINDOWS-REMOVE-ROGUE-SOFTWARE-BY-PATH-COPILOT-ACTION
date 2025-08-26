[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$TargetPath,

  [string]$LogPath = "$env:TEMP\RemoveRogueSoftware-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log',
  [string]$Arg1
)

if ($Arg1 -and -not $TargetPath) { $TargetPath = $Arg1 }

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep  = 5
$runStart = Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){Write-Verbose $line}}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Now-Timestamp {
  $tz=(Get-Date).ToString('zzz').Replace(':','')
  (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + $tz
}

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp=Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try{Move-Item -Path $tmp -Destination $Path -Force}catch{Move-Item -Path $tmp -Destination ($Path + '.new') -Force}
}

function Safe-ResolvePath {
  param([string]$Path)
  try { (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path } catch { $null }
}

function Quarantine-Path {
  param([string]$FullPath)

  $qRoot = 'C:\Quarantine'
  if(-not (Test-Path $qRoot)){ New-Item -Path $qRoot -ItemType Directory -Force | Out-Null }

  $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
  $leaf  = Split-Path -Path $FullPath -Leaf
  $destDirBase = Join-Path $qRoot ($stamp + '_' + $leaf)

  $suffix = 0; $finalDir = $destDirBase
  while(Test-Path $finalDir){ $suffix++; $finalDir = "$destDirBase`_$suffix" }
  New-Item -Path $finalDir -ItemType Directory -Force | Out-Null

  if (Test-Path -LiteralPath $FullPath -PathType Leaf) {
    Move-Item -LiteralPath $FullPath -Destination (Join-Path $finalDir $leaf) -Force
  } else {
    $parentName = Split-Path -Path $FullPath -Leaf
    Move-Item -LiteralPath $FullPath -Destination (Join-Path $finalDir $parentName) -Force
  }

  $manifest = [pscustomobject]@{
    original_path   = $FullPath
    quarantine_path = $finalDir
    timestamp       = (Get-Date).ToString('o')
    host            = $HostName
    action          = 'remove_rogue_software'
    method          = 'quarantine'
    copilot_action  = $true
  }
  $mfPath = Join-Path $finalDir '_manifest.json'
  $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $mfPath -Encoding utf8
  icacls $finalDir /inheritance:r | Out-Null
  icacls $finalDir /grant:r "Administrators:(F)" "SYSTEM:(F)" "Users:(R)" | Out-Null
  Get-ChildItem -LiteralPath $finalDir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    try { icacls $_.FullName /inheritance:r /grant:r "Administrators:(F)" "SYSTEM:(F)" "Users:(R)" | Out-Null } catch {}
  }

  return @{ QuarantineDir=$finalDir; Manifest=$mfPath }
}

Rotate-Log
Write-Log "=== SCRIPT START : Remove Rogue Software (auto-quarantine) ==="

$lines = @()
$ts    = Now-Timestamp

try {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
  if(-not $isAdmin){ throw "Administrator privileges are required." }

  $FullPath = Safe-ResolvePath -Path $TargetPath
  if (-not $FullPath) {
    Write-Log "Target path '${TargetPath}' not found." 'ERROR'
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'remove_rogue_software'
      copilot_action = $true
      type           = 'error'
      target         = $TargetPath
      error          = 'Path not found'
    } | ConvertTo-Json -Compress -Depth 4)
    Write-NDJSONLines -JsonLines $lines -Path $ARLog
    return
  }

  Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      if ($_.Path -and ($_.Path -like ($FullPath + '*'))) {
        $procId = $_.Id
        $pname  = $_.ProcessName
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        Write-Log ("Killed process {0} (PID {1})" -f $pname,$procId) 'INFO'
        $lines += ([pscustomobject]@{
          timestamp      = $ts
          host           = $HostName
          action         = 'remove_rogue_software'
          copilot_action = $true
          type           = 'process_killed'
          process        = $pname
          pid            = $procId
          path_prefix    = $FullPath
        } | ConvertTo-Json -Compress -Depth 4)
      }
    } catch {}
  }

  Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
    $_.PathName -and ($_.PathName -like ($FullPath + '*'))
  } | ForEach-Object {
    try{
      $svc = $_.Name
      sc.exe stop $svc | Out-Null
      sc.exe delete $svc | Out-Null
      Write-Log ("Deleted service {0}" -f $svc) 'INFO'
      $lines += ([pscustomobject]@{
        timestamp      = $ts
        host           = $HostName
        action         = 'remove_rogue_software'
        copilot_action = $true
        type           = 'service_deleted'
        service        = $svc
        path_name      = $_.PathName
      } | ConvertTo-Json -Compress -Depth 4)
    }catch{
      $lines += ([pscustomobject]@{
        timestamp      = $ts
        host           = $HostName
        action         = 'remove_rogue_software'
        copilot_action = $true
        type           = 'service_delete_error'
        service        = $_.Name
        error          = $_.Exception.Message
      } | ConvertTo-Json -Compress -Depth 4)
    }
  }

  $taskMatches = schtasks /Query /FO LIST /V | Select-String -SimpleMatch -Pattern $FullPath -Context 0,10
  if ($taskMatches) {
    foreach ($line in $taskMatches) {
      if ($line -match "TaskName:\s+(.+)") {
        $taskName = $Matches[1].Trim()
        try {
          schtasks /Delete /TN "$taskName" /F | Out-Null
          Write-Log ("Deleted scheduled task {0}" -f $taskName) 'INFO'
          $lines += ([pscustomobject]@{
            timestamp      = $ts
            host           = $HostName
            action         = 'remove_rogue_software'
            copilot_action = $true
            type           = 'task_deleted'
            task_name      = $taskName
            matched_path   = $FullPath
          } | ConvertTo-Json -Compress -Depth 4)
        } catch {
          $lines += ([pscustomobject]@{
            timestamp      = $ts
            host           = $HostName
            action         = 'remove_rogue_software'
            copilot_action = $true
            type           = 'task_delete_error'
            task_name      = $taskName
            matched_path   = $FullPath
            error          = $_.Exception.Message
          } | ConvertTo-Json -Compress -Depth 4)
        }
      }
    }
  }
  $runKeys=@(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
  )
  foreach($rk in $runKeys){
    try{
      $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
      if($props){
        $props.PSObject.Properties | Where-Object {
          $_.MemberType -eq 'NoteProperty' -and ($_.Value -is [string]) -and ($_.Value -like ($FullPath + '*'))
        } | ForEach-Object {
          Remove-ItemProperty -Path $rk -Name $_.Name -Force -ErrorAction SilentlyContinue
          Write-Log ("Removed autorun {0} from {1}" -f $_.Name,$rk) 'INFO'
          $lines += ([pscustomobject]@{
            timestamp      = $ts
            host           = $HostName
            action         = 'remove_rogue_software'
            copilot_action = $true
            type           = 'startup_entry_removed'
            reg_path       = $rk
            value_name     = $_.Name
            value          = $_.Value
          } | ConvertTo-Json -Compress -Depth 4)
        }
      }
    }catch{}
  }
  $startup=@(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
  )
  foreach($sf in $startup){
    Get-ChildItem $sf -ErrorAction SilentlyContinue | Where-Object { $_.FullName -like ($FullPath + '*') } | ForEach-Object {
      try{
        Remove-Item $_.FullName -Force
        Write-Log ("Removed startup shortcut {0}" -f $_.FullName) 'INFO'
        $lines += ([pscustomobject]@{
          timestamp      = $ts
          host           = $HostName
          action         = 'remove_rogue_software'
          copilot_action = $true
          type           = 'startup_shortcut_removed'
          shortcut       = $_.FullName
        } | ConvertTo-Json -Compress -Depth 4)
      }catch{}
    }
  }
  $RegBases=@(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  )
  foreach ($regBase in $RegBases) {
    Get-ChildItem $regBase -ErrorAction SilentlyContinue | ForEach-Object {
      try {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $DisplayIcon = $props.DisplayIcon
        if ($DisplayIcon -and ($DisplayIcon -like ($FullPath + '*'))) {
          Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction Stop
          Write-Log ("Removed uninstall entry {0}" -f $_.PSChildName) 'INFO'
          $lines += ([pscustomobject]@{
            timestamp      = $ts
            host           = $HostName
            action         = 'remove_rogue_software'
            copilot_action = $true
            type           = 'reg_uninstall_removed'
            key            = $_.PSChildName
            base_path      = $regBase
            matched_icon   = $DisplayIcon
          } | ConvertTo-Json -Compress -Depth 4)
        }
      } catch {
        $lines += ([pscustomobject]@{
          timestamp      = $ts
          host           = $HostName
          action         = 'remove_rogue_software'
          copilot_action = $true
          type           = 'reg_uninstall_error'
          base_path      = $regBase
          error          = $_.Exception.Message
        } | ConvertTo-Json -Compress -Depth 4)
      }
    }
  }

  $q = $null
  try{
    $q = Quarantine-Path -FullPath $FullPath
    Write-Log ("Quarantined {0} -> {1}" -f $FullPath,$($q.QuarantineDir)) 'INFO'
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'remove_rogue_software'
      copilot_action = $true
      type           = 'quarantine_manifest'
      manifest_path  = $q.Manifest
      quarantine_dir = $q.QuarantineDir
    } | ConvertTo-Json -Compress -Depth 4)
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'remove_rogue_software'
      copilot_action = $true
      type           = 'quarantined'
      source         = $FullPath
      destination    = $q.QuarantineDir
    } | ConvertTo-Json -Compress -Depth 4)
  }catch{
    Write-Log ("Failed to quarantine {0}: {1}" -f $FullPath,$_.Exception.Message) 'ERROR'
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'remove_rogue_software'
      copilot_action = $true
      type           = 'quarantine_error'
      source         = $FullPath
      error          = $_.Exception.Message
    } | ConvertTo-Json -Compress -Depth 4)
  }
  $duration = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  $summary = [pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'remove_rogue_software'
    copilot_action = $true
    type           = 'summary'
    target         = $FullPath
    quarantine     = $true
    duration_s     = $duration
  }
  $lines = @(( $summary | ConvertTo-Json -Compress -Depth 5 )) + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch{
  Write-Log $_.Exception.Message 'ERROR'
  $err=[pscustomobject]@{
    timestamp      = Now-Timestamp
    host           = $HostName
    action         = 'remove_rogue_software'
    copilot_action = $true
    type           = 'error'
    target         = $TargetPath
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(( $err | ConvertTo-Json -Compress -Depth 4 )) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally{
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
