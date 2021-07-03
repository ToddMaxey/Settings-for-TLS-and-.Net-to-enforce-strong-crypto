#Cryptographic Settings v1.0
#By Todd Maxey


Write-Host " "
Write-Host "This will set .NETFramework v2.0.50727, .NETFramework v4.0.30319 to utilize strong cryptographic and force these version it use the machines cryptographic settings." -ForegroundColor Green
Write-Host " "
Write-Host "The WinHTTP setting will be set to use TLS 1.2" -ForegroundColor Green
Write-Host " "
Write-Host "It will also disabled SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, RC4 Ciphers and enabled TLS 1.2 and if this is a Windows 10 build 18362+ it will enabled TLS 1.3" -ForegroundColor Green
Write-Host " "
Write-Host "This script maakes registry changes! Be sure to have a backup of the machine before proceesing" -ForegroundColor Red
Write-Host " "
Write-Host "Pausing.... Hit Enter to continue or ctrl+c to escape" -ForegroundColor yellow
Read-host " "

#Initialization
$version = $Null
$SessionTime = (get-date -f dddd-MMMM-dd-yyyy-HH.mm.ss)
$FilePath = $path+$env:computername+" "+$SessionTime+".reg"
$path = "C:\temp\registry backups\"
$namenetwowframeworkv2 = "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727\" 
$namenetframeworkv2 = "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\"
$namenetwowframeworkv4 = "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319\" 
$namenetframeworkv4 = "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\"

#Determine of path exist and if not create path
If(!(test-path $path))
{
New-Item -ItemType Directory -Force -Path $path
}


# .Net settings to force Strong crypto and use system TLS settings

reg add $namenetwowframeworkv2+ /v SystemDefaultTlsVersions /t REG_DWORD /d 00000001 /f
reg add $namenetwowframeworkv2+ /v SchUseStrongCrypto /t REG_DWORD /d 00000001 /f
reg add $namenetframeworkv2+ /v SystemDefaultTlsVersions /t REG_DWORD /d 00000001 /f
reg add $namenetframeworkv2+ /v SchUseStrongCrypto /t REG_DWORD /d 00000001 /f
reg add $namenetwowframeworkv4+ /v SystemDefaultTlsVersions /t REG_DWORD /d 00000001 /f
reg add $namenetwowframeworkv4+ /v SchUseStrongCrypto /t REG_DWORD /d 00000001 /f
reg add $namenetframeworkv4+ /v SystemDefaultTlsVersions /t REG_DWORD /d 00000001 /f
reg add $namenetframeworkv4+ /v SchUseStrongCrypto /t REG_DWORD /d 00000001 /f



# Disable SSL 2.0, SSL 30, TLS 1.0 and TLS 1.1
# Enabled TLS 1.3 and if this is a Windows 10 build 10.0.18362+ enabled TLS 1.3

reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Client" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Client" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Client" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v Enabled /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v Enabled /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v DisabledByDefault /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v DisabledByDefault /t REG_DWORD /d 00000000 /f

# Disable Rc4

reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /v Enabled /t REG_DWORD /d 00000000 /f

#Get OS information
$version = [System.Environment]::OSVersion.Version

If (($version.Major -ige 10) -and ($version.Build -ige 18362)){
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v Enabled /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v Enabled /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /v DisabledByDefault /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v DisabledByDefault /t REG_DWORD /d 00000000 /f
}
{else Write-host "OS is not the right version for TLS 1.3"} 

#WinHttp setting to TLS 1.2
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v DefaultSecureProtocols /t REG_DWORD /d 0x800  /f

#Done
Write-Host " "
Write-Host "All Done - REBOOT, Pretty Please, with sugar on top..." -ForegroundColor Green
Write-Host " "