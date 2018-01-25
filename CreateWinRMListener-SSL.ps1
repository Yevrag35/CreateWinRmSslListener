<#
    .SYNOPSIS
        Automatically create an HTTPS WinRM Listener on a local computer.

    .DESCRIPTION
        Created:    5/21/2017
        Author:     Mike Garvey
        Copyright:  © 2017 Red Arrow Labs, LLC.  All rights reserved.

        This script is best viewed with an advanced text editor (e.g. - Notepad++, Visual Studio Code, etc.)

        ----------------------------------------------------------------

        Recommended that you have .NET Framework 3.5.1 w/ SP1 installed.  Minimum PowerShell version 2.0

        ----------------------------------------------------------------

        You must have already created the necessary certificate in order to use this script.  Running this along with specifying a SHA1 Thumbprint
        will create the HTTPS listener for the WinRM service, as well as creating the necessary firewall rule.

        This script can called easily by right-clicking and selecting "Run with PowerShell".  The script will re-launch as an elevated process if necessary.

    .INPUTS
        <None>
    .OUTPUTS
        <None>

    .EXAMPLE
        .\CreateWinRMListener-SSL.ps1 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    .EXAMPLE
        .\CreateWinRMListener-SSL.ps1 -SHA1Thumbprint XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    .EXAMPLE
        .\CreateWinRMListener-SSL.ps1 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX -NonInteractive
#>
[CmdletBinding(PositionalBinding=$false)]
param
(
    [switch]$NonInteractive
    ,
    [switch]$DontCreateFirewallRule
    ,
    [switch]$DontChangePrivateKeyPermissions
)
DynamicParam
{
    Import-Module .\DynamicParameter.dll
    $tprints = (gci Cert:\LocalMachine\My).Thumbprint
    $dynParam = New-Object Dynamic.DynamicParameter("SHA1Thumbprint", $tprints)
    $dynParam.RuntimeType = [string]
    $dynParam.Attributes = @{ Position = 0 }
    $dynParam.Aliases = "cert"
    return $($dynParam.Create())
}
Begin
{
    $SHA1Thumbprint = $PSBoundParameters["SHA1Thumbprint"]
}
Process
{
    Function Get-PrivateKeyContainerPath
    {
        [CmdletBinding(PositionalBinding=$false)]
        Param(
            [Parameter(Mandatory=$True)][string][ValidateNotNullOrEmpty()] $Name,
            [Parameter(Mandatory=$True)][boolean] $IsCNG
        )
        If ($IsCNG)
        {
            $searchDirectories = @("Microsoft\Crypto\Keys","Microsoft\Crypto\SystemKeys")
        }
        else
        {
            $searchDirectories = @("Microsoft\Crypto\RSA\MachineKeys","Microsoft\Crypto\RSA\S-1-5-18","Microsoft\Crypto\RSA\S-1-5-19","Crypto\DSS\S-1-5-20")
        }
        foreach ($searchDirectory in $searchDirectories)
        {
            $machineKeyDirectory = Join-Path -Path $([Environment]::GetFolderPath("CommonApplicationData")) -ChildPath $searchDirectory
            $privateKeyFile = Get-ChildItem -Path $machineKeyDirectory -Filter $Name -Recurse
            if ($null -ne $privateKeyFile)
            {
               return $privateKeyFile.FullName
            }
        }
        Throw "Cannot find private key file path for key container ""$Name"""
    }

    # Make sure script execution is elevated, if not re-launch with elevation.
    $curDir= Split-Path -Parent $MyInvocation.MyCommand.Definition
    $myWinID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myPrinID = New-Object System.Security.Principal.WindowsPrincipal($myWinID)
    $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    if (!($myPrinID.IsInRole($adm)))
    {
        $curScr= Split-Path $MyInvocation.MyCommand.Definition -Leaf
        $psArgs=@('-ExecutionPolicy','Bypass','-File')
        $psArgs += '"'+$curDir+'\'+$curScr+'"'
        if ($SHA1Thumbprint)
        {
            $psArgs += $SHA1Thumbprint
        }
        Start-Process powershell -ArgumentList $psArgs -Verb RunAs
        exit 5
    }

    if ((!$SHA1Thumbprint) -and (!$NonInteractive))
    {
		$cert = gci Cert:\LocalMachine\My | Select Thumbprint, FriendlyName, `
            @{N="Template";E={($_.Extensions | ?{$_.oid.FriendlyName -match 'Certificate Template Information'}).Format(0) -replace '^.*[=](.*)[(].*$', '$1'}}, `
            @{N="Subject";E={$_.SubjectName.Name}} | Out-GridView -Title "Choose a certificate for the binding:" -PassThru
        if (!$cert)
        {
            exit 2
        }
        else
        {
            $SHA1Thumbprint=$cert.Thumbprint
        }
	}
    elseif ((!$SHA1Thumbprint) -and ($NonInteractive))
    {
        Add-Content $curDir -Value "You didn't specify a SHA1 Thumbprint in order for the script to run non-interactively!" -Force
        throw "You didn't specify a SHA1 Thumbprint in order for the script to run non-interactively!"
    }

    $hn = (gci Cert:\LocalMachine\My | ? Thumbprint -eq $SHA1Thumbprint).Subject.Replace('CN=','')
    $create=@('create')
    $create += 'winrm/config/Listener?Address=*+Transport=HTTPS'
    $create += '@{Hostname="'+$hn+'";CertificateThumbprint="'+$SHA1Thumbprint+'"}'
    $cProc = Start-Process winrm -ArgumentList $create -NoNewWindow -Wait -PassThru
    if ($cProc.ExitCode -ne 0)
    {
        if (!$NonInteractive)
        {
            Write ""
            Write-Host "An error occurred creating the SSL Listener on port 5986! " -F Red
            Write ""
            Read-Host
        }
        exit 1
    }
    else
    {
        $set=@('set')
        $set += 'winrm/config/service'
        $set += '@{CertificateThumbprint="'+$SHA1Thumbprint+'"}'
        $sProc = Start-Process winrm -ArgumentList $set -NoNewWindow -Wait -PassThru
        if ($sProc.ExitCode -ne 0)
        {
            Write-Host "An error occurred while trying the WinRM service's thumbprint!" -F Red
            Write-Host "Reverting changes that were made... " -F Yellow -NoNewline
            $delete=@('delete')
            $delete += 'winrm/config/Listener?Address=*+Transport=HTTPS'
            $dProc = Start-Process winrm -ArgumentList $delete -Wait -PassThru
            if ($dProc.ExitCode -ne 0)
            {
                if (!$NonInteractive)
                {
                    Write-Host "ERROR!" -F Red -NoNewline
                    Write ""
                    Write-Host "Press enter to exit " -F Cyan -NoNewline
                    Read-Host
                }
                exit 1
            }
            else
            {
                if (!$NonInteractive)
                {
                    Write-Host "Success." -F Green -NoNewline
                    Write ""
                    Write-Host "Press enter to exit " -F Cyan -NoNewline
                    Read-Host
                }
                exit 0
            }
        }
        else
        {
            if (!$DontChangePrivateKeyPermissions)
            {
                $hash = "b580f6206001a98279a87b658aa3ff9fbb967e1aa96c1cb6f2ce4d9ae39c12994d82670f93c0786af7f7e0ae1ea3aec6"
                $dllPath = "$curDir\Security.Cryptography.dll"
                if (Test-Path $dllPath)
                {
                    $checkHash = @"
certutil -hashfile "$dllPath" SHA384
"@
                    $check = & cmd /c $checkHash
                    $check = $check[1]

                    if ($check -ne $hash)
                    {
                        throw "The Hash Algorithms for the Security.Cryptography.dll did not match.  Therefore, it's not trusted."
                    }
                    # Load the Assembly
                    [System.Reflection.Assembly]::LoadFile($dllPath)
                    $Certificate = Get-ChildItem "Cert:\LocalMachine\My\$SHA1Thumbprint"
                    if ([Security.Cryptography.X509Certificates.X509CertificateExtensionMethods]::HasCngKey($Certificate))
                    {
                        Write-Verbose "Private Key is CNG"
                        $privateKey = [Security.Cryptography.X509Certificates.X509Certificate2ExtensionMethods]::GetCngPrivateKey($Certificate)
                        $keyContainerName = $privateKey.UniqueName
                        $privateKeyPath = Get-PrivateKeyContainerPath -Name $keyContainerName -IsCNG $true
                    }
                    elseif ($null -ne $Certificate.PrivateKey)
                    {
                        Write-Verbose "Private Key CSP is Legacy"
                        $privateKey = $Certificate.PrivateKey
                        $keyContainerName = $privateKey.CspKeyContainerInfo.UniqueKeyContainerName
                        $privateKeyPath = Get-PrivateKeyContainerPath -Name $keyContainerName -IsCNG $false
                    }
                    else
                    {
                        throw "Certificate `"$($Certificate.GetNameInfo("SimpleName",$false))`" does not have a private key, or that key is inaccessible, therefore permission not granted"
                    }

                    # Grant the "Network Service" read access to the private key
                    $Acl = Get-Acl -Path $privateKeyPath
                    $permission = "NT AUTHORITY\NETWORK SERVICE", "Read", "Allow"
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
                    $Acl.AddAccessRule($rule)
                    Set-Acl $privateKeyPath $Acl -Verbose
                }

            }
            # Commit the changes by restarting the Remote Management service.
            Restart-Service winrm

            if (!$DontCreateFirewallRule)
            {
                $shArgs=@('advfirewall','firewall','add','rule')
                $shArgs += 'name="WinRM SSL"'
                $shArgs += @('dir=in','action=allow','enable=yes','profile=any','localport=5986','protocol=TCP','interfacetype=any')
                &netsh.exe $shArgs
            }
            if (!$NonInteractive)
            {
                Write-Host "The WinRM-HTTPS listener has been successfully created. " -F Green
                Write ""
                Write-Host "Press enter to exit " -F Cyan -NoNewline
                Read-Host
            }
            exit 0
        }
    }
}