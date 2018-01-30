Function New-DynamicParameter()
{
    [CmdletBinding(PositionalBinding=$false)]
    [OutputType([System.Management.Automation.RuntimeDefinedParameter])]
    param
    (
        [parameter(Mandatory=$true)]
        [string] $Name
        ,
        [parameter(Mandatory=$true)]
        [string[]] $ValidatedItems
        ,
        [hashtable] $Attributes
        ,
        [string[]] $Aliases
        ,
        [type] $RuntimeType = [type]::GetType("System.String")
    )
    $attCol = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $valSet = New-Object System.Management.Automation.ValidateSetAttribute($ValidatedItems)
    $attCol.Add($valSet) > $null
    if ($Attributes)
    {
        $pAtt = New-Object System.Management.Automation.ParameterAttribute -Property $Attributes
        $attCol.Add($pAtt) > $null
    }
    if ($Aliases)
    {
        $pAlias = New-Object System.Management.Automation.AliasAttribute($Aliases)
        $attCol.Add($pAlias) > $null
    }
    $rtParam = [System.Management.Automation.RuntimeDefinedParameter]::new($Name, $RuntimeType, $attCol)
    return $rtParam
}

Function New-DynamicDictionary()
{
    [CmdletBinding(PositionalBinding=$false)]
    [OutputType([System.Management.Automation.RuntimeDefinedParameterDictionary])]
    param
    (
        [parameter(Mandatory=$true)]
        [System.Management.Automation.RuntimeDefinedParameter[]] $Parameters
    )
    $rtDict = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    foreach ($p in $Parameters)
    {
        $rtDict.Add($p.Name, $p) > $null
    }
    return $rtDict
}

Function Get-PrivateKeyContainerPath()
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Name,
        [Parameter(Mandatory=$true,Position=1)]
        [bool] $IsCNG
    )
    if ($IsCNG)
    {
        $searchDirectories = ("Microsoft\Crypto\Keys","Microsoft\Crypto\SystemKeys")
    }
    else
    {
        $searchDirectories = ("Microsoft\Crypto\RSA\MachineKeys","Microsoft\Crypto\RSA\S-1-5-18","Microsoft\Crypto\RSA\S-1-5-19","Crypto\DSS\S-1-5-20")
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
    throw "Cannot find private key file path for key container ""$Name"""
}

Function New-WinRmException()
{
    [CmdletBinding(PositionalBinding=$false)]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param
    (
        [parameter(Mandatory)]
        [string] $Message,

        [parameter(Mandatory)]
        [string] $FQErrorId,

        [parameter(Mandatory)]
        [string] $TargetObject,

        [string] $HResult,

        [string] $ExitCode
    )
    $errExc = New-Object System.Exception($Message)
    if ((![String]::IsNullOrEmpty($HResult)) -and (![String]::IsNullOrEmpty($ExitCode)))
    {
        $errExc.Data.Add("ExitCode", $ExitCode)
        $errExc.Data.Add("HResult", $HResult)
    }
    return $([System.Management.Automation.ErrorRecord]::new($errExc, $FQErrorId, [System.Management.Automation.ErrorCategory]::InvalidOperation, $TargetObject))
}

Function Create-WinRmSslListener()
{
    <#
        .SYNOPSIS
            Automatically create an HTTPS WinRM Listener on a local computer.

        .DESCRIPTION
            This function creates a WinRM listener on its default port (5986).  If specified, it can also apply the necessary
            permissions for the Network Service to read the private key of the binding certificate, as well creating a new firewall
            rule to allow 5986 inbound traffic.
        
        .PARAMETER SHA1Thumbprint
            Mandatory.  Dynamic.  Specifies the thumbprint of the certificate used on the bound port.
        .PARAMETER NonInteractive
            Optional.  Switch.  Specifies that the command will run without prompting for input as well
            as suppressing any output except for returning the 'exit code' of the overall operation.
        .PARAMETER DontCreateFirewallRule
            Optional.  Switch.  Specifies that the function will not create a new firewall rule for TCP port 5986.
        .PARAMETER DontChangePrivateKeyPermissions
            Optional.  Switch.  Specifies that the function will not adjust the private key permissions that
            allow the 'NT AUTHORITY\NETWORK SERVICE' read access to the certificate's private key.
            
            *NOTE* - If you specify this, you must do this manually or in some other way otherwise remote connections
                     will fail to connect to the listener with '500' HTTP status codes.

        .INPUTS
            System.Security.Cryptography.X509Certificates.X509Certificate2
        .OUTPUTS
            <None>

        .EXAMPLE
            .\CreateWinRMListener-SSL.ps1 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        .EXAMPLE
            .\CreateWinRMListener-SSL.ps1 -SHA1Thumbprint XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        .EXAMPLE
            .\CreateWinRMListener-SSL.ps1 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX -NonInteractive
        .EXAMPLE

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
        $tprints = (Get-ChildItem -Path Cert:\LocalMachine\My).Thumbprint
        $dp = New-DynamicParameter -Name "SHA1Thumbprint" -ValidatedItems $tprints `
            -Aliases "Thumbprint" -Attributes @{ Mandatory = $false; Position = 0; ValueFromPipelineByPropertyName = $true }
        return $(New-DynamicDictionary -Parameters $dp)
    }
    Begin
    {
        # Make sure we're running in an elevated session.
        $myWinID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $myPrinID = New-Object System.Security.Principal.WindowsPrincipal($myWinID)
        $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
        if (!($myPrinID.IsInRole($adm)))
        {
            throw "This operation requires running with elevated permissions.  Please re-launch your shell with Administrator privileges."
        }
        $SHA1Thumbprint = $PSBoundParameters["SHA1Thumbprint"]
    }
    Process
    {

        if ((!$SHA1Thumbprint) -and (!$NonInteractive))
        {
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Select Thumbprint, FriendlyName, `
                @{N="Template";E={($_.Extensions | ?{$_.oid.FriendlyName -match 'Certificate Template Information'}).Format(0) -replace '^.*[=](.*)[(].*$', '$1'}}, `
                @{N="Subject";E={$_.SubjectName.Name}} | Out-GridView -Title "Choose a certificate for the binding:" -PassThru
            if (!$cert)
            {
                return 2
            }
            else
            {
                $SHA1Thumbprint=$cert.Thumbprint
            }
        }
        elseif ((!$SHA1Thumbprint) -and ($NonInteractive))
        {
            throw "You didn't specify a SHA1 Thumbprint in order for the script to run non-interactively!"
        }

        # The host name for the listener config is the cert's subject name (minus the 'CN=')
        $hn = (Get-ChildItem -Path Cert:\LocalMachine\My | ? Thumbprint -eq $SHA1Thumbprint).Subject.Replace('CN=','')

        $create=@('create')
        $create += "winrm/config/Listener`?Address=*+Transport=HTTPS"
        $create += "@{Hostname=`"$hn`";CertificateThumbprint=`"$SHA1Thumbprint`"}"
        $create = $create -join ' '
        $cProc = New-Object System.Diagnostics.Process
        $cProc.StartInfo.FileName = "$env:WINDIR\System32\winrm.cmd"
        $cProc.StartInfo.Arguments = $create
        $cProc.StartInfo.UseShellExecute = $false
        $cProc.StartInfo.RedirectStandardError = $true
        $cProc.StartInfo.CreateNoWindow = $true
        
        $cProc.Start() > $null; $cProc.WaitForExit()
        if ($cProc.StandardError.Read() -ne -1)
        {
            # An error happened, present the results.
            $flag=$false; while ($cProc.StandardError.Peek() -ge 0)
            {
                $line = $cProc.StandardError.ReadLine()
                if ($flag)
                {
                    $errMsg = $line
                }
                elseif ($line -like "Error number*")
                {
                    $code = $line
                    $flag=$true
                }
            }
            $m = [RegEx]::Match($code, "^Error\snumber:\s*(`?'exitcode'-[0-9]{1,10})\s*(`?'hresult'0x(`?:[0-9]){8})\s*`$")
            $extCode = $m.Groups["exitcode"].Value
            $hresult = $m.Groups["hresult"].Value
            throw $(New-WinRmException `
                -Message $errMsg `
                -FQErrorId $code `
                -TargetObject '$cProc.Start();' `
                -HResult $hresult `
                -ExitCode $extCode)
        }
        else
        {
            $set=@('set')
            $set += 'winrm/config/service'
            $set += "@{CertificateThumbprint=`"$SHA1Thumbprint`"}"
            $sProc = New-Object System.Diagnostics.Process
            $sProc.StartInfo.FileName = "$env:WINDIR\System32\winrm.cmd"
            $sProc.StartInfo.Arguments = $set -join ' '
            $sProc.StartInfo.CreateNoWindow=$true
            $sProc.StartInfo.RedirectStandardError=$true
            $sProc.StartInfo.UseShellExecute=$false

            $sProc.Start() > $null; $sProc.WaitForExit()
            if ($sProc.StandardError.Read() -ne -1)
            {
                $flag=$false; while ($cProc.StandardError.Peek() -ge 0)
                {
                    $line = $cProc.StandardError.ReadLine()
                    if ($flag)
                    {
                        $errMsg = $line
                    }
                    elseif ($line -like "Error number*")
                    {
                        $code = $line
                        $flag=$true
                    }
                }
                $m = [RegEx]::Match($code, "^Error\snumber:\s*(`?'exitcode'-[0-9]{1,10})\s*(`?'hresult'0x(`?:[0-9]){8})\s*`$")
                $extCode = $m.Groups["exitcode"].Value
                $hresult = $m.Groups["hresult"].Value
                throw $(New-WinRmException `
                    -Message $errMsg `
                    -FQErrorId $code `
                    -TargetObject '$sProc.Start();' `
                    -HResult $hresult `
                    -ExitCode $extCode)
            }
            else
            {
                if (!$DontChangePrivateKeyPermissions)
                {

                    $Certificate = Get-ChildItem "Cert:\LocalMachine\My\$SHA1Thumbprint"
                    if ([Security.Cryptography.X509Certificates.X509CertificateExtensionMethods]::HasCngKey($Certificate))
                    {
                        Write-Verbose "Private Key is CNG"
                        $privateKey = [Security.Cryptography.X509Certificates.X509Certificate2ExtensionMethods]::GetCngPrivateKey($Certificate)
                        $keyContainerName = $privateKey.UniqueName
                        $privateKeyPath = Get-PrivateKeyContainerPath $keyContainerName $true -ErrorAction Stop
                    }
                    elseif ($null -ne $Certificate.PrivateKey)
                    {
                        Write-Verbose "Private Key CSP is Legacy"
                        $privateKey = $Certificate.PrivateKey
                        $keyContainerName = $privateKey.CspKeyContainerInfo.UniqueKeyContainerName
                        $privateKeyPath = Get-PrivateKeyContainerPath $keyContainerName $false -ErrorAction Stop
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
                    Set-Acl $privateKeyPath $Acl
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
                }
                else
                {
                    return 0
                }
            }
        }
    }
}