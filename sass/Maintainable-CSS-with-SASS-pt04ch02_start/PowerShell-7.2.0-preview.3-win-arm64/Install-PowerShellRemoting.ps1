# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#####################################################################################################
#
# Registers the WinRM endpoint for this instance of PowerShell.
#
# If the parameters '-PowerShellHome' were specified, it means that the script will be registering
# an instance of PowerShell from another instance of PowerShell.
#
# If no parameter is specified, it means that this instance of PowerShell is registering itself.
#
# Assumptions:
#     1. The CoreCLR and the the PowerShell assemblies are side-by-side in $PSHOME
#     2. Plugins are registered by version number. Only one plugin can be automatically registered
#        per PowerShell version. However, multiple endpoints may be manually registered for a given
#        plugin.
#
#####################################################################################################
[CmdletBinding(DefaultParameterSetName = "NotByPath")]
param
(
    [parameter(Mandatory = $true, ParameterSetName = "ByPath")]
    [switch]$Force,
    [string]
    $PowerShellHome
)

Set-StrictMode -Version 3.0

if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error "WinRM registration requires Administrator rights. To run this cmdlet, start PowerShell with the `"Run as administrator`" option."
    return
}
function Register-WinRmPlugin
{
    param
    (
        #
        # Expected Example:
        # %windir%\\system32\\PowerShell\\6.0.0\\pwrshplugin.dll
        #
        [string]
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $pluginAbsolutePath,

        #
        # Expected Example: powershell.6.0.0-beta.3
        #
        [string]
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $pluginEndpointName
    )

    $regKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Plugin\$pluginEndpointName"

    $pluginArchitecture = "64"
    if ($env:PROCESSOR_ARCHITECTURE -match "x86" -or $env:PROCESSOR_ARCHITECTURE -eq "ARM")
    {
        $pluginArchitecture = "32"
    }
    $regKeyValueFormatString = @"
<PlugInConfiguration xmlns="http://schemas.microsoft.com/wbem/wsman/1/config/PluginConfiguration" Name="{0}" Filename="{1}"
    SDKVersion="2" XmlRenderingType="text" Enabled="True" OutputBufferingMode="Block" ProcessIdleTimeoutSec="0" Architecture="{2}"
    UseSharedProcess="false" RunAsUser="" RunAsPassword="" AutoRestart="false">
    <InitializationParameters>
        <Param Name="PSVersion" Value="7.0"/>
    </InitializationParameters>
    <Resources>
        <Resource ResourceUri="http://schemas.microsoft.com/powershell/{0}" SupportsOptions="true" ExactMatch="true">
            <Security Uri="http://schemas.microsoft.com/powershell/{0}" ExactMatch="true"
            Sddl="O:NSG:BAD:P(A;;GA;;;BA)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)"/>
            <Capability Type="Shell"/>
        </Resource>
    </Resources>
    <Quotas IdleTimeoutms="7200000" MaxConcurrentUsers="5" MaxProcessesPerShell="15" MaxMemoryPerShellMB="1024" MaxShellsPerUser="25"
    MaxConcurrentCommandsPerShell="1000" MaxShells="25" MaxIdleTimeoutms="43200000"/>
</PlugInConfiguration>
"@
    $valueString = $regKeyValueFormatString -f $pluginEndpointName, $pluginAbsolutePath, $pluginArchitecture

    New-Item $regKey -Force > $null
    New-ItemProperty -Path $regKey -Name ConfigXML -Value $valueString > $null
}

function New-PluginConfigFile
{
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="Medium")]
    param
    (
        [string]
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $pluginFile,

        [string]
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $targetPsHomeDir
    )

    # This always overwrites the file with a new version of it if the
    # script is invoked multiple times.
    Set-Content -Path $pluginFile -Value "PSHOMEDIR=$targetPsHomeDir" -ErrorAction Stop
    Add-Content -Path $pluginFile -Value "CORECLRDIR=$targetPsHomeDir" -ErrorAction Stop

    Write-Verbose "Created Plugin Config File: $pluginFile" -Verbose
}

function Install-PluginEndpoint {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="Medium")]
    param (
        [Parameter()] [bool] $Force,
        [switch]
        $VersionIndependent
    )

    ######################
    #                    #
    # Install the plugin #
    #                    #
    ######################

    if (-not [String]::IsNullOrEmpty($PowerShellHome))
    {
        $targetPsHome = $PowerShellHome
        $targetPsVersion = & "$targetPsHome\pwsh" -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
    }
    else
    {
        ## Get the PSHome and PSVersion using the current powershell instance
        $targetPsHome = $PSHOME
        $targetPsVersion = $PSVersionTable.PSVersion.ToString()
    }
    Write-Verbose "PowerShellHome: $targetPsHome" -Verbose

    # For default, not tied to the specific version endpoint, we apply
    # only first number in the PSVersion string to the endpoint name.
    # Example name: 'PowerShell.6'.
    if ($VersionIndependent) {
        $dotPos = $targetPsVersion.IndexOf(".")
        if ($dotPos -ne -1) {
            $targetPsVersion = $targetPsVersion.Substring(0, $dotPos)
        }
    }

    Write-Verbose "Using PowerShell Version: $targetPsVersion" -Verbose

    $pluginEndpointName = "PowerShell.$targetPsVersion"

    $endPoint = Get-PSSessionConfiguration $pluginEndpointName -Force:$Force -ErrorAction silentlycontinue 2>&1

    # If endpoint exists and -Force parameter was not used, the endpoint would not be overwritten.
    if ($endpoint -and !$Force)
    {
        Write-Error -Category ResourceExists -ErrorId "PSSessionConfigurationExists" -Message "Endpoint $pluginEndpointName already exists."
        return
    }

    if (!$PSCmdlet.ShouldProcess($pluginEndpointName)) {
        return
    }

    if ($PSVersionTable.PSVersion -lt "6.0")
    {
        # This script is primarily used from Windows PowerShell for Win10 IoT and NanoServer to setup PSCore6 remoting endpoint
        # so it's ok to hardcode to 'C:\Windows' for those systems
        $pluginBasePath = Join-Path "C:\Windows\System32\PowerShell" $targetPsVersion
    }
    else
    {
        $pluginBasePath = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows) + "\System32\PowerShell") $targetPsVersion
    }

    $resolvedPluginAbsolutePath = ""
    if (! (Test-Path $pluginBasePath))
    {
        Write-Verbose "Creating $pluginBasePath"
        $resolvedPluginAbsolutePath = New-Item -Type Directory -Path $pluginBasePath
    }
    else
    {
        $resolvedPluginAbsolutePath = Resolve-Path $pluginBasePath
    }

    $pluginPath = Join-Path $resolvedPluginAbsolutePath "pwrshplugin.dll"

    # This is forced to ensure the the file is placed correctly
    Copy-Item $targetPsHome\pwrshplugin.dll $resolvedPluginAbsolutePath -Force -Verbose -ErrorAction Stop

    $pluginFile = Join-Path $resolvedPluginAbsolutePath "RemotePowerShellConfig.txt"
    New-PluginConfigFile $pluginFile (Resolve-Path $targetPsHome)

    # Register the plugin
    Register-WinRmPlugin $pluginPath $pluginEndpointName

    ####################################################################
    #                                                                  #
    # Validations to confirm that everything was registered correctly. #
    #                                                                  #
    ####################################################################

    if (! (Test-Path $pluginFile))
    {
        throw "WinRM Plugin configuration file not created. Expected = $pluginFile"
    }

    if (! (Test-Path $resolvedPluginAbsolutePath\pwrshplugin.dll))
    {
        throw "WinRM Plugin DLL missing. Expected = $resolvedPluginAbsolutePath\pwrshplugin.dll"
    }

    try
    {
        Write-Host "`nGet-PSSessionConfiguration $pluginEndpointName" -ForegroundColor "green"
        Get-PSSessionConfiguration $pluginEndpointName -ErrorAction Stop
    }
    catch [Microsoft.PowerShell.Commands.WriteErrorException]
    {
        throw "No remoting session configuration matches the name $pluginEndpointName."
    }
}

Install-PluginEndpoint -Force $Force
Install-PluginEndpoint -Force $Force -VersionIndependent

Write-Host "Restarting WinRM to ensure that the plugin configuration change takes effect.`nThis is required for WinRM running on Windows SKUs prior to Windows 10." -ForegroundColor Magenta
Restart-Service winrm


# SIG # Begin signature block
# MIIjgwYJKoZIhvcNAQcCoIIjdDCCI3ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCfOFoH3rP/kr2E
# 0Q4vJtNjsECNzfLCg+aNt7OyJJ4h56CCDYEwggX/MIID56ADAgECAhMzAAABh3IX
# chVZQMcJAAAAAAGHMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAwMzA0MTgzOTQ3WhcNMjEwMzAzMTgzOTQ3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOt8kLc7P3T7MKIhouYHewMFmnq8Ayu7FOhZCQabVwBp2VS4WyB2Qe4TQBT8aB
# znANDEPjHKNdPT8Xz5cNali6XHefS8i/WXtF0vSsP8NEv6mBHuA2p1fw2wB/F0dH
# sJ3GfZ5c0sPJjklsiYqPw59xJ54kM91IOgiO2OUzjNAljPibjCWfH7UzQ1TPHc4d
# weils8GEIrbBRb7IWwiObL12jWT4Yh71NQgvJ9Fn6+UhD9x2uk3dLj84vwt1NuFQ
# itKJxIV0fVsRNR3abQVOLqpDugbr0SzNL6o8xzOHL5OXiGGwg6ekiXA1/2XXY7yV
# Fc39tledDtZjSjNbex1zzwSXAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUhov4ZyO96axkJdMjpzu2zVXOJcsw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU4Mzg1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAixmy
# S6E6vprWD9KFNIB9G5zyMuIjZAOuUJ1EK/Vlg6Fb3ZHXjjUwATKIcXbFuFC6Wr4K
# NrU4DY/sBVqmab5AC/je3bpUpjtxpEyqUqtPc30wEg/rO9vmKmqKoLPT37svc2NV
# BmGNl+85qO4fV/w7Cx7J0Bbqk19KcRNdjt6eKoTnTPHBHlVHQIHZpMxacbFOAkJr
# qAVkYZdz7ikNXTxV+GRb36tC4ByMNxE2DF7vFdvaiZP0CVZ5ByJ2gAhXMdK9+usx
# zVk913qKde1OAuWdv+rndqkAIm8fUlRnr4saSCg7cIbUwCCf116wUJ7EuJDg0vHe
# yhnCeHnBbyH3RZkHEi2ofmfgnFISJZDdMAeVZGVOh20Jp50XBzqokpPzeZ6zc1/g
# yILNyiVgE+RPkjnUQshd1f1PMgn3tns2Cz7bJiVUaqEO3n9qRFgy5JuLae6UweGf
# AeOo3dgLZxikKzYs3hDMaEtJq8IP71cX7QXe6lnMmXU/Hdfz2p897Zd+kU+vZvKI
# 3cwLfuVQgK2RZ2z+Kc3K3dRPz2rXycK5XCuRZmvGab/WbrZiC7wJQapgBodltMI5
# GMdFrBg9IeF7/rP4EqVQXeKtevTlZXjpuNhhjuR+2DMt/dWufjXpiW91bo3aH6Ea
# jOALXmoxgltCp1K7hrS6gmsvj94cLRf50QQ4U8Qwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWDCCFVQCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAYdyF3IVWUDHCQAAAAABhzAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgLfWQi/ze
# +cXovmP0gw6jnMoukGSvn9pnSi9vn/71n5swQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQC+zUqNoO8+sw2JnjEs2x7bJNYBWnpnBUgKciqJAILC
# y+wco1aMWOi1sFx3OPiq8pIfSmdDet9OHLkvMFk2zR4+/BiocGoEmWXeYmkz7Igq
# CBaAVq4D2mhcbOHz7YGfv31L9FMih0tLmwqmld2K5h2ewiA0q7mCRP0zBleR+IXf
# ZyN+DeslSDMXiuPrMPfT4MdPOn8N3rqhUYfieAkdMphpuDO9pLvKyV9ImNBg045p
# 73hZbfXF3jo1Gc/GSNAMvbrKGrhcEQ3yuM7H6fH8u7vrK9HOjM0dr4lDYCz+ghzr
# plJ04EBt/JBdKiuY1CCb+on9UQ37ZwZQCxtuothsZqo9oYIS4jCCEt4GCisGAQQB
# gjcDAwExghLOMIISygYJKoZIhvcNAQcCoIISuzCCErcCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIE0bad+t7mYqugPKJ1nxarCgdH/XKD/TcfwbqBot
# l44aAgZgGOevqAMYEzIwMjEwMjEwMDgxOTM5LjUyOVowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkFFMkMtRTMyQi0xQUZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOOTCCBPEwggPZoAMCAQICEzMAAAFIoohFVrwvgL8AAAAAAUgw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjAxMTEyMTgyNTU2WhcNMjIwMjExMTgyNTU2WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046QUUyQy1FMzJCLTFB
# RkMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD3/3ivFYSK0dGtcXaZ8pNLEARbraJe
# wryi/JgbaKlq7hhFIU1EkY0HMiFRm2/Wsukt62k25zvDxW16fphg5876+l1wYnCl
# ge/rFlrR2Uu1WwtFmc1xGpy4+uxobCEMeIFDGhL5DNTbbOisLrBUYbyXr7fPzxbV
# kEwJDP5FG2n0ro1qOjegIkLIjXU6qahduQxTfsPOEp8jgqMKn++fpH6fvXKlewWz
# dsfvhiZ4H4Iq1CTOn+fkxqcDwTHYkYZYgqm+1X1x7458rp69qjFeVP3GbAvJbY3b
# Flq5uyxriPcZxDZrB6f1wALXrO2/IdfVEdwTWqJIDZBJjTycQhhxS3i1AgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUhzLwaZ8OBLRJH0s9E63pIcWJokcwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAZhKWwbMnC9Qywcrlgs0qX9bhxiZGve+8JED27hOi
# yGa8R9nqzHg4+q6NKfYXfS62uMUJp2u+J7tINUTf/1ugL+K4RwsPVehDasSJJj+7
# boIxZP8AU/xQdVY7qgmQGmd4F+c5hkJJtl6NReYE908Q698qj1mDpr0Mx+4LhP/t
# TqL6HpZEURlhFOddnyLStVCFdfNI1yGHP9n0yN1KfhGEV3s7MBzpFJXwOflwgyE9
# cwQ8jjOTVpNRdCqL/P5ViCAo2dciHjd1u1i1Q4QZ6xb0+B1HdZFRELOiFwf0sh3Z
# 1xOeSFcHg0rLE+rseHz4QhvoEj7h9bD8VN7/HnCDwWpBJTCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAsswggI0AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpBRTJDLUUzMkItMUFG
# QzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAhyuClrocWf4SIcRafAEX1Rhs6zmggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOPN8dgwIhgPMjAy
# MTAyMTAxMzQ3MDRaGA8yMDIxMDIxMTEzNDcwNFowdDA6BgorBgEEAYRZCgQBMSww
# KjAKAgUA483x2AIBADAHAgEAAgIRHDAHAgEAAgIRLDAKAgUA489DWAIBADA2Bgor
# BgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAID
# AYagMA0GCSqGSIb3DQEBBQUAA4GBAFx84NTBxou4vI8GbyUJKfAXykOQU6und9i3
# XaEiLj0699rk/oSyBPsXLFzKzL/C5ow204zgV1C5KN+E29DcrGDROc2R1y/4w/JH
# JWgNtXBD+AE6PlOg6BwlGwqgDhSkY/NPV5KbWKtQaNewkk095Nh8/QTNx+wTHV4w
# cSnfiNTRMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAFIoohFVrwvgL8AAAAAAUgwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqG
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgWZAzfz0l6q48
# v7jM+6SP3f4UkL8pQ9REmPqrNHp8vFMwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
# MIG9BCCpkBrqjHmhvyYf5tTcTvD5Y4a+V79TwVV6T1aAwdto2DCBmDCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABSKKIRVa8L4C/AAAAAAFI
# MCIEIPQ5mwkPeW/+pZ8wOKzkS0WkJRzX3BLI7w0l4QyEemeKMA0GCSqGSIb3DQEB
# CwUABIIBAERpSNwznew9PgxhNPlW6oCYYvAMFLPMtltZRT4z5EcE3V0SWphn6ufF
# eEJ3j4S4arUAj1A1W2j6en3hGV8Qo74KN/Rs16KG43gsyeoUFD0BsB6atHILChSv
# TujWRatiknhHAHBcXryBu6D712E3m4RAqgSPRHNjPH6slhH8noopHdIz1uGCJ2MW
# Sa0furJec6mTGrHuDeMT9evcDzM9DxU3LlRUZ9YAtIbDKG0yH5KmMUHgvTZPxaaF
# 7/hnFadvZvdxPA1vHs4jOH0wGVNNurw6vmuBZJ+Y09qnBOozS390N8AvXcAjoSGv
# 8pUDDQNyhCQHoe+O1lmxQ3/0RFfK5uE=
# SIG # End signature block
