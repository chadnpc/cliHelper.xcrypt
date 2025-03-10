function New-X509Certificate {
  [OutputType(([System.Security.Cryptography.X509Certificates.X509Certificate2]))]
  [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = '__runtime')]
  param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Subject,

    [Parameter(Mandatory = $false, Position = 1)]
    [datetime]$notBefore = [DateTime]::Now.AddDays(-1),

    [Parameter(Mandatory = $false, Position = 2)]
    [datetime]$notAfter = $NotBefore.AddDays(365),

    [Parameter(Mandatory = $false)]
    [Alias('Length', 'KeyLength')]
    [int]$keySizeInBits = 2048,


    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()][Alias('KU')]
    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]
    $KeyUsage = 0,

    [Parameter(Mandatory = $true, ParameterSetName = '__file')]
    [Alias('OutFile', 'OutPath', 'Out')]
    [string]$pfxFile,

    [Parameter(Mandatory = $true, ParameterSetName = '__file')]
    [SecureString]$Password,

    # [Parameter(Mandatory = $false)]
    # [Security.Cryptography.X509Certificates.X509ExtensionCollection]
    # $CustomExtension,

    # [Parameter(Mandatory = $false)]
    # # [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
    # [string]$SignatureAlgorithm = "SHA256",

    [KeyExportPolicy]$ExportPolicy
  )
  begin {
    $ErrorActionPreference = "Stop"
    if ($OSVersion.Major -lt 6) {
      throw [NotSupportedException]::new("Windows XP and Windows Server 2003 are not supported!")
    }
    #1. (string subject, System.IO.FileInfo pfxFile, securestring password, int keySizeInBits, datetime notBefore, datetime notAfter)
    #2. (string Subject, int keySizeInBits, int ValidForInDays, string StoreLocation, securestring Pin, string KeyExportPolicy, KeyProtection KeyProtection, string KeyUsage, string[] Extentions, bool IsCritical)
  }
  process {
    if ($PSCmdlet.ShouldProcess("Target", "Create SelfSignedCertificate")) {
    }
  }
}