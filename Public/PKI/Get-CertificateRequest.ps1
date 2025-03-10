function Get-CertificateRequest {
  [OutputType([System.Security.Cryptography.X509CertificateRequests.X509CertificateRequest])]
  [CmdletBinding(DefaultParameterSetName = '__fileName')]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = "__fileName")]
    [string]$Path,

    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "__rawData")]
    [Byte[]]$RawRequest
  )

  process {
    switch ($PsCmdlet.ParameterSetName) {
      "__fileName" {
        if ($(Get-Item $Path -ErrorAction Stop).PSProvider.Name -ne "FileSystem") {
          throw { "File either does not exist or not a file object" }
        }
        New-Object Security.Cryptography.X509CertificateRequests.X509CertificateRequest -ArgumentList (Resolve-Path $Path).ProviderPath
      }
      "__rawData" { New-Object Security.Cryptography.X509CertificateRequests.X509CertificateRequest -ArgumentList @(, $RawRequest) }
    }
  }
}