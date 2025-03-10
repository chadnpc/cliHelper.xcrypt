function Get-ObjectIdentifier {
  [OutputType([Security.Cryptography.Oid2[]])]
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Value,
    [Security.Cryptography.OidGroupEnum]$Group,
    [switch]$UseActiveDirectory
  )
  if ($null -eq $Group) {
    [Security.Cryptography.Oid2]::GetAllOids($Value, $UseActiveDirectory)
  } else {
    New-Object Security.Cryptography.Oid2 -ArgumentList $Value, $Group, $UseActiveDirectory
  }
}