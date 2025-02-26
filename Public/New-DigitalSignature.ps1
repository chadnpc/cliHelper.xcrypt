function New-DigitalSignature {
  <#
    .SYNOPSIS
    Creates a digital signature.

    .DESCRIPTION
    Generates a digital signature for a file using a private key.

    .PARAMETER FilePath
    The path to the file to be signed.

    .PARAMETER PrivateKeyPath
    The path to the private key file to use for signing.

    .PARAMETER SignatureOutputPath
    The path where the generated signature will be saved.

    .LINK
    https://github.com/chadnpc/cliHelper.xcrypt/blob/main/Public/New-DigitalSignature.ps1
    #>
  [CmdletBinding(SupportsShouldProcess = $true)]
  param (
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string]$PrivateKeyPath,

    [Parameter(Mandatory = $true)]
    [string]$SignatureOutputPath
  )

  begin {}

  process {
    if ($PSCmdlet.ShouldProcess("Target", "Operation")) {
      Write-Verbose ""
    }
  }

  end {}
}
