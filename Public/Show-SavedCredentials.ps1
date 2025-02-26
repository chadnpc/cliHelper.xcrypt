function Show-SavedCredentials {
  <#
    .SYNOPSIS
        Retreives All strored credentials from credential Manager, but no securestrings. (Just showing)
    .DESCRIPTION
        Retreives All strored credentials and returns a PsObject[]
    .NOTES
        This function is supported on windows only
    .LINK
        https://github.com/chadnpc/cliHelper.xcrypt/blob/main/Public/Show-SavedCredentials.ps1
    .EXAMPLE
        Show-SavedCredentials
    #>
  [CmdletBinding()]
  [outputType([PsObject[]])]
  [Alias('ShowCreds')]
  param ()

  end {
    return [CredentialManager]::get_StoredCreds();
  }
}
