function Invoke-xcrypt {
  #.DESCRIPTION
  #  Creates a custom xcrypt object and Invokes methods on it.
  # .EXAMPLE
  #  "https://github.com" | xcrypt IsValidUrl
  # .NOTES
  #  If you want more control you can directly use the [xcrypt] class :)
  #.LINK
  #  https://github.com/chadnpc/cliHelper.xcrypt/blob/main/Public/Invoke-xcrypt.ps1
  [CmdletBinding()]
  [Alias('xcrypt')]
  [OutputType({ [xcrypt]::ReturnTypes })]
  param(
    [Parameter(Mandatory = $false, Position = 0)]
    [Alias('m')][ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
        [OutputType([System.Management.Automation.CompletionResult])]
        param(
          [string] $CommandName,
          [string] $ParameterName,
          [string] $WordToComplete,
          [System.Management.Automation.Language.CommandAst] $CommandAst,
          [System.Collections.IDictionary] $FakeBoundParameters
        )
        $CompletionResults = [System.Collections.Generic.List[CompletionResult]]::new()
        $matchingMethods = [xcrypt]::Methods.Where({ $_.Name -like "$WordToComplete*" -and $_.CustomAttributes.AttributeType.Name -notContains "HiddenAttribute" })
        foreach ($method in $matchingMethods) {
          $paramst = ($method.GetParameters() | Select-Object @{l = '_'; e = { "[$($_.ParameterType.Name)]`$$($_.Name)" } })._ -join ', '
          $toolTip = "[{0}] {1}({2})" -f $method.ReturnType.Name, $method.Name, $paramst
          $CompletionResults.Add([System.Management.Automation.CompletionResult]::new($method.Name, $toolTip, 'Method', $toolTip))
        }
        return $CompletionResults
      })]
    [string]$Method,

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('i')][ValidateNotNullOrEmpty()]
    $InputObject
  )
  begin {
    $result = $null
    $crypt = [xcrypt]::new()
  }
  process {
    $InvalidMethods = $Method.Where({ $_ -notin [xcrypt]::Methods.Name })
    if ($InvalidMethods.Count -gt 0) {
      $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
          [System.InvalidOperationException]::new("Please use valid method names. Methods ($($InvalidMethods -join ', ')) were not found.",
            [System.Management.Automation.MethodInvocationException]::new("")),
          "METHOD_NOT_FOUND",
          "InvalidArgument",
          $null
        )
      )
    }
    $result = $PSBoundParameters.ContainsKey("InputObject")? ($crypt::$Method($InputObject)) : $crypt::$Method()
  }
  end {
    return $result
  }
}
