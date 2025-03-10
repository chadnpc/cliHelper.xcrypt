﻿
#!/usr/bin/env pwsh
using namespace System.IO
using namespace System.Web
using namespace System.Text
using namespace System.Net.Http
using namespace System.Security
using namespace System.Reflection
using namespace System.Reflection.Emit
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices
using namespace System.Security.Cryptography.X509Certificates

#Requires -PSEdition Core
#Requires -Modules cliHelper.xconvert

#region    enums

enum EncryptionScope {
  User    # The encrypted data can be decrypted with the same user on any machine.
  Machine # The encrypted data can only be decrypted with the same user on the same machine it was encrypted on.
}

enum keyStoreMode {
  Vault
  KeyFile
  SecureString
}
enum KeyExportPolicy {
  NonExportable
  ExportableEncrypted
  Exportable
}
enum KeyProtection {
  None
  Protect
  ProtectHigh
  ProtectFingerPrint
}
enum KeyUsage {
  None
  CRLSign
  CertSign
  EncipherOnly
  KeyAgreement
  DataEncipherment
  KeyEncipherment
  NonRepudiation
  DigitalSignature
  DecipherOnly
}
enum X509ContentType {
  Unknown
  Cert
  SerializedCert
  Pfx
  PEM
  Pkcs12
  SerializedStore
  Pkcs7
  Authenticode
}

enum ECCurveName {
  ansix9p256r1
  ansix9p384r1
  ansix9p521r1
  brainpoolP256r1
  brainpoolP384r1
  brainpoolP512r1
  nistP256
  nistP384
  nistP521
  secp256k1
}

enum SdCategory {
  Token
  Password
}
enum ExpType {
  Milliseconds
  Years
  Months
  Days
  Hours
  Minutes
  Seconds
}
enum CertStoreName {
  MY
  ROOT
  TRUST
  CA
}
# Only Encryption algorithms that are widely trusted and used in real-world
enum CryptoAlgorithm {
  AesGCM # AES-GCM (Galois/Counter Mode). A strong encryption on its own that doesn't necessarily with its built-in authentication functions. Its a mode of operation for AES that provides both confidentiality and authenticity for the encrypted data. GCM provides faster encryption and decryption compared to CBC mode and is widely used for secure communication, especially in VPN and TLS/SSL apps.
  ChaCha20 # ChaCha20 + SHA256 in this case. I would prefer ChaCha20Poly1305 but the Poly1305 class is still not working/usable. But no wories, ChaCha20 is like the salsa of the cryptography world, it's got the moves to keep your data secure and grooving to its own beat! :) Get it? [ref] to the dance-like steps performed in the algorithm's mixing process? Nevermind ... Its a symmetric key encryption algorithm, based on salsa20 algorithm. ChaCha20 provides the encryption, while Poly1305 (or SHA256 in this case) provides the authentication. This combination provides both confidentiality and authenticity for the encrypted data.
  RsaAesHMAC # RSA + AES + HMAC: This combination uses RSA for key exchange, AES for encryption, and HMAC (hash-based message authentication code) for authentication. This provides a secure mechanism for exchanging keys and encrypting data, as well as a way to verify the authenticity of the data. ie: By combining RSA and AES, one can take advantage of both algorithms' strengths: RSA is used to securely exchange the AES key, while AES is be used for the actual encryption and decryption of the data. This way, RSA provides security for key exchange, and AES provides fast encryption and decryption for the data.
  RsaECDSA # RSA + ECDSA (Elliptic Curve Digital Signature Algorithm) are public-key cryptography algorithms that are often used together. RSA can be used for encrypting data, while ECDSA can be used for digital signatures, providing both confidentiality and authenticity for the data.
  RsaOAEP # RSA-OAEP (Optimal Asymmetric Encryption Padding)
}
# System.Security.Cryptography.RSAEncryptionPadding Names
enum RSAPadding {
  Pkcs1
  OaepSHA1
  OaepSHA256
  OaepSHA384
  OaepSHA512
}

enum Compression {
  Gzip
  Deflate
  ZLib
  # Zstd # Todo: Add Zstandard. (The one from facebook. or maybe zstd-sharp idk. I just can't find a way to make it work in powershell! no dll nothing!)
}

enum CredFlags {
  None = 0x0
  PromptNow = 0x2
  UsernameTarget = 0x4
}

enum CredType {
  Generic = 1
  DomainPassword = 2
  DomainCertificate = 3
  DomainVisiblePassword = 4
  GenericCertificate = 5
  DomainExtended = 6
  Maximum = 7
  MaximumEx = 1007 # (Maximum + 1000)
}

enum CredentialPersistence {
  Session = 1
  LocalComputer = 2
  Enterprise = 3
}

#endregion enums

class InvalidArgumentException : System.Exception {
  [string]$paramName
  [string]$Message
  InvalidArgumentException() {
    $this.message = 'Invalid argument'
  }
  InvalidArgumentException([string]$paramName) {
    $this.paramName = $paramName
    $this.message = "Invalid argument: $paramName"
  }
  InvalidArgumentException([string]$paramName, [string]$message) {
    $this.paramName = $paramName
    $this.message = $message
  }
}

# Static class for calling the native credential functions
class CredentialNotFoundException : System.Exception, System.Runtime.Serialization.ISerializable {
  [string]$Message; [Exception]$InnerException; hidden $Info; hidden $Context
  CredentialNotFoundException() { $this.Message = 'CredentialNotFound' }
  CredentialNotFoundException([string]$message) { $this.Message = $message }
  CredentialNotFoundException([string]$message, [Exception]$InnerException) { ($this.Message, $this.InnerException) = ($message, $InnerException) }
  CredentialNotFoundException([System.Runtime.Serialization.SerializationInfo]$info, [Runtime.Serialization.StreamingContext]$context) { ($this.Info, $this.Context) = ($info, $context) }
}
class IntegrityCheckFailedException : System.Exception {
  [string]$Message; [Exception]$InnerException;
  IntegrityCheckFailedException() { }
  IntegrityCheckFailedException([string]$message) { $this.Message = $message }
  IntegrityCheckFailedException([string]$message, [Exception]$innerException) { $this.Message = $message; $this.InnerException = $innerException }
}
class InvalidPasswordException : System.Exception {
  [string]$Message; [string]hidden $Passw0rd; [securestring]hidden $Password; [Exception]$InnerException
  InvalidPasswordException() { $this.Message = "Invalid password" }
  InvalidPasswordException([string]$Message) { $this.message = $Message }
  InvalidPasswordException([string]$Message, [string]$Passw0rd) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, [Exception]::new($Message)) }
  InvalidPasswordException([string]$Message, [securestring]$Password) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, [Exception]::new($Message)) }
  InvalidPasswordException([string]$Message, [string]$Passw0rd, [Exception]$InnerException) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, $InnerException) }
  InvalidPasswordException([string]$Message, [securestring]$Password, [Exception]$InnerException) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, $InnerException) }
}

class cPsObject : PsObject {
  cPsObject([System.Object]$Object) {
    $types = (($Object | Get-Member).Typename | Sort-Object -Unique)
    $ogtyp = if ($types.count -eq 1) { $types -as 'type' } else { $Object.GetType() }
    $b64sb = [convert]::ToBase64String($(if ($types.Equals("System.Byte")) { [byte[]]$Object } else { $Object | xconvert ToBytes }))
    $this.PsObject.properties.add([psscriptproperty]::new('Type', [scriptblock]::Create("[Type]'$ogtyp'")))
    $this.PsObject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$b64sb')")))
    $this.PsObject.properties.add([psscriptproperty]::new('SecScope', [scriptblock]::Create('[EncryptionScope]::User')))
    $this.PsObject.Methods.Add(
      [psscriptmethod]::new(
        'Protect', {
          $_bytes = $this.Bytes; $Entropy = [Encoding]::UTF8.GetBytes([xcrypt]::GetUniqueMachineId())[0..15]
          $_bytes = Protect-Data -Bytes $_bytes -Scope $this.SecScope -Entropy $Entropy
          $this.PsObject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create($_bytes)))
        }
      )
    )
    $this.PsObject.Methods.Add(
      [psscriptmethod]::new(
        'UnProtect', {
          $_bytes = $this.Bytes; $Entropy = [Encoding]::UTF8.GetBytes([xcrypt]::GetUniqueMachineId())[0..15]
          $_bytes = UnProtect-Data -Bytes $_bytes -Entropy $Entropy -Scope $this.SecScope
          $this.PsObject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create($_bytes)))
        }
      )
    )
    $this.PsObject.Methods.Add(
      [psscriptmethod]::new(
        'Tostring', {
          return $this.PsObject.properties.value[0].name
        }
      )
    )
  }
}

#region    xcrypt
# .SYNOPSIS
#   xtended cryptography helper class
class xcrypt {
  static [string] $caller
  static [byte[]] $counter
  static [EncryptionScope] $Scope = 'User'
  static [Type[]] $ReturnTypes = ([xcrypt]::Methods.ReturnType | Sort-Object -Unique Name)
  static [MethodInfo[]] $Methods = ([xcrypt].GetMethods().Where({ $_.IsStatic -and !$_.IsHideBySig }))

  static hidden [ValidateNotNull()][byte[]] $_salt = [Convert]::FromBase64String( 'bz07LmY5XiNkXW1WQjxdXw==')
  static hidden [ValidateNotNull()][byte[]] $_bytes
  static hidden [ValidateNotNull()][securestring] $_Password
  static hidden [ValidateNotNull()][CryptoAlgorithm] $_Algorithm
  xcrypt() {}

  static [string] GetRandomName() {
    return [xcrypt]::GetRandomName((Get-Random -min 16 -max 80));
  }
  static [string] GetRandomName([int]$Length) {
    return [string][xcrypt]::GetRandomName($Length, $Length);
  }
  static [string] GetRandomName([bool]$IncludeNumbers) {
    $Length = Get-Random -min 16 -max 80
    return [string][xcrypt]::GetRandomName($Length, $Length, $IncludeNumbers);
  }
  static [string] GetRandomName([int]$Length, [bool]$IncludeNumbers) {
    return [string][xcrypt]::GetRandomName($Length, $Length, $IncludeNumbers);
  }
  static [string] GetRandomName([int]$minLength, [int]$maxLength) {
    return [string][xcrypt]::GetRandomName($minLength, $maxLength, $false);
  }
  static [string] GetRandomName([int]$minLength, [int]$maxLength, [bool]$IncludeNumbers) {
    [int]$iterations = 2; $MinrL = 3; $MaxrL = 999 #Gotta have some restrictions, or one typo could slow down an entire script.
    if ($minLength -lt $MinrL) { Write-Warning "Length is below the Minimum required 'String Length'. Try $MinrL or greater." ; Break }
    if ($maxLength -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'String Length'. Try $MaxrL or lower." ; Break }
    $samplekeys = if ($IncludeNumbers) {
      [string]::Join('', ([int[]](97..122) | ForEach-Object { [string][char]$_ }) + (0..9))
    } else {
      [string]::Join('', ([int[]](97..122) | ForEach-Object { [string][char]$_ }))
    }
    return [string][xcrypt]::GetRandomSTR($samplekeys, $iterations, $minLength, $maxLength);
  }
  static [byte[]] GetRfc2898DeriveBytes() {
    return [xcrypt]::GetRfc2898DeriveBytes(16)
  }
  static [byte[]] GetRfc2898DeriveBytes([int]$Length) {
    return [xcrypt]::GetRfc2898DeriveBytes(([xcrypt]::GetRandomName(16) | xconvert ToSecurestring), $Length)
  }
  static [byte[]] GetRfc2898DeriveBytes([securestring]$password) {
    return [xcrypt]::GetRfc2898DeriveBytes($password, 16)
  }
  static [byte[]] GetRfc2898DeriveBytes([securestring]$password, [int]$Length) {
    return [xcrypt]::GetRfc2898DeriveBytes(
      [xconvert]::ToSecurestring([xcrypt]::Scope.Equals([EncryptionScope]::User) ? [convert]::FromBase64String("hsKgmva9wZoDxLeREB1udw==") : [Encoding]::UTF8.GetBytes([xcrypt]::GetUniqueMachineId())),
      [Rfc2898DeriveBytes]::new($password, [Encoding]::UTF8.GetBytes(($password | xconvert ToString))).GetBytes(16),
      $Length
    )
  }
  static [byte[]] GetRfc2898DeriveBytes([securestring]$password, [byte[]]$salt, [int]$Length) {
    return [Rfc2898DeriveBytes]::new($password, $salt, 1000).GetBytes($Length);
  }
  static [byte[]] GetKey() {
    return [xcrypt]::GetKey(16);
  }
  static [byte[]] GetKey([int]$Length) {
    return [xcrypt]::GetKey(([xcrypt]::GeneratePassword() | xconvert ToSecurestring), $Length)
  }
  static [byte[]] GetKey([securestring]$password) {
    return [xcrypt]::GetKey($password, 16)
  }
  static [byte[]] GetKey([securestring]$password, [int]$Length) {
    return [xcrypt]::GetRfc2898DeriveBytes($password, $Length)
  }
  static [byte[]] GetKey([securestring]$password, [byte[]]$salt) {
    return [xcrypt]::GetKey($password, $salt, 16)
  }
  static [byte[]] GetKey([securestring]$password, [byte[]]$salt, [int]$Length) {
    return [xcrypt]::GetRfc2898DeriveBytes($password, $salt, $Length)
  }
  # can be used to generate random IV
  static [byte[]] GetRandomEntropy() {
    [byte[]]$entropy = [byte[]]::new(16);
    [void][RNGCryptoServiceProvider]::new().GetBytes($entropy)
    return $entropy;
  }
  static [string] GetRandomSTR([string]$InputSample, [int]$Length) {
    return [xcrypt]::GetRandomSTR($InputSample, 3, $Length, $Length)
  }
  static [string] GetRandomSTR([string]$InputSample, [int]$iterations, [int]$Length) {
    return [xcrypt]::GetRandomSTR($InputSample, $iterations, $Length, $Length)
  }
  static [string] GetRandomSTR([string]$InputSample, [int]$iterations, [int]$minLength, [int]$maxLength) {
    # Uses a cryptographic hash function (SHA-256) to generate a unique machine ID
    if ($maxLength -lt $minLength) { throw [ArgumentOutOfRangeException]::new('MinLength', "'MaxLength' cannot be less than 'MinLength'") }
    if ($iterations -le 0) { throw [InvalidOperationException]::new('Negative and Zero Iterations are NOT Possible!') }
    [char[]]$chars = [char[]]::new($InputSample.Length);
    $chars = $InputSample.ToCharArray();
    $Keys = [Collections.Generic.List[string]]::new();
    $rand = [Random]::new();
    [int]$size = $rand.Next([int]$minLength, [int]$maxLength);
    for ($i = 0; $i -lt $iterations; $i++) {
      [byte[]] $data = [Byte[]]::new(1);
      $crypto = [RNGCryptoServiceProvider]::new();
      $data = [Byte[]]::new($size);
      $crypto.GetNonZeroBytes($data);
      $result = [StringBuilder]::new($size);
      foreach ($b In $data) { $result.Append($chars[$b % ($chars.Length - 1)]) };
      [void]$Keys.Add($result.ToString());
    }
    $STR = [string]::Join('', $keys)
    if ($STR.Length -gt $maxLength) {
      $STR = $STR.Substring(0, $maxLength);
    }
    return $STR;
  }
  static [string] GeneratePassword() {
    return [string][xcrypt]::GeneratePassword(19);
  }
  static [string] GeneratePassword([int]$Length) {
    return [string][xcrypt]::GeneratePassword($Length, $false, $false, $false, $false);
  }
  static [string] GeneratePassword([int]$Length, [bool]$StartWithLetter) {
    return [string][xcrypt]::GeneratePassword($Length, $StartWithLetter, $false, $false, $false);
  }
  static [string] GeneratePassword([int]$Length, [bool]$StartWithLetter, [bool]$NoSymbols, [bool]$UseAmbiguousCharacters, [bool]$UseExtendedAscii) {
    # https://stackoverflow.com/questions/55556/characters-to-avoid-in-automatically-generated-passwords
    [string]$possibleCharacters = [char[]](33..126 + 161..254); $MinrL = 14; $MaxrL = 999 # Gotta have some restrictions, or one typo could endup creating insanely long or small Passwords, ex 30000 intead of 30.
    if ($Length -lt $MinrL) { Write-Warning "Length is below the Minimum required 'Password Length'. Try $MinrL or greater."; Break }
    if ($Length -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'Password Length'. Try $MaxrL or lower."; Break }
    # Warn the user if they've specified mutually-exclusive options.
    if ($NoSymbols -and $UseExtendedAscii) { Write-Warning 'The -NoSymbols parameter was also specified.  No extended ASCII characters will be used.' }
    do {
      $Passw0rd = [string]::Empty; $x = $null; $r = 0
      #This person Wants a really good password, so We retry Until we get a 60% strong password.
      do {
        do {
          do {
            do {
              do {
                $x = [int][char][string][xcrypt]::GetRandomSTR($possibleCharacters, 1, 1, 1);
                # Write-Verbose "Use character: $([char]$x) : $x"
              } While ($x -eq 127 -Or (!$UseExtendedAscii -and $x -gt 127))
              # The above Do..While loop does this:
              #  1. Don't allow ASCII 127 (delete).
              #  2. Don't allow extended ASCII, unless the user wants it.
            } While (!$UseAmbiguousCharacters -and ($x -In @(49, 73, 108, 124, 48, 79)))
            # The above loop disallows 1 (ASCII 49), I (73), l (108),
            # | (124), 0 (48) or O (79) -- unless the user wants those.
          } While ($NoSymbols -and ($x -lt 48 -Or ($x -gt 57 -and $x -lt 65) -Or ($x -gt 90 -and $x -lt 97) -Or $x -gt 122))
          # If the -NoSymbols parameter was specified, this loop will ensure
          # that the character is neither a symbol nor in the extended ASCII
          # character set.
        } While ($r -eq 0 -and $StartWithLetter -and !(($x -ge 65 -and $x -le 90) -Or ($x -ge 97 -and $x -le 122)))
        # If the -StartWithLetter parameter was specified, this loop will make
        # sure that the first character is an upper- or lower-case letter.
        $Passw0rd = $Passw0rd.Trim()
        $Passw0rd += [string][char]$x; $r++
      } until ($Passw0rd.length -eq $Length)
    } until ([int][xcrypt]::GetPasswordStrength($Passw0rd) -gt 60)
    return $Passw0rd;
  }
  [int] static GetPasswordStrength([string]$passw0rd) {
    # Inspired by: https://www.security.org/how-secure-is-my-password/
    $passwordDigits = [RegularExpressions.Regex]::new("\d", [RegularExpressions.RegexOptions]::Compiled);
    $passwordNonWord = [RegularExpressions.Regex]::new("\W", [RegularExpressions.RegexOptions]::Compiled);
    $passwordUppercase = [RegularExpressions.Regex]::new("[A-Z]", [RegularExpressions.RegexOptions]::Compiled);
    $passwordLowercase = [RegularExpressions.Regex]::new("[a-z]", [RegularExpressions.RegexOptions]::Compiled);
    [int]$strength = 0; $digits = $passwordDigits.Matches($passw0rd); $NonWords = $passwordNonWord.Matches($passw0rd); $Uppercases = $passwordUppercase.Matches($passw0rd); $Lowercases = $passwordLowercase.Matches($passw0rd);
    if ($digits.Count -ge 2) { $strength += 10 };
    if ($digits.Count -ge 5) { $strength += 10 };
    if ($NonWords.Count -ge 2) { $strength += 10 };
    if ($NonWords.Count -ge 5) { $strength += 10 };
    if ($passw0rd.Length -gt 8) { $strength += 10 };
    if ($passw0rd.Length -ge 16) { $strength += 10 };
    if ($Lowercases.Count -ge 2) { $strength += 10 };
    if ($Lowercases.Count -ge 5) { $strength += 10 };
    if ($Uppercases.Count -ge 2) { $strength += 10 };
    if ($Uppercases.Count -ge 5) { $strength += 10 };
    return $strength;
  }
  static [bool] IsBase64String([string]$base64) {
    return $(try { [void][Convert]::FromBase64String($base64); $true } catch { $false })
  }
  static [bool] IsValidAES([Aes]$aes) {
    return [bool]$(try { [xcrypt]::CheckProps($aes); $? } catch { $false })
  }
  static [bool] IsValidUrl([string]$url) {
    return $url -match '(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})'
  }
  static [void] CheckProps([Aes]$Aes) {
    $MissingProps = @(); $throw = $false
    Write-Verbose "$([xcrypt]::caller) [+] Checking Encryption Properties ... $(('Mode','Padding', 'keysize', 'BlockSize') | ForEach-Object { if ($null -eq $Aes.Algo.$_) { $MissingProps += $_ } };
            if ($MissingProps.Count -eq 0) { "Done. All AES Props are Good." } else { $throw = $true; "System.ArgumentNullException: $([string]::Join(', ', $MissingProps)) cannot be null." }
        )"
    if ($throw) { throw [ArgumentNullException]::new([string]::Join(', ', $MissingProps)) }
  }
  static [string] GetResolvedPath([string]$Path) {
    return [xcrypt]::GetResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
  }
  static [string] GetResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
    $paths = $session.Path.GetResolvedPSPathFromPSPath($Path);
    if ($paths.Count -gt 1) {
      throw [IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} is ambiguous", $Path))
    } elseif ($paths.Count -lt 1) {
      throw [IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} not Found", $Path))
    }
    return $paths[0].Path
  }
  static [string] GetUnResolvedPath([string]$Path) {
    return [xcrypt]::GetUnResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
  }
  static [string] GetUnResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
    return $session.Path.GetUnresolvedProviderPathFromPSPath($Path)
  }
  static [Type] CreateEnum([string]$Name, [bool]$IsPublic, [string[]]$Members) {
    # Example:
    # $MacMseries = [xcrypt]::CreateEnum('Mseries', $true, ('M1', 'M2', 'M3'))
    # $MacMseries::M1 | gm
    # Todo: Explore more about [EnumBuilder], so we can add more features. ex: Flags, instead of [string[]]$Members we can have [hastable]$Members etc.
    try {
      if ([string]::IsNullOrWhiteSpace($Name)) { throw [InvalidArgumentException]::new('Name', 'Name can not be null or space') }
      $DynAssembly = [Reflection.AssemblyName]::new("EmittedEnum")
      $AssmBuilder = [AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, ([AssemblyBuilderAccess]::Save -bor [AssemblyBuilderAccess]::Run)) # Only run in memory
      $ModulBuildr = $AssmBuilder.DefineDynamicModule("DynamicModule")
      $type_attrib = if ($IsPublic) { [Reflection.TypeAttributes]::Public }else { [Reflection.TypeAttributes]::NotPublic }
      $enumBuilder = [EnumBuilder]$ModulBuildr.DefineEnum($name, $type_attrib, [Int32]);
      for ($i = 0; $i -lt $Members.count; $i++) { [void]$enumBuilder.DefineLiteral($Members[$i], $i) }
      [void]$enumBuilder.CreateType()
    } catch {
      throw $_
    }
    return ($Name -as [Type])
  }
  static [Aes] GetAes() { return [xcrypt]::GetAes(1) }
  static [Aes] GetAes([int]$Iterations) {
    $salt = $null; $password = $null;
    Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $([xcrypt]::GeneratePassword() | xconvert ToSecurestring);
    Set-Variable -Name salt -Scope Local -Visibility Private -Option Private -Value $([xcrypt]::GetRfc2898DeriveBytes(16));
    return [xcrypt]::GetAes($password, $salt, $Iterations)
  }
  static [Aes] GetAes([securestring]$password, [byte[]]$salt, [int]$iterations) {
    $aes = $null; $M = $null; $P = $null; $k = $null;
    Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([AesManaged]::new());
    #Note: 'Zeros' Padding was avoided, see: https://crypto.stackexchange.com/questions/1486/how-to-choose-a-padding-mode-with-aes # Personally I prefer PKCS7 as the best padding.
    for ($i = 1; $i -le $iterations; $i++) { ($M, $P, $k) = ((Get-Random ('ECB', 'CBC')), (Get-Random ('PKCS7', 'ISO10126', 'ANSIX923')), (Get-Random (128, 192, 256))) }
    $aes.Mode = & ([scriptblock]::Create("[System.Security.Cryptography.CipherMode]::$M"));
    $aes.Padding = & ([scriptblock]::Create("[System.Security.Cryptography.PaddingMode]::$P"));
    $aes.keysize = $k;
    $aes.Key = [xcrypt]::GetKey($password, $salt);
    $aes.IV = [xcrypt]::GetRandomEntropy();
    return $aes
  }
  # Use a cryptographic hash function (SHA-256) to generate a unique machine ID
  static [string] GetUniqueMachineId() {
    $Id = [string]($Env:MachineId)
    $vp = (Get-Variable VerbosePreference).Value
    try {
      Set-Variable VerbosePreference -Value $([System.Management.Automation.ActionPreference]::SilentlyContinue)
      $sha256 = [SHA256]::Create()
      $HostOS = $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
      if ($HostOS -eq "Windows") {
        if ([string]::IsNullOrWhiteSpace($Id)) {
          $machineId = Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
          Set-Item -Path Env:\MachineId -Value $([convert]::ToBase64String($sha256.ComputeHash([Encoding]::UTF8.GetBytes($machineId))));
        }
        $Id = [string]($Env:MachineId)
      } elseif ($HostOS -eq "Linux") {
        # $Id = (sudo cat /sys/class/dmi/id/product_uuid).Trim() # sudo prompt is a nono
        # Lets use mac addresses
        $Id = ([string[]]$(ip link show | grep "link/ether" | awk '{print $2}') -join '-').Trim()
        $Id = [convert]::ToBase64String($sha256.ComputeHash([Encoding]::UTF8.GetBytes($Id)))
      } elseif ($HostOS -eq "macOS") {
        $Id = (system_profiler SPHardwareDataType | Select-String "UUID").Line.Split(":")[1].Trim()
        $Id = [convert]::ToBase64String($sha256.ComputeHash([Encoding]::UTF8.GetBytes($Id)))
      } else {
        throw "Error: HostOS = '$HostOS'. Could not determine the operating system."
      }
    } catch {
      throw $_
    } finally {
      $sha256.Clear(); $sha256.Dispose()
      Set-Variable VerbosePreference -Value $vp
    }
    return $Id
  }
  static [string] Get_Host_Os() {
    # Todo: Should return one of these: [Enum]::GetNames([System.PlatformID])
    return $(if ($(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" })
  }
  static [IO.DirectoryInfo] Get_dataPath([string]$appName, [string]$SubdirName) {
    $_Host_OS = [xcrypt]::Get_Host_Os()
    $dataPath = if ($_Host_OS -eq 'Windows') {
      [DirectoryInfo]::new([IO.Path]::Combine($Env:HOME, "AppData", "Roaming", $appName, $SubdirName))
    } elseif ($_Host_OS -in ('Linux', 'MacOs')) {
      [DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
    } elseif ($_Host_OS -eq 'Unknown') {
      try {
        [DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
      } catch {
        Write-Warning "Could not resolve chat data path"
        Write-Warning "HostOS = '$_Host_OS'. Could not resolve data path."
        [Directory]::CreateTempSubdirectory(($SubdirName + 'Data-'))
      }
    } else {
      throw [InvalidOperationException]::new('Could not resolve data path. Get_Host_OS FAILED!')
    }
    if (!$dataPath.Exists) { [xcrypt]::Create_Dir($dataPath) }
    return $dataPath
  }
  static [void] Create_Dir([string]$Path) {
    [xcrypt]::Create_Dir([DirectoryInfo]::new($Path))
  }
  static [void] Create_Dir([DirectoryInfo]$Path) {
    [ValidateNotNullOrEmpty()][DirectoryInfo]$Path = $Path
    $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
    [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create(); Write-Verbose "Created $_" }
  }
  [PSCustomObject] static Get_Ip_Info() {
    $i = $null
    try {
      $i = $(& ([scriptblock]::Create($((Invoke-RestMethod -Verbose:$false -ea Ignore -SkipHttpErrorCheck -Method Get https://api.github.com/gists/d1985ebe22fe07cc191c9458b3a2bdbc).files.'IpInfo.ps1'.content) + ';[Ipinfo]::getInfo()')))
    } catch {
      $i = [PSCustomObject]@{
        country_name = "US"
        location     = [PSCustomObject]@{
          geoname_id = "Ohio"
        }
        city         = "Florida"
      }
    }
    return $i
  }
  [securestring] static GetPassword() {
    $ThrowOnFailure = $true
    return [xcrypt]::GetPassword($ThrowOnFailure);
  }
  [securestring] static GetPassword([string]$Prompt) {
    return [xcrypt]::GetPassword($Prompt, $true)
  }
  [securestring] static GetPassword([bool]$ThrowOnFailure) {
    return [xcrypt]::GetPassword("Password", $ThrowOnFailure)
  }
  static [securestring] GetPassword([string]$Prompt, [bool]$ThrowOnFailure) {
    if ([xcrypt]::Scope.ToString() -eq "Machine") {
      return ([xcrypt]::GetUniqueMachineId() | xconvert ToSecurestring)
    } else {
      $pswd = [SecureString]::new(); $_caller = 'PasswordManager'; if ([xcrypt]::caller) {
        $_caller = [xcrypt]::caller
      }
      Set-Variable -Name pswd -Scope Local -Visibility Private -Option Private -Value $(Read-Host -Prompt "$_caller $Prompt" -AsSecureString);
      if ($ThrowOnFailure -and ($null -eq $pswd -or $([string]::IsNullOrWhiteSpace(($pswd | xconvert ToString))))) {
        throw [InvalidPasswordException]::new("Please Provide a Password that isn't Null or WhiteSpace.", $pswd, [ArgumentNullException]::new("Password"))
      }
      return $pswd;
    }
  }
  static [void] ValidateCompression([string]$Compression) {
    if ($Compression -notin ([Enum]::GetNames('Compression' -as 'Type'))) { Throw [InvalidCastException]::new("The name '$Compression' is not a valid [Compression]`$typeName.") };
  }
}
#endregion xcrypt


class SignatureUtils {
  # Static Properties
  static [string] $SIGNATURE_KEYNAME = "signature"
  static [string] $AppName = "ASP"
  static [string] $NewLine = "`n"
  static [string] $EmptyUriPath = "/"
  static [string] $equals = "="
  static [string] $And = "&"
  static [string] $UTF_8_Encoding = "UTF-8"

  # Static Methods

  # Method to sign parameters
  static [string] signParameters([hashtable] $parameters, [string] $key, [string] $HttpMethod, [string]$h0st, [string] $RequestURI, [string] $algorithm) {
    $stringToSign = [SignatureUtils]::calculateStringToSignV2($parameters, $HttpMethod, $h0st, $RequestURI)
    return [SignatureUtils]::sign($stringToSign, $key, $algorithm)
  }

  # Method to calculate the string to sign for SignatureVersion 2
  static [string] calculateStringToSignV2([hashtable] $parameters, [string] $httpMethod, [string] $hostHeader, [string] $requestURI) {
    if (!$httpMethod) { throw "HttpMethod cannot be null" }

    $stringToSign = "$httpMethod$([SignatureUtils]::NewLine)"

    # Host header to lowercase
    $stringToSign += ($hostHeader.ToLower() + [SignatureUtils]::NewLine)

    # URI or fallback to empty path
    if (!$requestURI) {
      $stringToSign += [SignatureUtils]::EmptyUriPath
    } else {
      $stringToSign += [SignatureUtils]::UrlEncode($requestURI, $true)
    }
    $stringToSign += [SignatureUtils]::NewLine

    # Sort and encode parameters
    $sortedParamMap = [Collections.SortedList]::new($parameters, [StringComparer]::Ordinal)
    foreach ($key in $sortedParamMap.Keys) {
      if ($key -ieq [SignatureUtils]::SIGNATURE_KEYNAME) { continue }
      $stringToSign += [SignatureUtils]::UrlEncode($key, $false) + [SignatureUtils]::equals + [SignatureUtils]::UrlEncode($sortedParamMap[$key], $false) + [SignatureUtils]::And
    }

    return $stringToSign.Substring(0, $stringToSign.Length - 1)
  }

  # URL encode method
  static [string] UrlEncode([string] $data, [bool] $path) {
    $encoded = [string]::Empty
    $unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~" + ($path ? "/" : "")
    $bytes = [Encoding]::UTF8.GetBytes($data)

    foreach ($symbol in $bytes) {
      $char = [char]$symbol
      if ($unreservedChars.Contains($char)) {
        $encoded += $char
      } else {
        $encoded += "%" + "{0:X2}" -f $symbol
      }
    }

    return $encoded
  }

  # Method to compute the RFC 2104-compliant HMAC signature
  static [string] sign([string] $data, [string] $key, [string] $signatureMethod) {
    try {
      $encoding = [ASCIIEncoding]::new()
      $hmac = [HMAC]::Create($signatureMethod)
      $hmac.Key = $encoding.GetBytes($key)
      $hmac.Initialize()
      $dataBytes = $encoding.GetBytes($data)
      $rawResult = $hmac.ComputeHash($dataBytes)
      return [Convert]::ToBase64String($rawResult)
    } catch {
      throw "Failed to generate signature: $($_.Exception.Message)"
    }
  }
}

class FileMonitor {
  static [bool] $FileClosed = $true
  static [bool] $FileLocked = $false
  static [ConsoleKeyInfo[]] $Keys = @()
  static [ValidateNotNull()][IO.FileInfo] $FileTowatch
  static [ValidateNotNull()][string] $LogvariableName = $(if ([string]::IsNullOrWhiteSpace([FileMonitor]::LogvariableName)) {
      $n = ('fileMonitor_log_' + [guid]::NewGuid().Guid).Replace('-', '_');
      Set-Variable -Name $n -Scope Global -Value ([string[]]@()); $n
    } else {
      [FileMonitor]::LogvariableName
    }
  )
  static [FileSystemWatcher] MonitorFile([string]$File) {
    return [FileMonitor]::monitorFile($File, { Write-Host "[+] File monitor Completed" -ForegroundColor Green })
  }
  static [FileSystemWatcher] MonitorFile([string]$File, [scriptblock]$Action) {
    [ValidateNotNull()][FileInfo]$File = [IO.FileInfo][xcrypt]::GetUnResolvedPath($File)
    if (![IO.File]::Exists($File.FullName)) {
      throw "The file does not exist"
    }
    [FileMonitor]::FileTowatch = $File
    $watcher = [FileSystemWatcher]::new();
    $Watcher = New-Object IO.FileSystemWatcher ([IO.Path]::GetDirectoryName($File.FullName)), $File.Name -Property @{
      IncludeSubdirectories = $false
      EnableRaisingEvents   = $true
    }
    $watcher.Filter = $File.Name
    $watcher.NotifyFilter = [NotifyFilters]::LastWrite;
    $onChange = Register-ObjectEvent $Watcher Changed -Action {
      [FileMonitor]::FileLocked = $true
    }
    $OnClosed = Register-ObjectEvent $Watcher Disposed -Action {
      [FileMonitor]::FileClosed = $true
    }
    # [Console]::Write("Monitoring changes to $File"); [Console]::WriteLine("Press 'crl^q' to stop")
    do {
      try {
        [FileMonitor]::FileLocked = [FileMonitor]::IsFileLocked($File.FullName)
      } catch [IOException] {
        [FileMonitor]::FileLocked = $(if ($_.Exception.Message.Contains('is being used by another process')) {
            $true
          } else {
            throw 'An error occured while checking the file'
          }
        )
      } finally {
        [Threading.Thread]::Sleep(100)
      }
    } until ([FileMonitor]::FileClosed -and ![FileMonitor]::FileLocked -and ![FileMonitor]::IsFileOpenInVim($File.FullName))
    Invoke-Command -ScriptBlock $Action
    Unregister-Event -SubscriptionId $onChange.Id; $onChange.Dispose();
    Unregister-Event -SubscriptionId $OnClosed.Id; $OnClosed.Dispose(); $Watcher.Dispose();
    return $watcher
  }
  static [PsObject] MonitorFileAsync([string]$filePath) {
    # .EXAMPLE
    # $flt = [FileMonitor]::MonitorFileAsync($filePath)
    # $flt.Thread.CloseInputStream();
    # $flt.Thread.StopJobAsync();
    # Stop-Job -Name $flt.Name -Verbose -PassThru | Remove-Job -Force -Verbose
    # $flt.Thread.Dispose()MOnitorFile
    # while ((Get-Job -Name $flt.Name).State -ne "Completed") {
    #     # DO other STUFF here ...
    # }
    $threadscript = [scriptblock]::Create("[FileMonitor]::MonitorFile('$filePath')")
    $fLT_Name = "kLThread-$([guid]::NewGuid().Guid)"
    return [PSCustomObject]@{
      Name   = $fLT_Name
      Thread = Start-ThreadJob -ScriptBlock $threadscript -Name $fLT_Name
    }
  }
  static [string] GetLogSummary() {
    return [FileMonitor]::GetLogSummary([FileMonitor]::LogvariableName)
  }
  static [string] GetLogSummary([string]$LogvariableName) {
    [ValidateNotNullOrWhiteSpace()][string]$LogvariableName = $LogvariableName
    $l = Get-Variable -Name $LogvariableName -Scope Global -ValueOnly;
    $summ = ''; $rgx = "\[.*\] The file '.*' is open in nvim \(PID: \d+\)"
    if ($null -eq $l) { return '' }; $ct = $l.Where({ $_ -notmatch $rgx })
    $LogSessions = @();
    $LogSessions += $(if ($ct.count -gt 1) {
                (($l.ForEach({ if ($_ -notmatch $rgx) { $_ + '|' } else { $_ } })) -join "`n").Split('|')
      } else {
        [string]::Join("`n", $l)
      }
    )
    foreach ($item in $LogSessions) {
      $s = ''; $lines = $item.Split("`n")
      0 .. $lines.Count | ForEach-Object { if ($_ -eq 0) { $s += "$($lines[0])`n" } elseif ($lines[$_] -match $rgx -or $lines[$_ + 1] -match $rgx) { $s += '.' } else { $s += "`n$($lines[$_ - 1])" } }
      $summ += [string]::Join("`n", $s.Split("`n").ForEach({ if ($_ -like "......*") { '⋮' } else { $_ } })).Trim()
      $summ += "`n"
    }
    return $summ.Trim()
  }
  static [bool] IsFileOpenInVim([FileInfo]$file) {
    $res = $null; $logvar = Get-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global;
    $fileName = Split-Path -Path $File.FullName -Leaf;
    $res = $false; $_log_msg = @(); $processes = Get-Process -Name "nvim*", "vim*" -ErrorAction SilentlyContinue
    foreach ($process in $processes) {
      if ($process.CommandLine -like "*$fileName*") {
        $_log_msg = "[{0}] The file '{1}' is open in {2} (PID: {3})" -f [DateTime]::Now.ToString(), $fileName, $process.ProcessName, $process.Id
        $res = $true; continue
      }
    }
    $_log_msg = $_log_msg -join [Environment]::NewLine
    if ([string]::IsNullOrEmpty($_log_msg)) {
      $res = $false; $_log_msg = "[{0}] The file '{1}' is not open in vim" -f [DateTime]::Now.ToString(), $fileName
    }
    $logvar.Value += $_log_msg
    Set-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global -Value $logvar.Value | Out-Null
    return $res
  }
  static [bool] IsFileLocked([string]$filePath) {
    $res = $true; $logvar = Get-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global; $filePath = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
    try {
      # (lsof -t "$filePath" | wc -w) -gt 0
      [FileStream]$stream = [IO.File]::Open($filePath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
      if ($stream) { $stream.Close(); $stream.Dispose() }
      $res = $false
    } finally {
      if ($res) { $logvar.Value += "[$([DateTime]::Now.ToString())] File is already locked by another process." }
      Set-Variable -Name ([FileMonitor]::LogvariableName) -Scope Global -Value $logvar.Value | Out-Null
    }
    return $res
  }
}

class SecretStore {
  [string]$Name
  [uri]$Url
  static hidden [ValidateNotNullOrWhiteSpace()][string]$DataPath

  SecretStore([string]$Name) {
    $this.Name = $Name
    if ([string]::IsNullOrWhiteSpace([SecretStore]::DataPath)) {
      [SecretStore]::DataPath = [IO.Path]::Combine([xcrypt]::Get_dataPath('ArgonCage', 'Data'), 'secrets')
    }
    $this.psobject.Properties.Add([psscriptproperty]::new('File', {
          return [FileInfo]::new([IO.Path]::Combine([SecretStore]::DataPath, $this.Name))
        }, {
          param($value)
          if ($value -is [IO.FileInfo]) {
            [SecretStore]::DataPath = $value.Directory.FullName
            $this.Name = $value.Name
          } else {
            throw "Invalid value assigned to File property"
          }
        }
      )
    )
    $this.psobject.Properties.Add([psscriptproperty]::new('Size', {
          if ([IO.File]::Exists($this.File.FullName)) {
            $this.File = Get-Item $this.File.FullName
            return $this.File.Length
          }
          return 0
        }, { throw "Cannot set Size property" }
      )
    )
  }
}

#region    FipsHMACSHA256
# .SYNOPSIS
#     A PowerShell class to provide a FIPS compliant alternative to the built-in [HMACSHA256]
# .DESCRIPTION
#     FIPS (Federal Information Processing Standard) is a set of guidelines that specify the security requirements for cryptographic algorithms and protocols used in the United States government.
#     A FIPS compliant algorithm is one that has been reviewed and approved by the National Institute of Standards and Technology (NIST) to meet certain security standards.
#     The HMAC is a type of message authentication code that uses a secret key to verify the authenticity and integrity of a message.
#     It is based on a hash function, such as SHA-256, which is a cryptographic function that produces a fixed-size output (called a hash or message digest) from a variable-size input.
#     The built-in HMACSHA256 class in .NET Framework implements the HMAC using the SHA-256 hash function.
#     However, in older versions the HMACSHA256 class may not be FIPS compliant.
# .EXAMPLE
#     $br = [Encoding]::UTF8.GetBytes("Hello world!")
#     $hc = [FipsHmacSha256]::new()
#     $hc.ComputeHash($br)
class FipsHmacSha256 : System.Security.Cryptography.HMAC {
  static hidden $rng
  static [HMACSHA256] $HMAC
  static [ValidateNotNullOrEmpty()] [byte[]] $key

  FipsHmacSha256() {
    $this._Init();
  }
  FipsHmacSha256([Byte[]]$key) {
    [FipsHmacSha256]::Key = $key;
    $this._Init();
  }

  [string] ComputeHash([byte[]] $data) {
    if ($null -eq [FipsHmacSha256]::HMAC) {
      [FipsHmacSha256]::HMAC = [HMACSHA256]::new([FipsHmacSha256]::key)
    }
    $hashBytes = [FipsHmacSha256]::HMAC.ComputeHash($data)
    $hash = [BitConverter]::ToString($hashBytes) -replace '-'
    return $hash
  }
  hidden [void] _Init() {
    if ($null -eq [FipsHmacSha256].RNG) {
      [FipsHmacSha256].psobject.Properties.Add([psscriptproperty]::new('RNG',
          { return [RNGCryptoServiceProvider]::new() }
        )
      )
    }
    $flags = [Reflection.BindingFlags]'Instance, NonPublic'
    [Reflection.FieldInfo]$m_hashName = [HMAC].GetField('m_hashName', $flags)
    [Reflection.FieldInfo]$m_hash1 = [HMAC].GetField('m_hash1', $flags)
    [Reflection.FieldInfo]$m_hash2 = [HMAC].GetField('m_hash2', $flags)
    if ($null -ne $m_hashName) {
      $m_hashName.SetValue($this, 'SHA256')
    }
    if ($null -ne $m_hash1) {
      $m_hash1.SetValue($this, [SHA256CryptoServiceProvider]::new())
    }
    if ($null -ne $m_hash2) {
      $m_hash2.SetValue($this, [SHA256CryptoServiceProvider]::new())
    }
    if ($null -eq [FipsHmacSha256]::key) {
      $randomBytes = [Byte[]]::new(64); [FipsHmacSha256].RNG.GetBytes($randomBytes)
      [FipsHmacSha256]::Key = $randomBytes
      # Write-Verbose "Hexkey = $([BitConverter]::ToString([FipsHmacSha256]::Key).Tolower() -replace '-')" -verbose
    }
    $this.HashSizeValue = 256
  }
}
#endregion FipsHMACSHA256

#region    OTPKIT
class OTPKIT {
  [string] $key = ""

  static [string] CreateHOTP([string]$SECRET, [int]$Phone) {
    return [OTPKIT]::CreateHOTP($phone, [OTPKIT]::GetOtp($SECRET))
  }

  static [string] CreateHOTP([int]$phone, [string]$otp) {
    return [OTPKIT]::CreateHOTP($phone, $otp, 5)
  }
  static [string] CreateHOTP([int]$phone, [string]$otp, [int]$expiresAfter) {
    $ttl = $expiresAfter * 60 * 1000
    $expires = (Get-Date).AddMilliseconds($ttl).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $bytes = [byte[]]::new(16)
    [RNGCryptoServiceProvider]::new().GetBytes($bytes)
    $salt = [BitConverter]::ToString($bytes) -replace '-'
    $data = "$phone.$otp.$expires.$salt"
    Write-Host "data: " -NoNewline -ForegroundColor Green; Write-Host "$data" -ForegroundColor Blue
    $hashBase = [FipsHmacSha256]::new().ComputeHash([Encoding]::ASCII.GetBytes($data))
    $hash = "$hashBase.$expires.$salt"
    # Import the Twilio module
    Import-Module -Name Twilio
    $phoneNumber = "+1234567890"
    $message = "Hello, this is a test message."
    [OTPKIT]::Send_TWILIO_SMS($phoneNumber, $message)
    return $hash
  }
  static [bool] Send_TWILIO_SMS ([string]$PhoneNumber, [string]$Message) {
    # Function to send SMS using Twilio
    # Twilio account SID and auth token
    $accountSid = "YOUR_TWILIO_ACCOUNT_SID"
    $authToken = "YOUR_TWILIO_AUTH_TOKEN"

    # Twilio phone number
    $twilioPhoneNumber = "YOUR_TWILIO_PHONE_NUMBER"

    # Create a new Twilio client
    $twilio = New-TwilioRestClient -AccountSid $accountSid -AuthToken $authToken

    # Send the SMS message
    $twilio.SendMessage($twilioPhoneNumber, $PhoneNumber, $Message)
    return $?
  }
  static [bool] VerifyHOTP([string]$otp, [int]$phone, [string]$hash) {
    if (!$hash -match "\.") {
      return $false
    }

    $hashValue, $expires, $salt = $hash -split "\."

    $now = (Get-Date).Ticks / 10000
    if ($now -gt [double]$expires) {
      return $false
    }
    $data = "$phone.$otp.$expires.$salt"
    Write-Host "data: " -NoNewline -ForegroundColor Green; Write-Host "$data" -ForegroundColor Blue
    $newCalculatedHash = [FipsHmacSha256]::new().ComputeHash([Encoding]::ASCII.GetBytes($data))

    if ($newCalculatedHash -eq $hashValue) {
      return $true
    }
    return $false
  }

  static [string] ParseOtpUrl([string]$otpURL) {
    # $otpURL can be decrypted text
    if (![System.Uri]::IsWellFormedUriString("$otpURL", "Absolute") -or $otpURL -notmatch "^otpauth://") { Write-Host "The decrypted text is not a valid OTP URL" "Error" ; $script:FileBrowser.Dispose() ; exit 1 }
    $parseOtpUrl = [scriptblock]::Create("[System.Web.HttpUtility]::ParseQueryString(([uri]::new('$otpURL')).Query)").Invoke()
    $otpType = $([uri]$otpURL).Host
    if ($otpType -eq "hotp") { Write-Warning "TOTP is only supported" }
    if ($otpType -eq "totp" ) { $otpType = "$otpType=" }
    $otpPeriod = if (![string]::IsNullOrEmpty($parseOtpUrl["period"])) { $parseOtpUrl["period"] } else { 30 }
    $otpDigits = if (![string]::IsNullOrEmpty($parseOtpUrl["digits"])) { $parseOtpUrl["digits"] } else { 6 }
    $otpSecret = $parseOtpUrl["secret"]
    return [OTPKIT]::GetOtp($otpSecret, $otpDigits, $otpPeriod)
  }

  static [string] GetOtp([string]$SECRET) {
    return [OTPKIT]::GetOtp($SECRET, 4, "5")
  }
  static [string] GetOtp([string]$SECRET, [int]$LENGTH, [string]$WINDOW) {
    $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
    $hmac.key = $([OTPKIT]::ConvertBase32ToHex($SECRET.ToUpper())) -replace '^0x', '' -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [Convert]::ToByte( $_, 16 ) }
    $timeSpan = $(New-TimeSpan -Start (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0) -End (Get-Date).ToUniversalTime()).TotalSeconds
    $rndHash = $hmac.ComputeHash([byte[]][BitConverter]::GetBytes([Convert]::ToInt64([Math]::Floor($timeSpan / $WINDOW))))
    $toffset = $rndhash[($rndHash.Length - 1)] -band 0xf
    $fullOTP = ($rndhash[$toffset] -band 0x7f) * [math]::pow(2, 24)
    $fullOTP += ($rndHash[$toffset + 1] -band 0xff) * [math]::pow(2, 16)
    $fullOTP += ($rndHash[$toffset + 2] -band 0xff) * [math]::pow(2, 8)
    $fullOTP += ($rndHash[$toffset + 3] -band 0xff)

    $modNumber = [math]::pow(10, $LENGTH)
    $otp = $fullOTP % $modNumber
    $otp = $otp.ToString("0" * $LENGTH)
    return $otp
  }
  static [string] ConvertBase32ToHex([string]$base32) {
    $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    $bits = "";
    $hex = "";

    for ($i = 0; $i -lt $base32.Length; $i++) {
      $val = $base32chars.IndexOf($base32.Chars($i));
      $binary = [Convert]::ToString($val, 2)
      $str = $binary.ToString();
      $len = 5
      $pad = '0'
      if (($len + 1) -ge $str.Length) {
        while (($len - 1) -ge $str.Length) {
          $str = ($pad + $str)
        }
      }
      $bits += $str
    }

    for ($i = 0; $i + 4 -le $bits.Length; $i += 4) {
      $chunk = $bits.Substring($i, 4)
      # Write-Host $chunk
      $intChunk = [Convert]::ToInt32($chunk, 2)
      $hexChunk = '{0:x}' -f $([int]$intChunk)
      # Write-Host $hexChunk
      $hex = $hex + $hexChunk
    }
    return $hex;
  }
}
#endregion OTPKIT

#region    VaultStuff
# A managed credential object. Makes it easy to protect, convert, save and stuff ..
class CredManaged {
  [string] $target
  hidden [bool] $IsProtected = $false;
  hidden [CredType] $type = [CredType]1;
  hidden [EncryptionScope] $Scope = 'User';
  [ValidateNotNullOrEmpty()][string]$UserName = $(whoami);
  [ValidateNotNullOrEmpty()][securestring]$Password = [securestring]::new();
  [ValidateNotNullOrEmpty()][string]$Domain = [Environment]::UserDomainName;

  CredManaged() {}
  CredManaged([string]$target, [string]$username, [SecureString]$password) {
    ($this.target, $this.username, $this.password) = ($target, $username, $password)
  }
  CredManaged([string]$target, [string]$username, [SecureString]$password, [CredType]$type) {
    ($this.target, $this.username, $this.password, $this.type) = ($target, $username, $password, $type)
  }
  CredManaged([PSCredential]$PSCredential) {
    ($this.UserName, $this.Password) = ($PSCredential.UserName, $PSCredential.Password)
  }
  CredManaged([string]$target, [PSCredential]$PSCredential) {
    ($this.target, $this.UserName, $this.Password) = ($target, $PSCredential.UserName, $PSCredential.Password)
  }
  [void] Protect() {
    $_scope_ = [EncryptionScope]$this.Scope
    $_Props_ = @($this | Get-Member -Force | Where-Object { $_.MemberType -eq 'Property' -and $_.Name -ne 'Scope' } | Select-Object -ExpandProperty Name)
    foreach ($n in $_Props_) {
      $OBJ = $this.$n
      if ($n.Equals('Password')) {
        $this.$n = $(Protect-Data -MSG ($OBJ | xconvert ToString) -Scope $_scope_) | xconvert ToBase85, ToSecurestring
      } else {
        $this.$n = Protect-Data -MSG $OBJ -Scope $_scope_
      }
    }
    Invoke-Command -InputObject $this.IsProtected -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
          $this.psobject.Properties.Add([psscriptproperty]::new('IsProtected', { return $true }))
        }
      )
    )
  }
  [void] UnProtect() {
    $_scope_ = [EncryptionScope]$this.Scope
    $_Props_ = @($this | Get-Member -Force | Where-Object { $_.MemberType -eq 'Property' -and $_.Name -ne 'Scope' } | Select-Object -ExpandProperty Name)
    foreach ($n in $_Props_) {
      $OBJ = $this.$n
      if ($n.Equals('Password')) {
        $this.$n = UnProtect-Data -MSG ($OBJ | xconvert ToString, FromBase85, ToString) -Scope $_scope_ | xconvert ToSecurestring;
      } else {
        $this.$n = UnProtect-Data -MSG $OBJ -Scope $_scope_;
      }
    }
    Invoke-Command -InputObject $this.IsProtected -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
          $this.psobject.Properties.Add([psscriptproperty]::new('IsProtected', { return $false }))
        }
      )
    )
  }
  [void] SaveToVault() {
    $CredMan = [CredentialManager]::new();
    [void]$CredMan.SaveCredential($this.target, $this.UserName, $this.Password);
  }
  [string]ToString() {
    $str = $this.UserName
    if ($str.Length -gt 9) { $str = $str.Substring(0, 6) + '...' }
    return $str
  }
}
class NativeCredential {
  [Int32]$AttributeCount
  [UInt32]$CredentialBlobSize
  [IntPtr]$CredentialBlob
  [IntPtr]$TargetAlias
  [Int32]$Type
  [IntPtr]$TargetName
  [IntPtr]$Attributes
  [IntPtr]$UserName
  [UInt32]$Persist
  [IntPtr]$Comment

  NativeCredential([CredManaged]$Cr3dential) {
    $this._init_();
    $this.CredentialBlobSize = [UInt32](($Cr3dential.password.Length + 1) * 2)
    $this.TargetName = [Marshal]::StringToCoTaskMemUni($Cr3dential.target)
    $this.CredentialBlob = [Marshal]::SecureStringToCoTaskMemUnicode($Cr3dential.password)
    $this.UserName = [Marshal]::StringToCoTaskMemUni($Cr3dential.username)
  }
  NativeCredential([string]$target, [string]$username, [securestring]$password) {
    $this._init_();
    $this.CredentialBlobSize = [UInt32](($password.Length + 1) * 2);
    $this.TargetName = [Marshal]::StringToCoTaskMemUni($target);
    $this.CredentialBlob = [Marshal]::SecureStringToCoTaskMemUnicode($password);
    $this.UserName = [Marshal]::StringToCoTaskMemUni($username);
  }
  hidden _init_() {
    $this.AttributeCount = 0
    $this.Comment = [IntPtr]::Zero
    $this.Attributes = [IntPtr]::Zero
    $this.TargetAlias = [IntPtr]::Zero
    $this.Type = [CredType]::Generic.value__
    $this.Persist = [UInt32] [CredentialPersistence]::LocalComputer
  }
}
# Windows credential manager
class CredentialManager {
  static $LastErrorCode
  CredentialManager() { $this::Init() }
  [object] static hidden Advapi32() {
    return (New-Object -TypeName CredentialManager.Advapi32)
  }
  static [void] SaveCredential([string]$title, [SecureString]$SecureString) {
    $UserName = [Environment]::GetEnvironmentVariable('UserName');
    [CredentialManager]::SaveCredential([CredManaged]::new($title, $UserName, $SecureString));
  }
  static [void] SaveCredential([string]$title, [string]$UserName, [SecureString]$SecureString) {
    [CredentialManager]::SaveCredential([CredManaged]::new($title, $UserName, $SecureString));
  }
  static [void] SaveCredential([CredManaged]$Object) {
    if ($null -eq [CredentialManager].CONSTANTS) { [CredentialManager]::Init() }
    # Create the native credential object.
    $NativeCredential = New-Object -TypeName CredentialManager.Advapi32+NativeCredential;
    foreach ($prop in ([NativeCredential]::new($Object).PsObject.properties)) {
      $NativeCredential."$($prop.Name)" = $prop.Value
    }
    # Save Generic credential to the Windows Credential Vault.
    $result = [CredentialManager]::Advapi32()::CredWrite([ref]$NativeCredential, 0)
    [CredentialManager]::LastErrorCode = [Marshal]::GetLastWin32Error();
    if (!$result) {
      throw [Exception]::new("Error saving credential: 0x" + "{0}" -f [CredentialManager]::LastErrorCode)
    }
    # Clean up memory allocated for the native credential object.
    [Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.TargetName)
    [Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.CredentialBlob)
    [Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.UserName)
  }
  static [bool] Remove([string]$target, [CredType]$type) {
    if ($null -eq [CredentialManager].CONSTANTS) { [CredentialManager]::Init() }
    $Isdeleted = [CredentialManager]::Advapi32()::CredDelete($target, $type, 0);
    [CredentialManager]::LastErrorCode = [Marshal]::GetLastWin32Error();
    if (!$Isdeleted) {
      if ([CredentialManager]::LastErrorCode -eq [CredentialManager].CONSTANTS.ERROR_NOT_FOUND) {
        throw [CredentialNotFoundException]::new("DeleteCred failed with the error code $([CredentialManager]::LastErrorCode) (credential not found).");
      } else {
        throw [Exception]::new("DeleteCred failed with the error code $([CredentialManager]::LastErrorCode).");
      }
    }
    return $Isdeleted
  }
  [CredManaged] static GetCredential([string]$target) {
    #uses the default $(whoami)
    return [CredentialManager]::GetCredential($target, (Get-Item Env:\USERNAME).Value);
  }
  [CredManaged] static GetCredential([string]$target, [string]$username) {
    return [CredentialManager]::GetCredential($target, [CredType]::Generic, $username);
  }
  # Method for retrieving a saved credential from the Windows Credential Vault.
  [CredManaged] static GetCredential([string]$target, [CredType]$type, [string]$username) {
    if ($null -eq [CredentialManager].CONSTANTS) { [CredentialManager]::Init() }
    $NativeCredential = New-Object -TypeName CredentialManager.Advapi32+NativeCredential;
    foreach ($prop in ([NativeCredential]::new($target, $username, [securestring]::new()).PsObject.properties)) {
      $NativeCredential."$($prop.Name)" = $prop.Value
    }
    # Declare variables
    $AdvAPI32 = [CredentialManager]::Advapi32()
    $outCredential = [IntPtr]::Zero # To hold the retrieved native credential object.
    # Try to retrieve the credential from the Windows Credential Vault.
    $result = $AdvAPI32::CredRead($target, $type.value__, 0, [ref]$outCredential)
    [CredentialManager]::LastErrorCode = [Marshal]::GetLastWin32Error();
    if (!$result) {
      $errorCode = [CredentialManager]::LastErrorCode
      if ($errorCode -eq [CredentialManager].CONSTANTS.ERROR_NOT_FOUND) {
        $(Get-Variable host).value.UI.WriteErrorLine("`nERROR_NOT_FOUND: Credential '$target' not found in Windows Credential Vault. Returning Empty Object ...`n");
        return [CredManaged]::new();
      } else {
        throw [Exception]::new("Error reading '{0}' in Windows Credential Vault. ErrorCode: 0x{1}" -f $target, $errorCode)
      }
    }
    # Convert the retrieved native credential object to a managed Credential object & Get the Credential from the mem location
    $NativeCredential = [Marshal]::PtrToStructure($outCredential, [Type]"CredentialManager.Advapi32+NativeCredential") -as 'CredentialManager.Advapi32+NativeCredential'
    [GC]::Collect();
    $target = [Marshal]::PtrToStringUni($NativeCredential.TargetName)
    $password = [Runtime.InteropServices.Marshal]::PtrToStringUni($NativeCredential.CredentialBlob)
    $targetuser = [Marshal]::PtrToStringUni($NativeCredential.UserName)
    $credential = [CredManaged]::new($target, $targetuser, ($password | xconvert ToSecurestring));
    # Clean up memory allocated for the native credential object.
    [void]$AdvAPI32::CredFree($outCredential); [CredentialManager]::LastErrorCode = [Marshal]::GetLastWin32Error();
    # Return the managed Credential object.
    return $credential
  }
  [Collections.ObjectModel.Collection[CredManaged]] static RetreiveAll() {
    $Credentials = [Collections.ObjectModel.Collection[CredManaged]]::new();
    # CredEnumerate is slow af so, I ditched it.
    $credList = [CredentialManager]::get_StoredCreds();
    foreach ($cred in $credList) {
      Write-Verbose "CredentialManager.GetCredential($($cred.Target))";
      $Credentials.Add([CredManaged]([CredentialManager]::GetCredential($cred.Target, $cred.Type, $cred.User)));
    }
    return $Credentials
  }
  [Psobject[]] static hidden get_StoredCreds() {
    $_Host_OS = [xcrypt]::Get_Host_Os()
    if ($_Host_OS -in ('Linux', 'MacOs')) {
      throw [Exception]::new('UnsupportedPlatform: get_StoredCreds() works on Windows Only.')
    }
    # until I know the existance of a [wrapper module](https://learn.microsoft.com/en-us/powershell/utility-modules/crescendo/overview?view=ps-modules), I'll stick to this Hack.
    $cmdkey = (Get-Command cmdkey -ErrorAction SilentlyContinue).Source
    if ([string]::IsNullOrEmpty($cmdkey)) { throw [Exception]::new('get_StoredCreds() Failed.') }
    $outputLines = (&$cmdkey /list) -split "`n"
    [CredentialManager]::LastErrorCode = [Marshal]::GetLastWin32Error();
    if ($outputLines) {
    } else {
      throw $error[0].Exception.Message
    }
    $target = $type = $user = $perst = $null
    $credList = $(foreach ($line in $outputLines) {
        if ($line -match "^\s*Target:\s*(.+)$") {
          $target = $matches[1]
        } elseif ($line -match "^\s*Type:\s*(.+)$") {
          $type = $matches[1]
        } elseif ($line -match "^\s*User:\s*(.+)$") {
          $user = $matches[1]
        } elseif ($line -match "^\s*Local machine persistence$") {
          $perst = "LocalComputer"
        } elseif ($line -match "^\s*Enterprise persistence$") {
          $perst = 'Enterprise'
        }
        if ($target -and $type -and $user -and ![string]::IsNullOrEmpty($perst)) {
          [PSCustomObject]@{
            Target      = [string]$target
            Type        = [CredType]$type
            User        = [string]$user
            Persistence = [CredentialPersistence]$perst
          }
          $target = $type = $user = $perst = $null
        }
      }
    ) | Select-Object @{l = 'Target'; e = { $_.target.replace('LegacyGeneric:target=', '').replace('WindowsLive:target=', '') } }, Type, User, Persistence | Where-Object { $_.target -ne 'virtualapp/didlogical' };
    return $credList
  }
  static hidden [void] Init() {
    $Host_OS = $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
    if ($Host_OS -ne "Windows") {
      throw [System.PlatformNotSupportedException]::new("'$Host_OS' is not supported. CredentialManager class works on windows only.")
    }
    $CONSTANTS = [psobject]::new()
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_SUCCESS', { return 0 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_NOT_FOUND', { return 1168 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_INVALID_FLAGS', { return 1004 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_PERSIST_LOCAL_MACHINE', { return 2 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_USERNAME_LENGTH', { return 514 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_CREDENTIAL_BLOB_SIZE', { return 512 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_GENERIC_TARGET_LENGTH', { return 32767 }))
    [CredentialManager].psobject.Properties.Add([psscriptproperty]::new('CONSTANTS', { return $CONSTANTS }))
    # Import native functions from Advapi32.dll
    # No other choice but to use Add-Type. ie: https://stackoverflow.com/questions/64405866/invoke-runtime-interopservices-dllimportattribute
    # So CredentialManager.Advapi32+functionName it is!
    if (![bool]('CredentialManager.Advapi32' -as 'type')) { Add-Type -Namespace CredentialManager -Name Advapi32 -MemberDefinition $(Expand-Data -str 'H4sIAAAAAAAEALVUS2/aQBC+91eMOIFqWQT6kIo4UB4VKkQohuYQ5bDYA1lpvUt31zSk6n/vrB+AMW1a2vhge+f5ffONDQCwSZaCh4AyiaGvMZrvNggfIOHSwvdXkF+fUKKmsC5ceTBQMeNyxoz5pnREtlZh66O2fMVDZpHM7cL8hRu+FHiU8cYrSpZT3hYpw0eLMkIX+86DKXvkMQHswvv9YfhIx3rheQ1XzWazkQL+kd5Pic1QG25slVuAxnAlM24TFTIxZeEDl5gxG0qLeqO5SSkdNbgLrE5CO2E7ldh69vjMZeQH+DVBaTkTHvQfmA7QUmr+5i8kD1WEjftjlCYtleLMMg/w8ogU9EiwtekUpr1c7tY5KsXlGuZMr9Fes7ji6as4piZ784BGP+cxwoQZe6u5pcl3Sm1JOKdbwJ8qxQpN9/ZgZyzGNIMwoVK77AWDLDo7VHKO5cmfZQA9S/nLxGJfJUfIx9LOrD54zfkh9ARnFdfCoE6n87KKXjPLt3jQFS4XNmd7RtjccypsLsUNjYzk9cdukdUmQL3lIRqfwl1944/Gk+F8PB3+egEO+D8KtSztQdG7FHGyPv9F0hL9sqS566ykAyHG8UZpW6/1oi3b8HbLj4SopR+23s2UA9OFmiNwgyy6rf1GYo822LopDbVWmvwkMul+0JzUpl8O/bu0hKVSAoqy9buxvC92z6YcPEhte7Et3XKbw6SR6GwxcqvhAW1iQTPcj5pOjc7f03QS4wvwTOtmRDWuqqufEKHDMae6IFbtFqzcB3AJmZFGrF2G16VmcKuTdS3wD6Z7pu85lAMU+MzMn4Wb1fi3RWp0fgKYas6b9AcAAA==') }
    if (Get-Service vaultsvc -ErrorAction SilentlyContinue) { Start-Service vaultsvc -ErrorAction Stop }
  }
}

# .DESCRIPTION
#     Hashicorp VaultClient helper class for interacting with a Vault server by the Vault API.
#     To use this class, you will need to have access to a running instance of Hashicorp Vault.
#     You can download it from from the Hashicorp website at https://www.hashicorp.com/products/vault/.
# .EXAMPLE
#     $vaucl = [VaultClient]::new('<VAULT_ADDRESS>', '<VAULT_TOKEN>', '<VAULT_PROTOCOL>')
#     $vault = $vaucl.GetVaultServer()
#     $secrets = $vaucl.GetVaultSecretList('<VAULT_PATH>')
#     $vaucl.SetVaultSecret('<VAULT_PATH>', @{key = 'value'})
class VaultClient {
  # Properties
  [string] $Address # This is the URL or IP address of your Vault server, including the port number if applicable. You can find this value in the api_addr field of the vault.hcl configuration file, or you can use the vault status command to display the current address of the Vault server.
  [string] $Token # This is a token that is used to authenticate with the Vault server. You can generate a new token using the vault token create command, or you can use the vault status command to display the current token of the Vault server.
  [string] $Protocol # This is the protocol that will be used to communicate with the Vault server. The most common value is https, but you can also use http if you have configured your Vault server to use an insecure connection. You can find this value in the api_addr field of the vault.hcl configuration file, or you can use the vault status command to display the current protocol of the Vault server.
  [string] $Url = [string]::Empty
  hidden [PSCustomObject] $ClientObj = $null
  static hidden $releases # ie: [Microsoft.PowerShell.Commands.HtmlWebResponseObject]

  # Constructor for the VaultClient class
  VaultClient([string]$address, [string]$token, [string]$protocol) {
    $this.Address = $address
    $this.Token = $token
    $this.Protocol = $protocol
    # Set the Vault URL
    $this.Url = "{0}://{1}/v1/" -f $protocol, $address
    # Generate the vaultClient object
    $this.GenerateVaultClient($token)
  }
  # Download and Install the latest Vault
  static [void] Install() {
    [console]::Write("Check Latest Version ...")
    [VaultClient]::releases = Invoke-WebRequest "https://releases.hashicorp.com/vault/" -Verbose:$false
    [string]$latestver = $([VaultClient]::releases.Links | ForEach-Object { $_.outerText.split('-')[0].split('_')[1] -as 'version' } | Sort-Object -Descending)[0].tostring()
    [VaultClient]::Install($latestver)
  }
  static [void] Install([string]$version) {
    [console]::WriteLine(" Found vault version: $version")
    if ($null -eq [VaultClient]::releases) { [VaultClient]::releases = Invoke-WebRequest "https://releases.hashicorp.com/vault/" -Verbose:$false }
    [string]$latest_dl = $(Invoke-WebRequest ("https://releases.hashicorp.com" + ([VaultClient]::releases.Links | Where-Object { $_.href -like "*/$version/*" } | Select-Object -ExpandProperty href)) -Verbose:$false).Links.href | Where-Object { $_ -like "*windows_386*" }
    $p = Get-Variable progressPreference -ValueOnly; $progressPreference = "SilentlyContinue"
    $Outfile = [FileInfo]::new([xcrypt]::GetUnResolvedPath("vault_$version.zip"));
    try {
      $should_download = $true
      if ($Outfile.Exists()) {
        #TODO: Check version of the file, if the version is lower, then $should_download = $true
      }
      if ($should_download) {
        $Outfile = [scriptblock]::Create("[NetworkManager]::DownloadFile([uri]::new('$latest_dl'), '$($Outfile.FullName)')").Invoke()
      }
      if ($Outfile.Exists()) {
        Expand-Archive -Path $Outfile.FullName -DestinationPath "C:\Program Files\Vault\"
      }
      [void][System.Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\Program Files\Vault\", "Machine")
    } catch {
      throw $_
    } finally {
      Remove-Item $Outfile -Force -ErrorAction SilentlyContinue
      $progressPreference = $p
    }
    # refresh env: like Update-SessionEnvironment from choco~
  }
  # Method to generate the vaultClient object
  [void] GenerateVaultClient([string]$token) {
    # Set the Vault token
    $this.ClientObj = @{
      Token   = $token
      Headers = @{ 'X-Vault-Token' = $token }
      BaseUri = $this.Url
    }
  }

  # Method to get a Vault server
  [PSCustomObject] GetVaultServer() {
    # Create a custom object with the vaultClient object
    $vault = New-Object -TypeName PSObject -Property $this.ClientObj
    # Return the custom object
    return $vault
  }

  # Method to get a Vault secret
  [Hashtable] GetVaultSecret([string]$path) {
    # Get the server
    $vault = $this.GetVaultServer()
    # Get the secret at the specified path
    $uri = $vault.BaseUri + $path
    $secret = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data
    # Return the secret
    return $secret
  }

  # Method to get a list of Vault secrets
  [string[]] GetVaultSecretList([string]$path) {
    return $this.GetVaultSecretList($path, $null)
  }
  # Method to get a list of Vault secrets
  [string[]] GetVaultSecretList([string]$path, [PSCustomObject]$vault = $null) {
    # Get the server
    if (!$vault) { $vault = $this.GetVaultServer() }
    # Get the list of secrets
    $uri = $vault.BaseUri + $path
    $secrets = Invoke-WebRequest -Uri $uri -Headers $vault.Headers -CustomMethod 'list' | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty keys | ForEach-Object {
      if ($_ -like '*/') {
        $this.GetVaultSecretList($("$path/$_").Trim("/"), $vault)
      } else {
        "$path/$_"
      }
    }
    # Return the list of secrets
    return $secrets
  }

  # Method to set a Vault secret
  [void] SetVaultSecret([string]$path, [Hashtable]$secret) {
    $vault = $this.GetVaultServer()
    # Set the secret at the specified path
    $uri = $vault.BaseUri + $path
    $data = @{data = $secret } | ConvertTo-Json
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'POST' -Body $data | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data
  }
  # Method to remove a Vault secret
  [void] RemoveVaultSecret([string]$path) {
    $vault = $this.GetVaultServer()
    # Remove the secret at the specified path
    $uri = $vault.BaseUri + $path
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'DELETE'
  }

  # Method to get a Vault group
  [Hashtable] GetVaultGroup([string]$name) {
    $vault = $this.GetVaultServer()
    # Get the group with the specified name
    $uri = $vault.BaseUri + "identity/group/name/$name"
    $group = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data

    # Return the group
    return $group
  }

  # Method to set a Vault group
  [void] SetVaultGroup([Hashtable]$group) {
    $vault = $this.GetVaultServer()
    # Set the group
    $uri = $vault.BaseUri + "identity/group"
    $data = $group | ConvertTo-Json
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'POST' -Body $data
  }

  # Method to remove a Vault group
  [void] RemoveVaultGroup([string]$name) {
    $vault = $this.GetVaultServer()
    # Remove the group with the specified name
    $uri = $vault.BaseUri + "identity/group/name/$name"
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'DELETE'
  }

  # Method to get a Vault policy
  [string] GetVaultPolicy([string]$name) {
    $vault = $this.GetVaultServer()
    # Get the policy with the specified name
    $uri = $vault.BaseUri + "sys/policy/$name"
    $policy = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty rules

    # Return the policy
    return $policy
  }

  # Method to set a Vault policy
  [void] SetVaultPolicy([string]$name, [string]$rules) {
    $vault = $this.GetVaultServer()
    # Set the policy with the specified name
    $uri = $vault.BaseUri + "sys/policy/$name"
    $data = @{rules = $rules } | ConvertTo-Json
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'POST' -Body $data
  }

  # Method to remove a Vault policy
  [void] RemoveVaultPolicy([string]$name) {
    $vault = $this.GetVaultServer()
    # Remove the policy with the specified name
    $uri = $vault.BaseUri + "sys/policy/$name"
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'DELETE'
  }

  # Method to get a list of Vault policies
  [string[]] GetVaultPolicyList() {
    $vault = $this.GetVaultServer()
    # Get the list of policies
    $uri = $vault.BaseUri + "sys/policy"
    $policies = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty keys

    # Return the list of policies
    return $policies
  }
}
#endregion vaultStuff

#region    securecodes~Expiration
Class Expiration {
  [Datetime]$Date
  [Timespan]$TimeSpan
  [String]$TimeStamp
  [ExpType]$Type

  Expiration() {
    $this.TimeSpan = [Timespan]::FromMilliseconds([DateTime]::Now.Millisecond)
    $this.Date = [datetime]::Now + $this.TimeSpan
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([int]$Years) {
    # ($Months, $Years) = if ($Years -eq 1) { (12, 0) }else { (0, $Years) };
    # $CrDate = [datetime]::Now;
    # $Months = [int]($CrDate.Month + $Months); if ($Months -gt 12) { $Months -= 12 };
    $this.TimeSpan = [Timespan]::new((365 * $years), 0, 0, 0);
    $this.Date = [datetime]::Now + $this.TimeSpan
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([int]$Years, [int]$Months) {
    $this.TimeSpan = [Timespan]::new((365 * $years + $Months * 30), 0, 0, 0);
    $this.Date = [datetime]::Now + $this.TimeSpan
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([datetime]$date) {
    $this.Date = $date
    $this.TimeSpan = $date - [datetime]::Now;
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([string]$dateString) {
    $this.Date = $dateString | xconvert ToDateTime
    $this.TimeSpan = $this.Date - [datetime]::Now;
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([System.TimeSpan]$TimeSpan) {
    $this.TimeSpan = $TimeSpan;
    $this.Date = [datetime]::Now + $this.TimeSpan
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([int]$hours, [int]$minutes, [int]$seconds) {
    $this.TimeSpan = [Timespan]::new($hours, $minutes, $seconds);
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([int]$days, [int]$hours, [int]$minutes, [int]$seconds) {
    $this.TimeSpan = [Timespan]::new($days, $hours, $minutes, $seconds)
    $this.Date = [datetime]::Now + $this.TimeSpan
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  [void]setTimeStamp([System.TimeSpan]$TimeSpan) {
    if ($null -eq $this.Date) {
      $this.TimeStamp = [DateTime]::Now.Add([Timespan]::FromMilliseconds($TimeSpan.TotalMilliseconds)).ToString("yyyyMMddHHmmssffff");
    } else {
      $this.TimeStamp = $this.Date.ToString("yyyyMMddHHmmssffff")
    }
  }
  [void]hidden setExpType([Timespan]$TimeSpan) {
    $this.Type = switch ($true) {
      $($TimeSpan.Days -ge 365) { [ExpType]::Years; break }
      $($TimeSpan.Days -ge 30) { [ExpType]::Months; break }
      $($TimeSpan.Days -ge 1) { [ExpType]::Days; break }
      $($TimeSpan.Hours -ge 1) { [ExpType]::Hours; break }
      $($TimeSpan.Minutes -ge 1) { [ExpType]::Minutes; break }
      $($TimeSpan.Seconds -ge 1) { [ExpType]::Seconds; break }
      Default { [ExpType]::Milliseconds; break }
    }
  }
  [int]GetDays () {
    return $this.TimeSpan.Days
  }
  [int]GetMonths () {
    return [int]($this.TimeSpan.Days / 30)
  }
  [int]GetYears () {
    return [int]($this.TimeSpan.Days / 365)
  }
  [string]ToString() {
    if ($null -eq $this.Date) { return [string]::Empty }
    if ($($this.Date - [datetime]::Now) -ge [timespan]::new(0)) {
      return $this.Date.ToString();
    } else {
      return 'Expired'
    }
  }
}
#endregion securecodes~Expiration

#region    Custom_EncClasses_&_Helpers

#region    BitwiseTools
# .SYNOPSIS
#     BitwUtil class heps design encryption algorithms that use bitwise operations and non-linear transformations.
#     Its also used in the construction of the ChaCha20 cipher.
Class BitwUtil {
  static [Byte[]] Prepend([Byte[]]$Bytes, [byte[]]$BytesToPrepend) {
    $tmp = New-Object byte[] $($bytes.Length + $bytesToPrepend.Length);
    #$tmp = [Byte[]] (, 0xFF * ($bytes.Length + $bytesToPrepend.Length));
    $bytesToPrepend.CopyTo($tmp, 0);
    $bytes.CopyTo($tmp, $bytesToPrepend.Length);
    return $tmp;
  }
  static [byte[][]] Shift([byte[]]$Bytes, [int]$size) {
    $left = New-Object byte[] $size;
    $right = New-Object byte[] $($bytes.Length - $size);
    [Array]::Copy($bytes, 0, $left, 0, $left.Length);
    [Array]::Copy($bytes, $left.Length, $right, 0, $right.Length);
    return ($left, $right);
  }
  static [Int32] RotateLeft([Int32]$val, [Int32]$amount) {
    return (($val -shl $amount) -bor ($val -shr (32 - $amount)))
  }
  static [Int64] RotateLeft([Int64]$val, [Int64]$amount) {
    return (($val -shl $amount) -bor ($val -shr (32 - $amount)))
  }
  static [void] QuaterRound([ref]$a, [ref]$b, [ref]$c, [ref]$d) {
    $a.Value = $a.Value + $b.Value; $d.Value = [BitwUtil]::RotateLeft($d.Value -xor $a.Value, 16);
    $c.Value = $c.Value + $d.Value; $b.Value = [BitwUtil]::RotateLeft($b.Value -xor $c.Value, 12);
    $a.Value = $a.Value + $b.Value; $d.Value = [BitwUtil]::RotateLeft($d.Value -xor $a.Value, 8);
    $c.Value = $c.Value + $d.Value; $b.Value = [BitwUtil]::RotateLeft($b.Value -xor $c.Value, 7);
  }
  static [int32[]] QuaterRound([int32]$a, [int32]$b, [int32]$c, [int32]$d) {
    # /!\ WARNING /!\ Incomplete & Not Tested
    [int32]$dVal = [BitConverter]::ToInt32($d, 0)
    [int32]$bVal = [BitConverter]::ToInt32($b, 0)
    $a = $a + $b
    $dVal = $dVal -xor $a
    $dVal = $dVal -shl 16
    $d = [BitConverter]::GetBytes($dVal)
    $c = $c + $d
    $bVal = $bVal -xor $c
    $bVal = $bVal -shl 12
    $b = [BitConverter]::GetBytes($bVal)
    $a = $a + $b
    $dVal = $dVal -xor $a
    $dVal = $dVal -shl 8
    $d = [BitConverter]::GetBytes($dVal)
    $c = $c + $d
    $bVal = $bVal -xor $c
    $bVal = $bVal -shl 7
    $b = [BitConverter]::GetBytes($bVal)
    return [int32[]]@([int32][BitConverter]::ToInt32($a, 0), [int32][BitConverter]::ToInt32($b, 0), [int32][BitConverter]::ToInt32($c, 0), [int32][BitConverter]::ToInt32($d, 0))
  }
  # MixColumns: performs operations on columns of an array
  static [byte[, ]] MixColumns([byte[, ]]$state) {
    [byte[]] $tmp = New-Object byte[] 4
    for ($i = 0; $i -lt 4; $i++) {
      $tmp[0] = [Byte] ($state[0, $i] * 2 + $state[1, $i] * 3)
      $tmp[1] = [Byte] ($state[1, $i] * 2 + $state[2, $i] * 3)
      $tmp[2] = [Byte] ($state[2, $i] * 2 + $state[3, $i] * 3)
      $tmp[3] = [Byte] ($state[3, $i] * 2 + $state[0, $i] * 3)
      for ($j = 0; $j -lt 4; $j++) {
        $state[$j, $i] = $tmp[$j]
      }
    }
    return $state
  }
  # ShiftRows: Performs bitwise operations to shift elements in rows of the $state array
  static [int32[]] ShiftRows([int32[]]$state) {
    $temp = $state[1]
    $state[1] = $state[5]
    $state[5] = $state[9]
    $state[9] = $state[13]
    $state[13] = $temp

    $temp = $state[2]
    $state[2] = $state[10]
    $state[10] = $temp
    $temp = $state[6]
    $state[6] = $state[14]
    $state[14] = $temp

    $temp = $state[15]
    $state[15] = $state[11]
    $state[11] = $state[7]
    $state[7] = $state[3]
    $state[3] = $temp

    return $state
  }
  # KeyExpansion: generates an expanded key based on the original key
  static [int32[]] KeyExpansion([int32[]]$key, [int32]$rounds) {
    $expandedKey = New-Object int32[] $rounds*16
    $temp = New-Object int32[] 4
    $i = 0
    while ($i -lt $rounds * 16) {
      $expandedKey[$i] = $key[$i % 4]
      if (($i % 4) -eq 3) {
        $temp = [BitwUtil]::KeyExpansionCore($temp, ($i / 4))
        for ($j = 0; $j -lt 4; $j++) {
          $expandedKey[$i + $j] = $expandedKey[$i + $j - 4] -xor $temp[$j]
        }
        $i += 4
      }
      $i++
    }
    return $expandedKey
  }

  static hidden [int32[]] KeyExpansionCore([int32[]]$temp, [int32]$round) {
    $temp[0] = [int32]([BitConverter]::ToInt32($temp, 0) -shl 8 -xor $temp[0] -xor ($round -shl 24))
    $temp[1] = [int32]([BitConverter]::ToInt32($temp, 4) -shl 8 -xor $temp[1])
    $temp[2] = [int32]([BitConverter]::ToInt32($temp, 8) -shl 8 -xor $temp[2])
    $temp[3] = [int32]([BitConverter]::ToInt32($temp, 12) -shl 8 -xor $temp[3] -xor $round)
    return $temp
  }
  # SubBytes: Performs a substitution operation on each byte of an array
  static [byte[]] SubBytes([byte[]]$state, [byte[]]$sBox) {
    # Note: $sBox is an array of 256 values representing the substitution box.
    # You'll need to initialize it with appropriate values for the specific encryption algorithm you're using.
    for ($i = 0; $i -lt $state.Length; $i++) {
      $state[$i] = $sBox[$state[$i]]
    }
    return $state
  }
  # AddRoundKey: performs bitwise operations to add elements from two arrays
  static [byte[]] AddRoundKey([byte[]]$state, [byte[]]$roundKey) {
    for ($i = 0; $i -lt $state.Length; $i++) {
      $state[$i] = $state[$i] -bxor $roundKey[$i]
    }
    return $state
  }
  static [Int64] Reduce([Double]$nput) {
    [Double]$max = 9223372036854775807
    $result = $nput
    while ($result -ge $max) {
      $result = [double]($result / 2)
    }
    return $result
  }
  static [Int64[]] Reduce([Int64[]]$arr) {
    [Int64]$u = 0; # The overflow from each calculation of the reduction process
    [Int64[]]$h = $arr
    $u = $u + [BitwUtil]::Reduce($h[0]);
    $h[0] = $u -band 0xffffffc;
    $u = $u -shr 26;
    $u = $u + [BitwUtil]::Reduce($h[1]);
    $h[1] = $u -band 0xffffffc;
    $u = $u -shr 26;
    $u = $u + [BitwUtil]::Reduce($h[2]);
    $h[2] = $u -band 0xffffffc;
    $u = $u -shr 26;
    $u = $u + [BitwUtil]::Reduce($h[3]);
    $h[3] = $u -band 0xffffffc;
    $u = $u -shr 26;
    $u = $u + [BitwUtil]::Reduce($h[4]);
    $h[4] = $u -band 0xffffffc;
    $u = $u -shr 26;
    $h[0] = [BitwUtil]::Reduce($h[0]) + $u * 5;
    $u = $u -shr 2;
    # Write-Debug "ReduceOverflow: $u" -Debug
    return $h
  }
  [byte[]]ToLittleEndian([byte[]]$value) {
    if (![System.BitConverter]::IsLittleEndian) { [array]::Reverse($value) }
    return $value
  }
  # TODO: write InvMixColumns method: performs inverse operations on columns of an array
  # TODO: write InvShiftRows method: performs inverse bitwise operations to shift elements in rows of an array
  # TODO: write InvSubBytes method: performs an inverse substitution operation on each byte of an array
  # TODO: write InvAddRoundKey method: performs inverse bitwise operations to add elements from two arrays.
}
#endregion BitwiseTools

#region    Shuffl3r
# .SYNOPSIS
#     Shuffles bytes and nonce into a jumbled byte[] mess that can be split using a password.
#     Can be used to Combine the encrypted data with the initialization vector (IV) and other data.
# .DESCRIPTION
#     Everyone is appending the IV to encrypted bytes, such that when decrypting, $CryptoProvider.IV = $encyptedBytes[0..15];
#     They say its safe since IV is basically random and changes every encryption. but this small loophole can allow an advanced attacker to use some tools to find that IV at the end.
#     This class aim to prevent that; or at least make it nearly impossible.
#     By using an int[] of indices as a lookup table to rearrange the $nonce and $bytes.
#     The int[] array is derrivated from the password that the user provides.
# .EXAMPLE
#     $_bytes = [Encoding]::UTF8.GetBytes('** _H4ck_z3_W0rld_ **');
#     $Nonce1 = [xcrypt]::GetRandomEntropy();
#     $Nonce2 = [xcrypt]::GetRandomEntropy();
#     $Passwd = 'OKay_&~rVJ+T?NpJ(8TqL' | xconvert ToSecurestring;
#     $shuffld = [Shuffl3r]::Combine([Shuffl3r]::Combine($_bytes, $Nonce2, $Passwd), $Nonce1, $Passwd);
#     ($b,$n1) = [Shuffl3r]::Split($shuffld, $Passwd, $Nonce1.Length);
#     ($b,$n2) = [Shuffl3r]::Split($b, $Passwd, $Nonce2.Length);
#     [Encoding]::UTF8.GetString($b) -eq '** _H4ck_z3_W0rld_ **' # should be $true
class Shuffl3r {
  static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [securestring]$Passwod) {
    return [Shuffl3r]::Combine($bytes, $Nonce, ($Passwod | xconvert Tostring))
  }
  static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [string]$Passw0d) {
    # if ($Bytes.Length -lt 16) { throw [InvalidArgumentException]::New('Bytes', 'Input bytes.length should be > 16. ie: $minLength = 17, since the common $nonce length is 16') }
    if ($bytes.Length -lt ($Nonce.Length + 1)) {
      Write-Debug "Bytes.Length = $($Bytes.Length) but Nonce.Length = $($Nonce.Length)" -Debug
      throw [ArgumentOutOfRangeException]::new("Nonce", 'Make sure $Bytes.length > $Nonce.Length')
    }
    if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [ArgumentNullException]::new('$Passw0d') }
    [int[]]$Indices = [int[]]::new($Nonce.Length);
    Set-Variable -Name Indices -Scope local -Visibility Public -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($Nonce.Length, $Passw0d, $bytes.Length));
    [Byte[]]$combined = [Byte[]]::new($bytes.Length + $Nonce.Length);
    for ([int]$i = 0; $i -lt $Indices.Length; $i++) {
      $combined[$Indices[$i]] = $Nonce[$i]
    }
    $i = 0; $ir = (0..($combined.Length - 1)) | Where-Object { $_ -NotIn $Indices };
    foreach ($j in $ir) { $combined[$j] = $bytes[$i]; $i++ }
    return $combined
  }
  static [array] Split([Byte[]]$ShuffledBytes, [securestring]$Passwod, [int]$NonceLength) {
    return [Shuffl3r]::Split($ShuffledBytes, ($Passwod | xconvert ToString), [int]$NonceLength);
  }
  static [array] Split([Byte[]]$ShuffledBytes, [string]$Passw0d, [int]$NonceLength) {
    if ($null -eq $ShuffledBytes) { throw [ArgumentNullException]::new('$ShuffledBytes') }
    if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [ArgumentNullException]::new('$Passw0d') }
    [int[]]$Indices = [int[]]::new([int]$NonceLength);
    Set-Variable -Name Indices -Scope local -Visibility Private -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($NonceLength, $Passw0d, ($ShuffledBytes.Length - $NonceLength)));
    $Nonce = [Byte[]]::new($NonceLength);
    $bytes = [Byte[]]$((0..($ShuffledBytes.Length - 1)) | Where-Object { $_ -NotIn $Indices } | Select-Object *, @{l = 'bytes'; e = { $ShuffledBytes[$_] } }).bytes
    for ($i = 0; $i -lt $NonceLength; $i++) { $Nonce[$i] = $ShuffledBytes[$Indices[$i]] };
    return ($bytes, $Nonce)
  }
  static hidden [int[]] GenerateIndices([int]$Count, [string]$randomString, [int]$HighestIndex) {
    if ($HighestIndex -lt 3 -or $Count -ge $HighestIndex) { throw [ArgumentOutOfRangeException]::new('$HighestIndex >= 3 is required; and $Count should be less than $HighestIndex') }
    if ([string]::IsNullOrWhiteSpace($randomString)) { throw [ArgumentNullException]::new('$randomString') }
    [Byte[]]$hash = [SHA256]::Create().ComputeHash([Encoding]::UTF8.GetBytes([string]$randomString))
    [int[]]$indices = [int[]]::new($Count)
    for ($i = 0; $i -lt $Count; $i++) {
      [int]$nextIndex = [Convert]::ToInt32($hash[$i] % $HighestIndex)
      while ($indices -contains $nextIndex) {
        $nextIndex = ($nextIndex + 1) % $HighestIndex
      }
      $indices[$i] = $nextIndex
    }
    return $indices
  }
}
#endregion Shuffl3r

#region    AesGCM
# .SYNOPSIS
#     A custom AesCGM class, with nerdy Options like compression, iterrations, protection ...
# .DESCRIPTION
#     Both AesCng and AesGcm are secure encryption algorithms, but AesGcm is generally considered to be more secure than AesCng in most scenarios.
#     AesGcm is an authenticated encryption mode that provides both confidentiality and integrity protection. It uses a Galois/Counter Mode (GCM) to encrypt the data, and includes an authentication tag that protects against tampering with or forging the ciphertext.
#     AesCng, on the other hand, only provides confidentiality protection and does not include an authentication tag. This means that an attacker who can modify the ciphertext may be able to undetectably alter the decrypted plaintext.
#     Therefore, it is recommended to use AesGcm whenever possible, as it provides stronger security guarantees compared to AesCng.
# .EXAMPLE
#     $bytes = 'Text_Message1' | xconvert ToBytes; $Password = 'X-aP0jJ_:No=08TfdQ' | xconvert ToSecurestring; $salt = [xcrypt]::GetRandomEntropy();
#     $enc = [AesGCM]::Encrypt($bytes, $Password, $salt)
#     $dec = [AesGCM]::Decrypt($enc, $Password, $salt)
#     echo ([Encoding]::UTF8.GetString($dec).Trim()) # should be: Text_Message1
# .EXAMPLE
#     $bytes = [Encoding]::UTF8.GetBytes("S3crEt message...")
#     $enc = [Aesgcm]::Encrypt($bytes, (Read-Host -AsSecureString -Prompt "Encryption Password"), 4) # encrypt 4 times!
#     $secmessage = [convert]::ToBase64String($enc)
#
#     # On recieving PC:
#     $dec = [AesGcm]::Decrypt([convert]::FromBase64String($secmessage), (Read-Host -AsSecureString -Prompt "Decryption Password"), 4)
#     echo ([Encoding]::UTF8.GetString($dec)) # should be: S3crEt message...
# .NOTES
#  Todo: Find a working/cross-platform way to protect bytes (Like DPAPI for windows but better) then
#  add static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [bool]$Protect, [string]$Compression, [int]$iterations)
class AesGCM : xcrypt {
  static [byte[]] Encrypt([byte[]]$bytes) {
    return [AesGCM]::Encrypt($bytes, [AesGCM]::GetPassword());
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Encrypt($bytes, $Password, $_salt);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, 1);
  }
  static [string] Encrypt([string]$text, [SecureString]$Password, [int]$iterations) {
    return [convert]::ToBase64String([AesGCM]::Encrypt([Encoding]::UTF8.GetBytes("$text"), $Password, $iterations));
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $null, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
    [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
    [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
    [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([Rfc2898DeriveBytes]::new(($Password | xconvert ToString), $Salt, 10000, [HashAlgorithmName]::SHA1).GetBytes(32)));
    [IntPtr]$th = [IntPtr]::new(0); if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
    Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([Marshal]::StringToHGlobalAnsi($TAG_SIZE));
    try {
      $_bytes = $bytes;
      $aes = $null; Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke());
      for ($i = 1; $i -lt $iterations + 1; $i++) {
        # Write-Host "$([AesGCM]::caller) [+] Encryption [$i/$iterations] ... Done" -ForegroundColor Yellow
        # if ($Protect) { $_bytes = Protect-Data -bytes $_bytes -entropy $Salt -scope User }
        # Generate a random IV for each iteration:
        [byte[]]$IV = $null; Set-Variable -Name IV -Scope Local -Visibility Private -Option Private -Value ([Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1, [HashAlgorithmName]::SHA1).GetBytes($IV_SIZE));
        $tag = [byte[]]::new($TAG_SIZE);
        $Encrypted = [byte[]]::new($_bytes.Length);
        [void]$aes.Encrypt($IV, $_bytes, $Encrypted, $tag, $associatedData);
        $_bytes = [Shuffl3r]::Combine([Shuffl3r]::Combine($Encrypted, $IV, $Password), $tag, $Password);
      }
    } catch {
      throw $_
    } finally {
      [void][Marshal]::ZeroFreeGlobalAllocAnsi($th);
      Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
    }
    if (![string]::IsNullOrWhiteSpace($Compression)) {
      $_bytes = Compress-Data -b $_bytes -c $Compression
    }
    return $_bytes
  }
  static [void] Encrypt([FileInfo]$File) {
    [AesGCM]::Encrypt($File, [AesGCM]::GetPassword());
  }
  static [void] Encrypt([FileInfo]$File, [securestring]$Password) {
    [AesGCM]::Encrypt($File, $Password, $null);
  }
  static [void] Encrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath) {
    [AesGCM]::Encrypt($File, $password, $OutPath, 1, $null);
  }
  static [void] Encrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations) {
    [AesGCM]::Encrypt($File, $password, $OutPath, $iterations, $null);
  }
  static [void] Encrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations, [string]$Compression) {
    [ValidateNotNullOrEmpty()][FileInfo]$File = [AesGCM]::GetResolvedPath($File.FullName); if ([string]::IsNullOrWhiteSpace($OutPath)) { $OutPath = $File.FullName }
    [ValidateNotNullOrEmpty()][string]$OutPath = [AesGCM]::GetUnResolvedPath($OutPath);
    if (![string]::IsNullOrWhiteSpace($Compression)) { [AesGCM]::ValidateCompression($Compression) }
    $streamReader = [FileStream]::new($File.FullName, [FileMode]::Open)
    $ba = [byte[]]::New($streamReader.Length);
    [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
    [void]$streamReader.Close();
    Write-Verbose "$([AesGCM]::caller) Begin file encryption:"
    Write-Verbose "[-]  File    : $File"
    Write-Verbose "[-]  OutFile : $OutPath"
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password);
    $encryptdbytes = [AesGCM]::Encrypt($ba, $Password, $_salt, $null, $Compression, $iterations)
    $streamWriter = [FileStream]::new($OutPath, [FileMode]::OpenOrCreate);
    [void]$streamWriter.Write($encryptdbytes, 0, $encryptdbytes.Length);
    [void]$streamWriter.Close()
    [void]$streamReader.Dispose()
    [void]$streamWriter.Dispose()
  }
  static [byte[]] Decrypt([byte[]]$bytes) {
    return [AesGCM]::Decrypt($bytes, [AesGCM]::GetPassword());
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Decrypt($bytes, $Password, $_salt);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
  }
  static [string] Decrypt([string]$text, [SecureString]$Password, [int]$iterations) {
    return [Encoding]::UTF8.GetString([AesGCM]::Decrypt([convert]::FromBase64String($text), $Password, $iterations));
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $null, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
    [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
    [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
    [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([Rfc2898DeriveBytes]::new(($Password | xconvert ToString), $Salt, 10000, [HashAlgorithmName]::SHA1).GetBytes(32)));
    [IntPtr]$th = [IntPtr]::new(0); if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
    Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([Marshal]::StringToHGlobalAnsi($TAG_SIZE));
    try {
      $_bytes = if (![string]::IsNullOrWhiteSpace($Compression)) { Expand-Data -bytes $bytes -compression $Compression } else { $bytes }
      $aes = [ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke()
      for ($i = 1; $i -lt $iterations + 1; $i++) {
        # Write-Host "$([AesGCM]::caller) [+] Decryption [$i/$iterations] ... Done" -ForegroundColor Yellow
        # if ($UnProtect) { $_bytes = UnProtect-Data -bytes $_bytes -entropy $Salt -scope User }
        # Split the real encrypted bytes from nonce & tags then decrypt them:
         ($b, $n1) = [Shuffl3r]::Split($_bytes, $Password, $TAG_SIZE);
         ($b, $n2) = [Shuffl3r]::Split($b, $Password, $IV_SIZE);
        $Decrypted = [byte[]]::new($b.Length);
        $aes.Decrypt($n2, $b, $n1, $Decrypted, $associatedData);
        $_bytes = $Decrypted;
      }
    } catch {
      if ($_.FullyQualifiedErrorId -eq "AuthenticationTagMismatchException") {
        Write-Host "$([AesGCM]::caller) Wrong password" -ForegroundColor Yellow
      }
      throw $_
    } finally {
      [void][Marshal]::ZeroFreeGlobalAllocAnsi($th);
      Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
    }
    return $_bytes
  }
  static [void] Decrypt([FileInfo]$File) {
    [AesGCM]::Decrypt($File, [AesGCM]::GetPassword());
  }
  static [void] Decrypt([FileInfo]$File, [securestring]$password) {
    [AesGCM]::Decrypt($File, $password, $null);
  }
  static [void] Decrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath) {
    [AesGCM]::Decrypt($File, $password, $OutPath, 1, $null);
  }
  static [void] Decrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations) {
    [AesGCM]::Decrypt($File, $password, $OutPath, $iterations, $null);
  }
  static [void] Decrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations, [string]$Compression) {
    [ValidateNotNullOrEmpty()][FileInfo]$File = [AesGCM]::GetResolvedPath($File.FullName); if ([string]::IsNullOrWhiteSpace($OutPath)) { $OutPath = $File.FullName }
    [ValidateNotNullOrEmpty()][string]$OutPath = [AesGCM]::GetUnResolvedPath($OutPath);
    if (![string]::IsNullOrWhiteSpace($Compression)) { [AesGCM]::ValidateCompression($Compression) }
    $streamReader = [FileStream]::new($File.FullName, [FileMode]::Open)
    $ba = [byte[]]::New($streamReader.Length);
    [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
    [void]$streamReader.Close();
    Write-Verbose "$([AesGCM]::caller) Begin file decryption:"
    Write-Verbose "[-]  File    : $File"
    Write-Verbose "[-]  OutFile : $OutPath"
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password);
    $decryptdbytes = [AesGCM]::Decrypt($ba, $Password, $_salt, $null, $Compression, $iterations)
    $streamWriter = [FileStream]::new($OutPath, [FileMode]::OpenOrCreate);
    [void]$streamWriter.Write($decryptdbytes, 0, $decryptdbytes.Length);
    [void]$streamWriter.Close()
    [void]$streamReader.Dispose()
    [void]$streamWriter.Dispose()
  }
}
#endregion AesGCM

#region    AesCng
# .SYNOPSIS
#     A custom System.Security.Cryptography.AesCng class, for more control on hashing, compression & other stuff.
# .DESCRIPTION
#     A symmetric-key encryption algorithm that is used to protect a variety of sensitive data, including financial transactions and government communications.
#     It is considered to be very secure, and has been adopted as a standard by many governments and organizations around the world.
#
#     Just as [AesCng], by default this class CBC ciphermode, PKCS7 padding, and 256b key & SHA1 to hash (since it has been proven to be more secure than MD5).
#     Plus there is the option to stack encryptions by iteration. (But beware when you iterate much it produces larger output)
class AesCng : xcrypt {
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password) {
    return [AesCng]::Encrypt($Bytes, $Password, [AesCng]::_salt);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
    return [AesCng]::Encrypt($Bytes, $Password, $Salt, 'Gzip', $false);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [bool]$Protect) {
    return [AesCng]::Encrypt($Bytes, $Password, [AesCng]::_salt, 'Gzip', $Protect);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [int]$iterations) {
    return [AesCng]::Encrypt($Bytes, $Password, [AesCng]::_salt, $iterations)
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [bool]$Protect) {
    return [AesCng]::Encrypt($Bytes, $Password, $Salt, 'Gzip', $Protect);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [byte[]]$Salt, [int]$iterations) {
    if ($null -eq $Bytes) { throw [ArgumentNullException]::new('bytes', 'Bytes Value cannot be null.') }
    $_bytes = $Bytes; if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesCng]::caller = '[AesCng]' }
    for ($i = 1; $i -lt $iterations + 1; $i++) {
      Write-Host "$([AesCng]::caller) [+] Encryption [$i/$iterations] ...$(
                $_bytes = [AesCng]::Encrypt($_bytes, $Password, $Salt)
            ) Done." -ForegroundColor Yellow
    };
    return $_bytes;
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [string]$Compression) {
    return [AesCng]::Encrypt($Bytes, $Password, [AesCng]::_salt, $Compression, $false);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression) {
    return [AesCng]::Encrypt($Bytes, $Password, $Salt, $Compression, $false);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression, [bool]$Protect) {
    [int]$KeySize = 256; $CryptoProvider = $null; $EncrBytes = $null
    if ($Compression -notin ([Enum]::GetNames('Compression' -as 'Type'))) { Throw [InvalidCastException]::new("The name '$Compression' is not a valid [Compression]`$typeName.") }
    Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([AesCryptoServiceProvider]::new());
    $CryptoProvider.KeySize = [int]$KeySize;
    $CryptoProvider.Padding = [PaddingMode]::PKCS7;
    $CryptoProvider.Mode = [CipherMode]::CBC;
    $CryptoProvider.Key = [Rfc2898DeriveBytes]::new(($Password | xconvert ToString), $Salt, 10000, [HashAlgorithmName]::SHA1).GetBytes($KeySize / 8);
    $CryptoProvider.IV = [Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1, [HashAlgorithmName]::SHA1).GetBytes(16);
    Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $([Shuffl3r]::Combine($CryptoProvider.CreateEncryptor().TransformFinalBlock($Bytes, 0, $Bytes.Length), $CryptoProvider.IV, $Password));
    if ($Protect) { $EncrBytes = Protect-Data -Bytes $encrBytes -Entropy $Salt -Scope User }
    Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $(Expand-Data -bytes $EncrBytes -compression $Compression);
    $CryptoProvider.Clear(); $CryptoProvider.Dispose()
    return $EncrBytes
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password) {
    return [AesCng]::Decrypt($bytes, $Password, 'Gzip');
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
    return [AesCng]::Decrypt($bytes, $Password, $Salt, 'GZip', $false);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [bool]$UnProtect) {
    return [AesCng]::Decrypt($bytes, $Password, [AesCng]::_salt, 'GZip', $UnProtect);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
    return [AesCng]::Decrypt($Bytes, $Password, [AesCng]::_salt, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [bool]$UnProtect) {
    return [AesCng]::Decrypt($bytes, $Password, $Salt, 'GZip', $UnProtect);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$salt, [int]$iterations) {
    if ($null -eq $bytes) { throw [ArgumentNullException]::new('bytes', 'Bytes Value cannot be null.') }
    $_bytes = $bytes; if ([string]::IsNullOrWhiteSpace([AesCng]::caller)) { [AesCng]::caller = '[AesCng]' }
    for ($i = 1; $i -lt $iterations + 1; $i++) {
      Write-Host "$([AesCng]::caller) [+] Decryption [$i/$iterations] ...$(
                $_bytes = [AesCng]::Decrypt($_bytes, $Password, $salt)
            ) Done" -ForegroundColor Yellow
    };
    return $_bytes
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [string]$Compression) {
    return [AesCng]::Decrypt($bytes, $Password, [AesCng]::_salt, $Compression, $false);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression) {
    return [AesCng]::Decrypt($bytes, $Password, $Salt, $Compression, $false);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression, [bool]$UnProtect) {
    [int]$KeySize = 256; $CryptoProvider = $null; $DEcrBytes = $null; $_Bytes = $null
    $_Bytes = Expand-Data -b $bytes -c $Compression;
    if ($UnProtect) { $_Bytes = UnProtect-Data -Bytes $_Bytes -Entropy $Salt -Scope User }
    Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([AesCryptoServiceProvider]::new());
    $CryptoProvider.KeySize = $KeySize;
    $CryptoProvider.Padding = [PaddingMode]::PKCS7;
    $CryptoProvider.Mode = [CipherMode]::CBC;
    $CryptoProvider.Key = [Rfc2898DeriveBytes]::new(($Password | xconvert ToString), $Salt, 10000, [HashAlgorithmName]::SHA1).GetBytes($KeySize / 8);
        ($_Bytes, $CryptoProvider.IV) = [Shuffl3r]::Split($_Bytes, $Password, 16);
    Set-Variable -Name DEcrBytes -Scope Local -Visibility Private -Option Private -Value $($CryptoProvider.CreateDecryptor().TransformFinalBlock($_Bytes, 0, $_Bytes.Length))
    $CryptoProvider.Clear(); $CryptoProvider.Dispose();
    return $DEcrBytes
  }
}
#endregion AesCng

#region    AesCtr
# .SYNOPSIS
#   A custom implementation of AES-ctr.
# .DESCRIPTION
#   [CipherMode]::CTR is not available in PowerShell.
#   This class implements the CTR mode manually by XOR-ing with a sequence of counter blocks generated from the given nonce (IV) and block count.
# .NOTES
#    It's awell known standard and recommended to use a more secure ciphermode mode, such as `[System.Security.Cryptography.CipherMode]::GCM` instead of a manual implementing the CTR mode.
#    thus I dont recommend using this class. what a waste!
class AesCtr : xcrypt {
  static [Byte[]] Encrypt([Byte[]]$Bytes, [byte[]]$Key, [byte[]]$IV) {
    $aes = [AesCryptoServiceProvider]::new()
    $aes.Mode = [CipherMode]::CBC
    $aes.Key = $Key
    $aes.Padding = [PaddingMode]::PKCS7
    [AesCtr]::counter = [Byte[]]::new($aes.BlockSize / 8)
    [Array]::Copy($IV, 0, [AesCtr]::counter, 0, $IV.Length)
    [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8)
    [Byte[]]$CipherBytes = [Byte[]]::new($Bytes.Length)
    for ($i = 0; $i -lt $Bytes.Length; $i += $aes.BlockSize / 8) {
      [Byte[]]$counterBlock = $aes.CreateEncryptor().TransformFinalBlock([AesCtr]::counter, 0, [AesCtr]::counter.Length);
      [Array]::Copy($counterBlock, 0, $CipherBytes, $i, [Math]::Min($counterBlock.Length, $Bytes.Length - $i));
      [AesCtr]::counter++
      [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8);
    }
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
      $CipherBytes[$i] = $CipherBytes[$i] -bxor $Bytes[$i]
    }
    return $CipherBytes
  }
  static [Byte[]] Decrypt([Byte[]]$Bytes, [byte[]]$Key, [byte[]]$IV) {
    $aes = [AesCryptoServiceProvider]::new()
    $aes.Mode = [CipherMode]::CBC
    $aes.Key = $Key
    $aes.Padding = [PaddingMode]::PKCS7
    [AesCtr]::counter = [Byte[]]::new($aes.BlockSize / 8)
    [Array]::Copy($IV, 0, [AesCtr]::counter, 0, $IV.Length)
    [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8)
    [Byte[]]$decrypted = [Byte[]]::new($Bytes.Length)
    for ($i = 0; $i -lt $Bytes.Length; $i += $aes.BlockSize / 8) {
      [Byte[]]$counterBlock = $aes.CreateEncryptor().TransformFinalBlock([AesCtr]::counter, 0, [AesCtr]::counter.Length)
      [Array]::Copy($counterBlock, 0, $decrypted, $i, [Math]::Min($counterBlock.Length, $Bytes.Length - $i))
      [AesCtr]::counter++
      [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8)
    }
    for ($i = 0; $i -lt $decrypted.Length; $i++) {
      $decrypted[$i] = $Bytes[$i] -bxor $decrypted[$i]
    }
    return $decrypted
  }
}
#endregion AesCtr

#region    RSA
# .SYNOPSIS
#     Powershell class implementation of RSA (Rivest-Shamir-Adleman) algorithm.
# .DESCRIPTION
#     A public-key cryptosystem that is widely used for secure data transmission. It is based on the mathematical concept of factoring large composite numbers into their prime factors. The security of the RSA algorithm is based on the difficulty of factoring large composite numbers, which makes it computationally infeasible for an attacker to determine the private key from the public key.
# .EXAMPLE
#     Test-MyTestFunction -Verbose
#     Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
class RSA : xcrypt {
  # Simply Encrypts the specified data using the public key.
  static [byte[]] Encrypt([byte[]]$data, [string]$publicKeyXml) {
    $rsa = [RSACryptoServiceProvider]::new()
    $rsa.FromXmlString($publicKeyXml)
    return $rsa.Encrypt($data, $true)
  }

  # Decrypts the specified data using the private key.
  static [byte[]] Decrypt([byte[]]$data, [string]$privateKeyXml) {
    $rsa = [RSACryptoServiceProvider]::new()
    $rsa.FromXmlString($privateKeyXml)
    return $rsa.Decrypt($data, $true)
  }

  # The data is encrypted using AES in combination with the password and salt.
  # The encrypted data is then encrypted using RSA.
  static [byte[]] Encrypt([byte[]]$data, [string]$PublicKeyXml, [securestring]$password, [byte[]]$salt) {
    # Generate the AES key and initialization vector from the password and salt
    $aesKey = [Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1000).GetBytes(32);
    $aesIV = [Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1000).GetBytes(16);

    # Encrypt the data using AES
    $aes = [AesCryptoServiceProvider]::new(); ($aes.Key, $aes.IV) = ($aesKey, $aesIV);
    $encryptedData = $aes.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)

    # Encrypt the AES key and initialization vector using RSA
    $rsa = [RSACryptoServiceProvider]::new()
    $rsa.FromXmlString($PublicKeyXml)
    $encryptedKey = $rsa.Encrypt($aesKey, $true)
    $encryptedIV = $rsa.Encrypt($aesIV, $true)

    # Concatenate the encrypted key, encrypted IV, and encrypted data
    # and return the result as a byte array
    return [byte[]]([System.Linq.Enumerable]::Concat($encryptedKey, $encryptedIV, $encryptedData));
  }

  # Decrypts the specified data using the private key.
  # The data is first decrypted using RSA to obtain the AES key and initialization vector.
  # The data is then decrypted using AES.
  static [byte[]] Decrypt([byte[]]$data, [string]$privateKeyXml, [securestring]$password) {
    # Extract the encrypted key, encrypted IV, and encrypted data from the input data
    $encryptedKey = $data[0..255]
    $encryptedIV = $data[256..271]
    $encryptedData = $data[272..$data.Length]

    # Decrypt the AES key and initialization vector using RSA
    $rsa = [RSACryptoServiceProvider]::new()
    # todo: Use the $PASSWORD to decrypt the private key so it can be used
    $rsa.FromXmlString($privateKeyXml)
    $aesKey = $rsa.Decrypt($encryptedKey, $true)
    $aesIV = $rsa.Decrypt($encryptedIV, $true)

    # Decrypt the data using AES
    $aes = [AesCryptoServiceProvider]::new()
    $aes.Key = $aesKey
    $aes.IV = $aesIV
    return $aes.CreateDecryptor().TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
  }
  # Exports the key pair to a file or string. # This can be useful if you want to save the key pair to a file or string for later use.
  # If a file path is specified, the key pair will be saved to the file.
  # If no file path is specified, the key pair will be returned as a string.
  static [void] ExportKeyPair([xml]$publicKeyXml, [string]$privateKeyXml, [string]$filePath = "") {
    $keyPair = @{
      "PublicKey"  = $publicKeyXml
      "PrivateKey" = $privateKeyXml
    }

    if ([string]::IsNullOrWhiteSpace($filePath)) {
      throw 'Invalid FilePath'
    } else {
      # Save the key pair to the specified file
      $keyPair | ConvertTo-Json | Out-File -FilePath $filePath
    }
  }
  static [psobject] LoadKeyPair([string]$filePath = "" ) {
    if ([string]::IsNullOrWhiteSpace($filePath)) {
      throw [ArgumentNullException]::new('filePath')
    }
    return [RSA]::LoadKeyPair((Get-Content $filePath | ConvertFrom-Json))
  }
  static [psobject] LoadKeyPair([string]$filePath = "", [string]$keyPairString = "") {
    return $keyPairString | ConvertFrom-Json
  }

  # Generates a new RSA key pair and returns the public and private key XML strings.
  [string] GenerateKeyPair() {
    $rsa = [RSACryptoServiceProvider]::new()
        ($publicKey, $privateKey) = ($rsa.ToXmlString($false), $rsa.ToXmlString($true))
    return $publicKey, $privateKey
  }
}
#endregion RSA

#region    X509
class X509 : xcrypt {
  static [X509Certificate2] CreateCertificate([string]$subject) {
    return [X509]::CreateCertificate($subject, [ECCurveName]::nistP521);
  }
  static [X509Certificate2] CreateCertificate([string]$Subject, [string]$KeyUsage) {
    $upn = if ([bool](Get-Command git -ErrorAction SilentlyContinue)) { git config user.email } else { 'work@contoso.com' }
    return [X509]::CreateCertificate($Subject, $KeyUsage, $upn)
  }
  static [X509Certificate2] CreateCertificate([string]$subject, [ECCurveName]$curveName) {
    [void][X509]::IsValidDistinguishedName($subject, $true);
    $ecdsa = [ECDsa]::Create();
    $ecdsa.GenerateKey([ECCurve]::CreateFromFriendlyName("$curveName"));
    $certRequest = [X509]::GetCertificateRequest($subject, $ecdsa, [HashAlgorithmName]::SHA256, 2048)
    return [X509]::CreateCertificate($certRequest, [FileInfo]::New([char]8) , [securestring]::New(), [DateTimeOffset]::Now.AddDays(-1).DateTime, [DateTimeOffset]::Now.AddYears(10).DateTime);
  }
  static [X509Certificate2] CreateCertificate([string]$Subject, [string]$KeyUsage, [string]$upn) {
    $pin = [xcrypt]::GetRandomSTR('01233456789', 4) | xconvert ToSecurestring
    $Extentions = @("2.5.29.17={text}upn=$upn")
    return [X509]::CreateCertificate($Subject, 2048, 60, "Cert:\CurrentUser\My", $Pin, 'ExportableEncrypted', 'Protect', $KeyUsage, $Extentions, $true)
  }
  static [X509Certificate2] CreateCertificate([string]$Subject, [string]$KeyUsage, [string[]]$Extentions) {
    $pin = [xcrypt]::GetRandomSTR('01233456789', 4) | xconvert ToSecurestring
    return [X509]::CreateCertificate($Subject, 2048, 60, "Cert:\CurrentUser\My", $Pin, 'ExportableEncrypted', 'Protect', $KeyUsage, $Extentions, $true)
  }
  static [X509Certificate2] CreateCertificate([string]$Subject, [string]$upn, [securestring]$pin, [string]$KeyUsage) {
    $Extentions = @("2.5.29.17={text}upn=$upn")
    return [X509]::CreateCertificate($Subject, 2048, 60, "Cert:\CurrentUser\My", $Pin, 'ExportableEncrypted', 'Protect', $KeyUsage, $Extentions, $true)
  }
  static [X509Certificate2] CreateCertificate([string]$Subject, [int]$keySizeInBits = 2048, [int]$ValidForInDays = 365, [string]$StoreLocation, [securestring]$Pin, [string]$KeyExportPolicy, [KeyProtection]$KeyProtection, [string]$KeyUsage, [string[]]$Extentions, [bool]$IsCritical) {
    if (!($KeyExportPolicy -as [KeyExportPolicy] -is 'KeyExportPolicy')) { throw [InvalidArgumentException]::New('[Microsoft.CertificateServices.Commands.KeyExportPolicy]$KeyExportPolicy') }
    if (!($KeyProtection -as [KeyProtection] -is 'KeyProtection')) { throw [InvalidArgumentException]::New("$KeyProtection is not a valid [Microsoft.CertificateServices.Commands.KeyProtection]. See [enum]::GetNames[KeyProtection]() for valid values") }
    if (!($keyUsage -as [KeyUsage] -is 'KeyUsage')) { throw [InvalidArgumentException]::New("$KeyUsage is not a valid X509KeyUsageFlag. See [enum]::GetNames[KeyUsage]() for valid values") }
    if (![bool]("Microsoft.CertificateServices.Commands.KeyExportPolicy" -as [Type]) -and [xcrypt]::Get_Host_Os() -eq "Windows") {
      Write-Verbose "[+] Load all necessary assemblies." # By Creating a dumy cert then remove it. This loads all necessary assemblies to create certificates; It worked for me!
      $DummyName = 'dummy-' + [Guid]::NewGuid().Guid; $DummyCert = New-SelfSignedCertificate -Type Custom -Subject "CN=$DummyName" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2", "2.5.29.17={text}upn=dummy@contoso.com") -KeyExportPolicy NonExportable -KeyUsage None -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My";
      $DummyCert.Dispose(); Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.subject -eq "CN=$DummyName" } | Remove-Item
    }
    $key = [System.Security.Cryptography.RSA]::Create($keySizeInBits)
    # Create a regular expression to match the DN (distinguishedName) format. ie: CN=CommonName,OU=OrganizationalUnit,O=Organization,L=Locality,S=State,C=Country
    $dnFormat = "^CN=.*,OU=.*,O=.*,L=.*,S=.*,C=.*"; # Ex: $subjN = "CN=My Cert Subject,OU=IT,O=MyCompany,L=MyCity,S=MyState,C=MyCountry"
    if ($subject -notmatch $dnFormat) {
      $Ip_Info = [X509]::Get_Ip_Info()
      $subject = "CN=$subject,OU=,O=,L=,S=,C=";
      $subject = $subject -replace "O=,", "O=Contoso,";
      $subject = $subject -replace "OU=,", "OU=$keyUsage,";
      $subject = $subject -replace "C=", "C=$($Ip_Info.country_name)";
      $subject = $subject -replace "L=,", "L=$($Ip_Info.location.geoname_id),";
      $subject = $subject -replace "S=,", "S=$($Ip_Info.city),"
    }
    # Set the OID (Object Identifier) for the subject name
    $distshdName = [X500DistinguishedName]::new($Subject); $distshdName.Oid = [Oid]::new("1.2.840.10045.3.1.7");
    $certRequest = [certificaterequest]::new($distshdName, $key, [HashAlgorithmName]::SHA256, [RSASignaturePadding]::Pkcs1);
    # Create an X509KeyUsageFlags object
    $X509KeyUsageFlags = [X509KeyUsageFlags]::None
    $X509KeyUsageFlags = $X509KeyUsageFlags -bor ([X509KeyUsageFlags]::$KeyUsage);
    $notBefore = [DateTimeOffset]::Now.AddDays(-1); $notAfter = [DateTimeOffset]::Now.AddDays($ValidForInDays)
    $certRequest.CertificateExtensions.Add([X509Extension][X509KeyUsageExtension]::new($X509KeyUsageFlags, $IsCritical))
    foreach ($ext in $Extentions) {
      if ([X509]::IsValidExtension($ext)) {
        $oid, $val = $ext.Split("=")
        $extensionOid = [Oid]::new($oid)
        $extsnrawData = [byte[]][Encoding]::ASCII.GetBytes($val)
        $certRequest.CertificateExtensions.Add([X509Extension]::new($extensionOid, $extsnrawData, $IsCritical))
      } else {
        throw [InvalidArgumentException]::New("$ext")
      }
    }
    $xsig = [X509Certificate2]$certRequest.CreateSelfSigned($notBefore, $notAfter);
    # Create an X509KeyStorageFlags object and set the KeyProtection value
    $t, $f = @{
      'NonExportable:None:None'                             = ('Cert', 'UserKeySet')
      'NonExportable:DataEncipherment:Protect'              = ('SerializedCertPfx', 'UserProtected')
      'ExportableEncrypted:None:Protect'                    = ('Pfx', 'Exportable')
      'ExportableEncrypted:DataEncipherment:Protect'        = ('Pfx', 'UserKeySet')
      'ExportableEncrypted:KeyEncipherment:Protect'         = ('Pfx', 'Exportable')
      'ExportableEncrypted:DataEncipherment:ProtectHigh'    = ('Pfx', 'UserProtected')
      'ExportableEncrypted:CertSign:Protect'                = ('SerializedStore', 'EphemeralKeySet')
      'Exportable:DataEncipherment:None'                    = ('Pkcs12', 'Exportable')
      'Exportable:DataEncipherment:Protect'                 = ('Pkcs12', 'UserProtected')
      'Exportable:DataEncipherment:ProtectHigh'             = ('Pkcs12', 'EphemeralKeySet')
      'Exportable:KeyEncipherment:Protect'                  = ('SerializedCertPfx', 'Exportable')
      'Exportable:KeyEncipherment:ProtectHigh'              = ('SerializedCertPfx', 'UserProtected')
      'Exportable:KeyAgreement:ProtectFingerPrint'          = ('Pkcs7', 'MachineKeySet')
      'ExportableEncrypted:DecipherOnly:ProtectFingerPrint' = ('Authenticode', 'PersistKeySet')
      'NonExportable:CRLSign:None'                          = ('SerializedStore', 'UserKeySet')
      'NonExportable:NonRepudiation:Protect'                = ('Pkcs7', 'UserProtected')
      'ExportableEncrypted:DigitalSignature:ProtectHigh'    = ('SerializedStore', 'EphemeralKeySet')
      'Exportable:EncipherOnly:ProtectFingerPrint'          = ('Pkcs7', 'UserProtected')
    }[[string]::Join(':', $KeyExportPolicy, $KeyUsage, $KeyProtection)]
    $x509ContentType, $x509KeyStorageFlags = ($t -and $f) ? ($t, $f) : ('Cert', 'DefaultKeySet')
    [ValidateNotNullOrEmpty()][X509ContentType]$x509ContentType = [X509ContentType]::$x509ContentType
    $x509KeyStorageFlags = [X509KeyStorageFlags]::$x509KeyStorageFlags
    # if ($null -eq $Pin) { [securestring]$Pin = Read-Host -Prompt "New Certificate PIN" -AsSecureString }
    [byte[]]$certData = $xsig.Export($x509ContentType, $Pin);
    $cert = [X509Certificate2]::new($certData, $Pin, $x509KeyStorageFlags)
    # TODO : test if this gives same result on windows:
    # if on Windows, Import the certificate from the byte array and return the imported certificate
    # if ([X509]::Get_Host_Os() -eq "Windows") {[void]$xsig.Import($certData, $Pin, $x509KeyStorageFlags); $cert = $xsig }

    $store = [X509Store]::new([StoreLocation]::CurrentUser) # save the certificate to the personal store
    [void]$store.Open([OpenFlags]::ReadWrite)
    [void]$store.Add($cert)
    [void]$store.Close()
    Write-Debug "[+] Created $StoreLocation\$($cert.Thumbprint)"
    return $cert
  }
  static [X509Certificate2] CreateCertificate([string]$subject, [string]$pfxFile, [securestring]$password) {
    return [X509]::CreateCertificate($subject, [FileInfo]::new($pfxFile), $password);
  }
  static [X509Certificate2] CreateCertificate([string]$subject, [FileInfo]$pfxFile, [securestring]$password) {
    return [X509]::CreateCertificate($subject, $pfxFile, $password, 2048, [datetime]::Now.AddDays(-1), [datetime]::Now.AddYears(10));
  }
  static [X509Certificate2] CreateCertificate([string]$subject, [FileInfo]$pfxFile, [securestring]$password, [int]$keySizeInBits, [datetime]$notBefore, [datetime]$notAfter) {
    [void][X509]::IsValidDistinguishedName($subject, $true);
    $certificate = [X509]::CreateCertificate($pfxFile, $password, $false);
    if ($null -ne $certificate) { return $certificate }
    $certificateRequest = [X509]::GetCertificateRequest($subject, [Object]::new(), [HashAlgorithmName]::SHA256, $keySizeInBits)
    return [X509]::CreateCertificate($certificateRequest, $pfxFile , $password, $notBefore, $notAfter);
  }
  static [X509Certificate2] CreateCertificate([FileInfo]$pfxFile, [securestring]$password, [bool]$throwOnFailure) {
    $Cert = $null; if ($pfxFile.Exists) {
      if ($null -ne $password) {
        [X509Certificate2]::new($pfxFile.FullName, $password)
      } else { [X509Certificate2]::new($pfxFile.FullName) }
    } elseif ($throwOnFailure) {
      throw [FileNotFoundException]::New($pfxFile.FullName)
    }; return $Cert
  }
  static [X509Certificate2] CreateCertificate([CertificateRequest]$certificateRequest, [FileInfo]$pfxFile, [securestring]$password, [datetime]$notBefore, [datetime]$notAfter) {
    $certResult = [X509Certificate2]$certificateRequest.CreateSelfSigned($notBefore, $notAfter);
    $certRawData = if (![string]::IsNullOrWhiteSpace([Pscredential]::new(' ', $password).GetNetworkCredential().Password)) {
      $certResult.Export([X509ContentType]::Pfx, $password)
    } else {
      $certResult.Export([X509ContentType]::Pfx)
    }
    # Return it in PFX form to prevent windows throwing a security credentials not found error during sslStream.connectAsClient or HttpClient request.
    $Certificate = [X509Certificate2]::new([byte[]]$certRawData);
    $certResult.Dispose(); if ($pfxFile -and $pfxFile.BaseName -ne ([string][char]8)) { [IO.File]::WriteAllBytes($pfxFile.FullName, $certRawData) }
    return $certificate
  }
  static [X509Certificate2Collection] ShowCertificate([X509Certificate2[]]$Certificate, [bool]$Multipick) {
    $certs = [X509Certificate2Collection]::new()
    [void]$certs.AddRange($Certificate)
    if ($Multipick) {
      return [X509Certificate2UI]::SelectFromCollection(
        $certs,
        "Select a certificate",
        "Select a certificate or certificates from the list",
        "MultiSelection"
      )
    } else {
      return [X509Certificate2UI]::SelectFromCollection(
        $certs,
        "Select a certificate",
        "Select a certificate from the list",
        "SingleSelection"
      )
    }
  }
  static [byte[]] Encrypt([byte[]]$PlainBytes, [X509Certificate2]$Cert) {
    $encryptor = $Cert.GetRSAPublicKey().CreateEncryptor()
    $cipherBytes = $encryptor.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)
    return $cipherBytes
  }
  static [byte[]] Encrypt([byte[]]$PlainBytes, [X509Certificate2]$Cert, [RSAEncryptionPadding]$KeyPadding) {
    $encryptor = $Cert.GetRSAPublicKey().CreateEncryptor($KeyPadding)
    $cipherBytes = $encryptor.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)
    return $cipherBytes
  }
  static [byte[]] Decrypt([byte[]]$CipherBytes, [X509Certificate2]$Cert) {
    $decryptor = $Cert.GetRSAPrivateKey().CreateDecryptor()
    $plainBytes = $decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)
    return $plainBytes
  }
  static [byte[]] Decrypt([byte[]]$CipherBytes, [X509Certificate2]$Cert, [RSAEncryptionPadding]$KeyPadding) {
    $decryptor = $Cert.GetRSAPrivateKey().CreateDecryptor($KeyPadding)
    $plainBytes = $decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)
    return $plainBytes
  }
  static [bool]IsValidExtension([string] $extension) {
    # Regular expression to match the format of an extension string: "oid={text}value"
    $extensionFormat = "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}={text}.*"
    return $extension -match $extensionFormat
  }
  static [CertificateRequest] GetCertificateRequest([string]$subject) {
    return [X509]::GetCertificateRequest($subject, [Object]::new(), [HashAlgorithmName]::SHA256, 2048)
  }
  static [CertificateRequest] GetCertificateRequest([string]$subject, $key, [HashAlgorithmName]$hashAlgorithm, [int]$keySizeInBits) {
    [void][X509]::IsValidDistinguishedName($subject, $true);
    $certificateRequest = if ($key.GetType().Name -eq 'System.Security. Cryptography.ECDsa') {
      $ecdsa = [ECDsa]::Create(); $ecdsa.GenerateKey([ECCurve]::CreateFromFriendlyName("brainpoolP512r1")); $ecdsa.KeySize = $keySizeInBits
      [CertificateRequest]::new($subject, $ecdsa, $hashAlgorithm);
    } else {
      [CertificateRequest]::new($subject, [System.Security.Cryptography.RSA]::Create($keySizeInBits), $hashAlgorithm, [RSASignaturePadding]::Pkcs1);
    }
    $certificateRequest.CertificateExtensions.Add([X509BasicConstraintsExtension]::new($true, $false, 0, $true));
    $certificateRequest.CertificateExtensions.Add([X509SubjectKeyIdentifierExtension]::new($certificateRequest.PublicKey, $false));
    $certificateRequest.CertificateExtensions.Add([X509KeyUsageExtension]::new([X509KeyUsageFlags]::DataEncipherment, $true));
    return $certificateRequest
  }
  static [string] GetThumbPrint([string]$certSubject, [string]$FriendlyName) {
    $CertStore = [X509Store]::new([StoreName]::My, [StoreLocation]::CurrentUser)
    $CertStore.Open([OpenFlags]::ReadOnly); $Thumbprints = $CertStore.Certificates.Where({ $_.Subject -eq $certSubject -and $_.FriendlyName -eq $FriendlyName }).Thumbprint
    if ($Thumbprints.count -gt 1) { Write-Warning 'Ambiguous certs' };
    $CertStore.Close();
    return $Thumbprints[0];
  }
  static [string] GetThumbprint([X509Certificate2]$certificate) {
    return $certificate.Thumbprint
  }

  static [void] SaveSelfSignedCertificate([X509Certificate2]$X509Cert2) {
    # Stores X509Cert2 in certificate store.
    $CertStore = [X509Store]::new([StoreName]::My, [StoreLocation]::CurrentUser);
    $CertStore.Open([OpenFlags]::ReadWrite);
    $CertStore.Add($X509Cert2);
    $CertStore.Close()
  }
  static [byte[]] Export([X509Certificate2]$certificate) {
    # By DEFAULT it Exports the certificate data in DER format.
    return [X509]::Export($certificate, [X509ContentType]::Cert)
  }
  static [byte[]] Export([X509Certificate2]$certificate, [X509ContentType]$contenttype) {
    return $certificate.Export($contenttype)
  }
  static [X509Certificate2] GetCertificate([byte[]]$rawData) {
    # do stuff here
    return [X509Certificate2]::new($rawData)
  }
  static [X509Certificate2] GetPfxCertificate([byte[]]$pfxData, [securestring]$password) {
    return [X509Certificate2]::new($pfxData, $password)
  }
  static [bool] TestCertificate([X509Certificate2]$certificate) {
    $passed_all_tests = $true
    # Check if the certificate has expired
    if ($certificate.NotAfter -lt [DateTime]::Now) {
      $passed_all_tests = $false
      Write-Host "Certificate has expired!"
    }
    # Check if the certificate has a specific key usage extension
    $keyUsageExtension = $certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.15" }
    if ($keyUsageExtension) {
      $keyUsageFlags = $keyUsageExtension.Format($false) -replace ".*?\((.*)\).*", '$1'
      if ($keyUsageFlags -notlike "*DigitalSignature*") {
        $passed_all_tests = $false
        Write-Host "Certificate does not have DigitalSignature key usage!"
      }
    } else {
      $passed_all_tests = $false
      Write-Host "Certificate does not have KeyUsage extension!"
    }
    # Check if the certificate has a specific extended key usage
    $extendedKeyUsage = $certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
    if ($extendedKeyUsage) {
      $extendedKeyUsageOids = $extendedKeyUsage.Format($false) -replace ".*?\((.*)\).*", '$1'
      if ($extendedKeyUsageOids -notlike "*1.3.6.1.5.5.7.3.1*") {
        $passed_all_tests = $false
        Write-Host "Certificate does not have Server Authentication extended key usage!"
      }
    } else {
      $passed_all_tests = $false
      Write-Host "Certificate does not have ExtendedKeyUsage extension!"
    }
    # More Custom Tests:
    $passed_all_tests = $passed_all_tests -and [X509]::IsCertificateRevoked($certificate) -and
    [X509]::IsKeyLengthValid($certificate) -and
    [X509]::IsSignatureAlgorithmValid($certificate) -and
    [X509]::ValidateCertificateChain($certificate)
    [X509]::IsSANsValid($certificate, ('', ''))

    return $passed_all_tests
  }
  static [string] GetOUname([string]$X500DistinguishedName) {
    $ou = [string]::Empty
    $rx = [RegularExpressions.Regex]::new("^(((CN=.*?))?)OU=(?<OUName>.*?(?=,))", "IgnoreCase")
    If ($rx.IsMatch($X500DistinguishedName) ) {
      $ou = $rx.Match($X500DistinguishedName).groups["OUName"].Value
    }
    return $ou
  }
  static [bool] IsValidDistinguishedName([string]$X500DistinguishedName) {
    return [X509]::IsValidDistinguishedName($X500DistinguishedName, $false)
  }
  static [bool] IsValidDistinguishedName([string]$X500DistinguishedName, [bool]$throwOnFailure) {
    # .DESCRIPTION
    # A valid distinguished name string must follow a specific format, where each attribute is identified by a key and a value, separated by an equal sign =, and each attribute is separated by a comma , . For example, "CN=ddd" is a valid distinguished name string because it has a key CN and a value ddd separated by an equal sign =.
    $IsValid = ![string]::IsNullOrWhiteSpace($X500DistinguishedName) -and [regex]::IsMatch($X500DistinguishedName, '^(?:(?:\s*[a-zA-Z][a-zA-Z0-9-]*\s*=\s*[a-zA-Z0-9\s]*\s*,\s*)*(?:\s*[a-zA-Z][a-zA-Z0-9-]*\s*=\s*[a-zA-Z0-9\s]*\s*))?$')
    if (!$IsValid -and $throwOnFailure) {
      throw 'Please Provide a valid certificate subject Name. eX: CN="name"'
    }
    return $IsValid
  }
  static [bool] IsCertificateRevoked([X509Certificate2]$certificate) {
    # .DESCRIPTION
    # Certificate Revocation Check: Perform a certificate revocation check by verifying if the certificate is listed in any certificate revocation lists (CRLs)
    # or if it has been revoked by the issuing certificate authority (CA).

    # Get the certificate chain:
    $chainPolicy = [X509ChainPolicy]::new();
    $chainPolicy.RevocationFlag = [X509RevocationFlag]::EntireChain
    $chainPolicy.RevocationMode = [X509RevocationMode]::Online

    $certificateChain = [X509Chain]::new();
    $certificateChain.ChainPolicy = $chainPolicy
    $certificateChain.Build($certificate)

    # Check if any certificate in the chain is revoked
    foreach ($element in $certificateChain.ChainElements) {
      foreach ($status in $element.ChainElementStatus) {
        if ($status.Status -eq [X509ChainStatusFlags]::Revoked) {
          Write-Host "Certificate is revoked" -ForegroundColor Green
          return $true
        }
      }
    }
    Write-Host "Certificate is not revoked" -ForegroundColor Red
    return $false
  }
  static [bool] IsKeyLengthValid([X509Certificate2]$certificate, [int]$minKeyLength) {
    # .DESCRIPTION
    # Key Length Check: Check the length of the public key in the certificate and ensure it meets your desired security requirements.
    # For example, you can check if the key length is at least 2048 bits for RSA certificates.
    $publicKey = $certificate.GetPublicKey();
    $publicKeyLength = $publicKey.Length * 8  # Convert byte length to bit length
    if ($publicKeyLength -ge $minKeyLength) {
      Write-Host "Key length is valid" -ForegroundColor Green
      return $true
    } else {
      Write-Host "Key length is not valid" -ForegroundColor Red
      return $false
    }
  }
  static [bool] IsSignatureAlgorithmValid([X509Certificate2]$certificate, [string]$requiredAlgorithm) {
    # .DESCRIPTION
    # Validate the signature algorithm used to sign the certificate.
    # Ensure it meets your desired security standards. Ex: you can check if the certificate is signed using a strong algorithm like SHA-256.
    # $requiredAlgorithm can be "SHA256", "SHA384", or "SHA512", among others.
    if ($certificate.SignatureAlgorithm.FriendlyName -eq $requiredAlgorithm) {
      Write-Host "Signature algorithm is valid" -ForegroundColor Green
      return $true
    } else {
      Write-Host "Signature algorithm is not valid" -ForegroundColor Red
      return $false
    }
  }
  static [bool] ValidateCertificateChain([X509Certificate2]$certificate) {
    # .DESCRIPTION
    # Validate the entire certificate chain up to the trusted root certificate.
    # Ensure that all intermediate certificates are present and correctly ordered in the chain, and that each certificate in the chain is valid and not expired.
    $chainPolicy = [X509ChainPolicy]::new();
    $chainPolicy.RevocationFlag = [X509RevocationFlag]::EntireChain
    $chainPolicy.RevocationMode = [X509RevocationMode]::Online
    $chainPolicy.VerificationFlags = [X509VerificationFlags]::NoFlag

    $certificateChain = [X509Chain]::new();
    $certificateChain.ChainPolicy = $chainPolicy
    $certificateChain.ChainPolicy.ExtraStore.Add($certificate)
    $certificateChain.Build($certificate)

    if ($certificateChain.ChainStatus.Length -eq 0) {
      Write-Host "Certificate chain is valid" -ForegroundColor Green
      return $true
    } else {
      Write-Host "Certificate chain is not valid" -ForegroundColor Red
      return $false
    }
  }
  static [bool] IsSANsValid([X509Certificate2]$certificate, [string[]]$requiredSANs) {
    #  Check if the certificate includes the required Subject Alternative Names (SANs) for your specific use case, such as DNS names, IP addresses, or email addresses.
    # Ex:
    # $requiredSANs = @(
    #     "www.example.com",
    #     "subdomain.example.com",
    #     "192.168.0.1"
    # )
    $certificateSANs = $certificate.Extensions.Where({ $_.Oid.FriendlyName -eq "Subject Alternative Name" }).Foreach({ $_.Format($false) -split ', ' });
    foreach ($requiredSAN in $requiredSANs) {
      if ($certificateSANs -contains $requiredSAN) {
        return $true  # Required SAN found in the certificate
      }
    }
    return $false  # Required SAN not found in the certificate
  }
  static [bool] IsCertificatePolicyValid([X509Certificate2]$certificate, [string]$requiredPolicy) {
    # Validate if the certificate adheres to specific certificate policies defined by your organization or industry standards.
    # /!\ Not sure how to write this one!

    $certificatePolicies = $certificate.Extensions |
      Where-Object { $_.Oid.FriendlyName -eq "Certificate Policies" } |
      ForEach-Object { $_.Format($false) -split ', ' }

    if ($certificatePolicies -contains $requiredPolicy) {
      return $true  # Required certificate policy is found
    } else {
      return $false  # Required certificate policy is not found
    }
  }
  static [bool] IsExtendedValidationValid([X509Certificate2]$certificate, [Oid]$ValidationOID) {
    # If you are dealing with Extended Validation (EV) certificates, perform additional checks specific to EV requirements,
    # such as verifying the presence of the EV OID in the certificate.
    $extendedValidationOID = $ValidationOID.Value
    $certificateExtensions = $certificate.Extensions
    foreach ($extension in $certificateExtensions) {
      if ($extension.Oid.Value -eq $extendedValidationOID) {
        Write-Host "Extended Validation flag is present" -ForegroundColor Green
        return $true
      }
    }
    Write-Host "Extended Validation flag is not present" -ForegroundColor Red
    return $false
  }
  static [RSAEncryptionPadding]GetRSAPadding () {
    return $(& ([ScriptBlock]::Create("[System.Security.Cryptography.RSAEncryptionPadding]::$([Enum]::GetNames([RSAPadding]) | Get-Random)")))
  }
  static [RSAEncryptionPadding]GetRSAPadding([string]$Padding) {
    if (!(($Padding -as 'RSAPadding') -is [RSAPadding])) {
      throw "Value Not in Validateset."
    }
    return $(& ([ScriptBlock]::Create("[System.Security.Cryptography.RSAEncryptionPadding]::$Padding")))
  }
  static [RSAEncryptionPadding]GetRSAPadding([RSAEncryptionPadding]$Padding) {
    [RSAEncryptionPadding[]]$validPaddings = [Enum]::GetNames([RSAPadding]) | ForEach-Object { & ([ScriptBlock]::Create("[System.Security.Cryptography.RSAEncryptionPadding]::$_")) }
    if ($Padding -notin $validPaddings) {
      throw "Value Not in Validateset."
    }
    return $Padding
  }
  static [X509Certificate2] Import([string]$FilePath, [securestring]$Password) {
    return [X509Certificate2]::new($FilePath, $Password);
  }

  static [void] Export([X509Certificate2]$Cert, [string]$FilePath, [string]$Passw0rd) {
    $Cert.Export([X509ContentType]::Pfx, $Passw0rd) | Set-Content -Path $FilePath -Encoding byte
  }
  static [IO.FileInfo] GetOpenssl () {
    # Return the path to openssl executable file & Will install it if not found :)
    $file = [IO.FileInfo](Get-Command -Name OpenSSL -Type Application -ErrorAction Ignore).Source
    if (!$file -or !$file.Exists) {
      if (!(Get-Command -Name Install-OpenSSL -Type ExternalScript -ErrorAction Ignore)) { Install-Script -Name Install-OpenSSL -Repository PSGallery -Scope CurrentUser }
      Install-OpenSSL
    }
    return $file
  }
}
# static [void]Import() {}
# static [string]Export([X509Certificate2]$cert, [X509ContentType]$contentType) {
#     # Ex:
#     if ($contentType -eq 'PEM') {
#         $InsertLineBreaks = 1
#         $oMachineCert = Get-Item Cert:\LocalMachine\My\1C0381278083E3CB026E46A7FF09FC4B79543D
#         $oPem = New-Object System.Text.StringBuilder
#         $oPem.AppendLine("-----BEGIN CERTIFICATE-----")
#         $oPem.AppendLine([System.Convert]::ToBase64String($oMachineCert.RawData, $InsertLineBreaks))
#         $oPem.AppendLine("-----END CERTIFICATE-----")
#         $oPem.ToString() | Out-File D:\Temp\my.pem

#         # Or load a certificate from a file and convert it to pem format
#         $InsertLineBreaks = 1
#         $sMyCert = "D:\temp\myCert.der"
#         $oMyCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sMyCert)
#         $oPem = New-Object System.Text.StringBuilder
#         $oPem.AppendLine("-----BEGIN CERTIFICATE-----")
#         $oPem.AppendLine([System.Convert]::ToBase64String($oMyCert.RawData, $InsertLineBreaks))
#         $oPem.AppendLine("-----END CERTIFICATE-----")
#         $oPem.ToString() | Out-File D:\Temp\my.pem
#     }
#     # $cert.Issuer = Get-CimInstance -ClassName Win32_UserAccount -Verbose:$false | Where-Object { $_.Name -eq $(whoami) } | Select-Object -ExpandProperty FullName
#     # X509Certificate2 pfxGeneratedCert = new X509Certificate2(generatedCert.Export(X509ContentType.Pfx));
#     # has to be turned into pfx or Windows at least throws a security credentials not found during sslStream.connectAsClient or HttpClient request...
#     # return pfxGeneratedCert;
#     return ''
# }
#endregion X509

#region    ecc
# .SYNOPSIS
#     Elliptic Curve Cryptography
# .DESCRIPTION
#     Asymmetric-key encryption algorithms that are known for their strong security and efficient use of resources. They are widely used in a variety of applications, including secure communication, file encryption, and password storage.
# .EXAMPLE
#     $ecc = new ECC($publicKeyXml, $privateKeyXml)
#     $encryptedData = $ecc.Encrypt($data, $password, $salt)
#     $decryptedData = $ecc.Decrypt($encryptedData, $password, $salt)
class ECC : xcrypt {
  $publicKeyXml = [string]::Empty
  $privateKeyXml = [string]::Empty

  # Constructor
  ECC([string]$publicKeyXml, [string]$privateKeyXml) {
    $this.publicKeyXml = $publicKeyXml
    $this.privateKeyXml = $privateKeyXml
  }
  # Encrypts the specified data using the public key.
  # The data is encrypted using AES in combination with the password and salt.
  # Normally I could use System.Security.Cryptography.ECCryptoServiceProvider but for Compatibility reasons
  # I use ECDsaCng class, which provides similar functionality.
  # The encrypted data is then encrypted using ECC.
  # Encrypts the specified data using the public key.
  # The data is encrypted using AES in combination with the password and salt.
  # The encrypted data is then encrypted using ECC.
  [byte[]] Encrypt([byte[]]$data, [securestring]$password, [byte[]]$salt) {
    # Generate the AES key and initialization vector from the password and salt
    $aesKey = [Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1000).GetBytes(32);
    $aesIV = [Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1000).GetBytes(16);
    # Encrypt the data using AES
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $aesKey
    $aes.IV = $aesIV
    $encryptedData = $aes.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)

    # Encrypt the AES key and initialization vector using ECC
    $ecc = New-Object System.Security.Cryptography.ECDsaCng
    $ecc.FromXmlString($this.publicKeyXml)
    $encryptedKey = $ecc.Encrypt($aesKey, $true)
    $encryptedIV = $ecc.Encrypt($aesIV, $true)

    # Concatenate the encrypted key, encrypted IV, and encrypted data
    # and return the result as a byte array
    return [byte[]]([System.Linq.Enumerable]::Concat($encryptedKey, $encryptedIV, $encryptedData))
    # or:
    # $bytes = New-Object System.Collections.Generic.List[Byte]
    # $bytes.AddRange($encryptedKey)
    # $bytes.AddRange($encryptedIV)
    # $bytes.AddRange($encryptedData)
    # return [byte[]]$Bytes
  }
  # Decrypts the specified data using the private key.
  # The data is first decrypted using ECC to obtain the AES key and initialization vector.
  # The data is then decrypted using AES.
  [byte[]] Decrypt([byte[]]$data, [securestring]$password) {
    # Extract the encrypted key, encrypted IV, and encrypted data from the input data
    $encryptedKey = $data[0..255]
    $encryptedIV = $data[256..271]
    $encryptedData = $data[272..$data.Length]

    # Decrypt the AES key and initialization vector using ECC
    $ecc = [ECDsaCng]::new();
    $ecc.FromXmlString($this.privateKeyXml)
    $aesKey = $ecc.Decrypt($encryptedKey, $true)
    $aesIV = $ecc.Decrypt($encryptedIV, $true)

    # Decrypt the data using AES
    $aes = [AesCryptoServiceProvider]::new();
    $aes.Key = $aesKey
    $aes.IV = $aesIV
    return $aes.CreateDecryptor().TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
  }
  # Generates a new ECC key pair and returns the public and private keys as XML strings.
  [string] GenerateKeyPair() {
    $ecc = [ECDsaCng]::new(256)
        ($publicKey, $privateKey) = ($ecc.ToXmlString($false), $ecc.ToXmlString($true))
    return $publicKey, $privateKey
  }
  # Exports the ECC key pair to a file or string.
  # If a file path is specified, the keys are saved to the file.
  # If a string is specified, the keys are returned as a string.
  # Usage:
  # $ECC.ExportKeyPair("C:\keys.xml")
  [string] ExportKeyPair([string]$file = $null) {
    # Create the key pair XML string
    $keyPairXml = "
            <keyPair>
                <publicKey>$($this.publicKeyXml)</publicKey>
                <privateKey>$($this.privateKeyXml)</privateKey>
            </keyPair>
        "
    # Save the key pair XML to a file or return it as a string
    if ($null -ne $file) {
      $keyPairXml | Out-File -Encoding UTF8 $file
      return $null
    } else {
      return $keyPairXml
    }
  }
  # Imports the ECC key pair from a file or string.
  # If a file path is specified, the keys are loaded from the file.
  # If a string is specified, the keys are loaded from the string.
  [void] ImportKeyPair([string]$filePath = $null, [string]$keyPairXml = $null) {
    # Load the key pair XML from a file or string
    if (![string]::IsNullOrWhiteSpace($filePath)) {
      if ([IO.File]::Exists($filePath)) {
        $keyPairXml = Get-Content -Raw -Encoding UTF8 $filePath
      } else {
        throw [FileNotFoundException]::new('Unable to find the specified file.', "$filePath")
      }
    } else {
      throw [ArgumentNullException]::new('filePath')
    }
    # Extract the public and private key XML strings from the key pair XML
    $publicKey = ([xml]$keyPairXml).keyPair.publicKey
    $privateKey = ([xml]$keyPairXml).keyPair.privateKey

    # Set the public and private key XML strings in the ECC object
    $this.publicKeyXml = $publicKey
    $this.privateKeyXml = $privateKey
  }
}
#endregion ecc

#region    MD5
class MD5 : xcrypt {
  MD5() {}
  static [byte[]] Encrypt([byte[]]$data, [string]$hash) {
    $md5 = [MD5CryptoServiceProvider]::new()
    $encoderShouldEmitUTF8Identifier = $false
    $encoder = [UTF8Encoding]::new($encoderShouldEmitUTF8Identifier)
    $keys = [byte[]]$md5.ComputeHash($encoder.GetBytes($hash));
    return [TripleDES]::Encrypt($data, $keys, $hash.Length);
  }
  static [byte[]] Decrypt([byte[]]$data, [string]$hash) {
    $md5 = [MD5CryptoServiceProvider]::new()
    $encoderShouldEmitUTF8Identifier = $false
    $encoder = [UTF8Encoding]::new($encoderShouldEmitUTF8Identifier)
    $keys = [byte[]]$md5.ComputeHash($encoder.GetBytes($hash));
    return [TripleDES]::Decrypt($data, $keys, $hash.Length);
  }
}
#endregion MD5


#region    TripleDES
# .SYNOPSIS
#     Triple Des implementation in Powershell
# .EXAMPLE
#     $t = [TripleDES]::new(3004)
#     $e = $t.Encrypt(30) # i.e: 30 times
#     [convert]::ToBase64String($e) > enc.txt
#
#     # On the same PC
#     $n = [TripleDES]::new([convert]::FromBase64String($(Get-Content ./enc.txt)))
#     $d = $n.Decrypt(30)
#     echo (Bytes_To_Object($d)) # should be 3004
# .EXAMPLE
#    # Use static methods
class TripleDES : xcrypt {
  [ValidateNotNullOrEmpty()][cPsObject]$Object;
  [ValidateNotNullOrEmpty()][SecureString]$Password;
  static hidden [byte[]] $Salt = [Encoding]::UTF7.GetBytes('@Q:j9=`M?EV/h>9_M/esau>A)Y6h>/v^q\ZVMPH\Vu5/E"P_GN`#t6Wnf;ah~[dik.fkj7vpoSqqN]-u`tSS5o26?\u).6YF-9e_5-KQ%kf)A{P4a9/67J8v]:[%i8PW');

  TripleDES([Object]$object) {
    $this.Object = [cPsObject]::new($object)
    $this.Password = [Encoding]::UTF7.GetString([Rfc2898DeriveBytes]::new([xcrypt]::GetUniqueMachineId(), [TripleDES]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(24)) | xconvert ToSecurestring
  }
  [byte[]]Encrypt() {
    return $this.Encrypt(1);
  }
  [byte[]]Encrypt([int]$iterations) {
    if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
    if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
    $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([TripleDES]::Encrypt($this.Object.Bytes, [Rfc2898DeriveBytes]::new(($this.Password | xconvert ToString), [TripleDES]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations)))')")));
    return $this.Object.Bytes
  }
  [byte[]]Decrypt() {
    return $this.Decrypt(1);
  }
  [byte[]]Decrypt([int]$iterations) {
    if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
    if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
    $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([TripleDES]::Decrypt($this.Object.Bytes, [Rfc2898DeriveBytes]::new(($this.Password | xconvert ToString), [TripleDES]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations)))')")));
    return $this.Object.Bytes
  }
  static [byte[]] Encrypt([Byte[]]$data, [Byte[]]$Key) {
    return [TripleDES]::Encrypt($data, $Key, $null, 1)
  }
  static [byte[]] Encrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV) {
    return [TripleDES]::Encrypt($data, $Key, $IV, 1)
  }
  static [byte[]] Encrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [int]$iterations) {
    for ($i = 1; $i -le $iterations; $i++) { $data = [TripleDES]::Get_ED($data, $Key, $IV, $true) }
    return $data
  }
  static [byte[]] Encrypt ([byte]$data, [securestring]$Password) {
    return [TripleDES]::Encrypt($data, $Password, 1);
  }
  static [byte[]] Encrypt ([byte]$data, [string]$Passw0rd, [int]$iterations) {
    return [TripleDES]::Encrypt($data, [Rfc2898DeriveBytes]::new($Passw0rd, [TripleDES]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations);
  }
  static [byte[]] Encrypt ([byte]$data, [securestring]$Password, [int]$iterations) {
    return [TripleDES]::Encrypt($data, ($Password | xconvert ToString), $iterations)
  }
  static [byte[]] Decrypt([Byte[]]$data, [Byte[]]$Key) {
    return [TripleDES]::Decrypt($data, $Key, $null, 1);
  }
  static [byte[]] Decrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV) {
    return [TripleDES]::Decrypt($data, $Key, $IV, 1);
  }
  static [byte[]] Decrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [int]$iterations) {
    for ($i = 1; $i -le $iterations; $i++) { $data = [TripleDES]::Get_ED($data, $Key, $IV, $false) }
    return $data
  }
  static [byte[]] Decrypt ([byte]$data, [securestring]$Password) {
    return [TripleDES]::Decrypt($data, $Password, 1)
  }
  static [byte[]] Decrypt ([byte]$data, [string]$Passw0rd, [int]$iterations) {
    return [TripleDES]::Decrypt($data, [Rfc2898DeriveBytes]::new($Passw0rd, [TripleDES]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations);
  }
  static [byte[]] Decrypt ([byte]$data, [securestring]$Password, [int]$iterations) {
    return [TripleDES]::Decrypt($data, ($Password | xconvert ToString), $iterations)
  }
  static hidden [byte[]] Get_ED([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [bool]$Encrypt) {
    $result = [byte[]]::new(0); $ms = [MemoryStream]::new(); $cs = $null
    try {
      $tdes = [TripleDESCryptoServiceProvider]::new()
      if ($null -eq $Key) { throw ([System.ArgumentNullException]::new('Key')) }else { $tdes.Key = $Key }
      if ($null -eq $IV) { $p4 = [xcrypt]::GetUniqueMachineId(); $tdes.IV = [Rfc2898DeriveBytes]::new($p4, [TripleDES]::Salt, [int]([int[]][char[]]$p4 | Measure-Object -Sum).Sum, [HashAlgorithmName]::SHA1).GetBytes(8) }else { $tdes.IV = $IV }
      $CryptoTransform = [ICryptoTransform]$(if ($Encrypt) { $tdes.CreateEncryptor() }else { $tdes.CreateDecryptor() })
      $cs = [CryptoStream]::new($ms, $CryptoTransform, [CryptoStreamMode]::Write)
      [void]$cs.Write($data, 0, $data.Length)
      [void]$cs.FlushFinalBlock()
      $ms.Position = 0
      $result = [Byte[]]::new($ms.Length)
      [void]$ms.Read($result, 0, $ms.Length)
    } catch [CryptographicException] {
      if ($_.exception.message -notlike "*data is not a complete block*") { throw $_.exception }
    } finally {
      Invoke-Command -ScriptBlock { $tdes.Clear(); $cs.Close(); $ms.Dispose() } -ErrorAction SilentlyContinue
    }
    return $result
  }
}
#endregion TripleDES

#region    XOR
# .SYNOPSIS
#     Custom Xor implementation in Powershell
# .EXAMPLE
#     $x = [XOR]::new("hello world!")
#     $e = $x.Encrypt(5) # i.e: 5 times
#     [convert]::ToBase64String($e) > xenc.txt
#
#     # On the same PC
#     $n = [XoR]::new([convert]::FromBase64String($(Get-Content ./xenc.txt)))
#     $d = $n.Decrypt(5)
#     echo (Bytes_To_Object($d)) # should be hello world!
# .EXAMPLE
#    # Use static methods
class XOR : xcrypt {
  [ValidateNotNullOrEmpty()][cPsObject]$Object;
  [ValidateNotNullOrEmpty()][SecureString]$Password;
  static hidden [byte[]] $Salt = [Encoding]::UTF7.GetBytes('\SBOv!^L?XuCFlJ%*[6(pUVp5GeR^|U=NH3FaK#XECOaM}ExV)3_bkd:eG;Z,tWZRMg;.A!,:-k6D!CP>74G+TW7?(\6;Li]lA**2P(a2XxL}<.*oJY7bOx+lD>%DVVa');
  XOR([Object]$object) {
    $this.Object = [cPsObject]::new($object)
    $this.Password = [Encoding]::UTF7.GetString([Rfc2898DeriveBytes]::new([xcrypt]::GetUniqueMachineId(), [XOR]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(256 / 8)) | xconvert ToSecurestring
  }
  [byte[]] Encrypt() {
    return $this.Encrypt(1)
  }
  [byte[]] Encrypt([int]$iterations) {
    if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
    if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('key')) }
    $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([byte[]][XOR]::Encrypt($this.Object.Bytes, $this.Password, $iterations)))')")))
    return $this.Object.Bytes
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [String]$Passw0rd) {
    return [XOR]::Encrypt($bytes, ([Encoding]::UTF7.GetString([Rfc2898DeriveBytes]::new($Passw0rd, [XOR]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(256 / 8)) | xconvert ToSecurestring), 1)
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$password) {
    return [XOR]::Encrypt($bytes, $password, 1)
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$password, [int]$iterations) {
    $xorkey = $password | xconvert ToString, ToBytes;
    return [XOR]::Encrypt($bytes, $xorkey, $iterations)
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [byte[]]$xorkey, [int]$iterations) {
    if ($null -eq $xorkey) {
      throw ([System.ArgumentNullException]::new('xorkey'))
    }
    $_bytes = $bytes;
    for ($i = 1; $i -lt $iterations + 1; $i++) {
      $_bytes = [XOR]::Get_ED($_bytes, $xorkey);
    }; if ($_bytes.Equals($bytes)) { $_bytes = $null }
    return $_bytes
  }
  [byte[]]Decrypt() {
    return $this.Decrypt(1)
  }
  [byte[]]Decrypt([int]$iterations) {
    if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
    if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
    $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([byte[]][XOR]::Decrypt($this.Object.Bytes, $this.Password, $iterations)))')")));
    return $this.Object.Bytes
  }
  #!Not Recommended!
  static [byte[]] Decrypt([byte[]]$Bytes, [String]$Passw0rd) {
    return [XOR]::Decrypt($bytes, ([Encoding]::UTF7.GetString([Rfc2898DeriveBytes]::new($Passw0rd, [XOR]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(256 / 8)) | xconvert ToSecurestring), 1);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$password) {
    return [XOR]::Decrypt($bytes, $password, 1);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$password, [int]$iterations) {
    $xorkey = $password | xconvert ToString, ToBytes
    return [XOR]::Decrypt($bytes, $xorkey, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [byte[]]$xorkey, [int]$iterations) {
    if ($null -eq $xorkey) {
      throw ([System.ArgumentNullException]::new('xorkey'))
    }
    $_bytes = $bytes; for ($i = 1; $i -lt $iterations + 1; $i++) {
      $_bytes = [XOR]::Get_ED($_bytes, $xorkey)
    };
    return $_bytes;
  }
  static hidden [byte[]] Get_ED([byte[]]$Bytes, [byte[]]$key) {
    return $(for ($i = 0; $i -lt $bytes.length) {
        for ($j = 0; $j -lt $key.length; $j++) {
          $bytes[$i] -bxor $key[$j]
          $i++
          if ($i -ge $bytes.Length) {
            $j = $key.length
          }
        }
      }
    )
  }
}
#endregion XOR

#region    RC4
# .SYNOPSIS
#     PowerShell class implementation of the RC4 algorithm
# .DESCRIPTION
#     "Ron's Code 4" or "Rivest Cipher 4," depending on the source.
#     A symmetric key stream cipher that was developed by Ron Rivest of RSA Security in 1987.
#     It was widely used in the 1990s and early 2000s, but has since been replaced by more secure algorithms in many applications due to vulnerabilities.
# .NOTES
#     RC4 is an old and insecure encryption algorithm.
#     It is recommended to use a more modern and secure algorithm, such as AES or ChaCha20.
#     But if you insist on using this, Just Use really strong passwords.
#     I mean shit like: Wwi@4c5w&@hOtf}Mm_t%&[BXq>5*0:Fm}6L'poyi!8LoZD\!HXPPPvMRas<CWl$yk${vlW9(f:S@w/E
# .EXAMPLE
#     $dat = Bytes_From_Object("Hello World")
#     $enc = [rc4]::Encrypt($dat, (Read-Host -AsSecureString -Prompt 'Password'))
#     $dec = [rc4]::Decrypt($enc, (Read-Host -AsSecureString -Prompt 'Password'))
#     Bytes_To_Object($dec)
class RC4 : xcrypt {
  static [Byte[]] Encrypt([Byte[]]$data, [Byte[]]$passwd) {
    $a = $i = $j = $k = $tmp = [Int]0
    $key = [Int[]]::new(256)
    $box = [Int[]]::new(256)
    $cipher = [Byte[]]::new($data.Length)
    for ($i = 0; $i -lt 256; $i++) {
      $key[$i] = $passwd[$i % $passwd.Length];
      $box[$i] = $i;
    }
    for ($j = $i = 0; $i -lt 256; $i++) {
      $j = ($j + $box[$i] + $key[$i]) % 256;
      $tmp = $box[$i];
      $box[$i] = $box[$j];
      $box[$j] = $tmp;
    }
    for ($a = $j = $i = 0; $i -lt $data.Length; $i++) {
      $a++;
      $a %= 256;
      $j += $box[$a];
      $j %= 256;
      $tmp = $box[$a];
      $box[$a] = $box[$j];
      $box[$j] = $tmp;
      $k = $box[(($box[$a] + $box[$j]) % 256)];
      $cipher[$i] = [Byte]($data[$i] -bxor $k);
    }
    return $cipher;
  }
  static [Byte[]] Decrypt([Byte[]]$data, [Byte[]]$passwd) {
    return [RC4]::Encrypt($data, $passwd);
    # The Decrypt method simply calls the Encrypt method with the same arguments.
    # This is because the RC4 algorithm is symmetric, meaning that the same key is used for both encryption and decryption.
    # Therefore, the encryption and decryption processes are identical.
  }
}
#endregion RC4

#region    CHACHA20
# .SYNOPSIS
#     An implementation of the ChaCha20 encryption algorithm in PowerShell.
# .DESCRIPTION
#     Its derived from the Salsa20 stream cipher algorithm, with several changes like integrity checking to improve its security and performance.
#     ChaCha20 operates on a 256-bit key, a 64-bit nonce, and a 20-round pseudo-random number generator to generate keystream data.
#     The algorithm is highly efficient, making it well-suited for use in a wide range of applications, including encryption, digital signatures, and key derivation.
# .NOTES
#     Encryption is a subtle and complex area and it's easy to make mistakes that can leave you vulnerable to attack.
#     While this implementation is functional, its not 100% tested. In a enterprise env practice, you should use a well-vetted implementation, like one from a reputable library.
#     You should also consider additional measures like key management, which are crucial for the security of the encryption and use a secure method for generating the key and nonce, such as using the System.Security.Cryptography.RNGCryptoServiceProvider class.
# .LINK
#     https://github.com/chadnpc/cliHelper.core/blob/main/Private/cliHelper.core.xcrypt/cliHelper.core.xcrypt.psm1
# .EXAMPLE
#     $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider; $key = New-Object Byte[] 32; $rng.GetBytes($key); $IV = New-Object Byte[] 16; $rng.GetBytes($IV)
#     $bytes = [Text.Encoding]::UTF8.GetBytes("my secret message")
#     $enc = [chacha20]::Encrypt($bytes, $key, $IV)
#     $dec = [chacha20]::Decrypt($enc, $key, $IV)
#     echo ([Text.Encoding]::UTF8.GetString($dec)) # should be: my secret message
# .EXAMPLE
#     $enc = [Chacha20]::Encrypt($bytes, (Read-Host -AsSecureString -Prompt "Passwd"), 5)
#     $dec = [chacha20]::Decrypt($enc, (Read-Host -AsSecureString -Prompt "Passwd"), 5)
#     echo ([Text.Encoding]::UTF8.GetString($dec))
Class ChaCha20 : xcrypt {
  static hidden [Int32]$blockSize = 64
  static hidden [Byte[]]$SIGMA = [Byte[]]@(83, 72, 65, 67, 72, 65, 50, 48, 87, 65, 86, 69)
  static hidden [byte[]]$Salt = [convert]::FromBase64String('plqnkknbuujsklslyscgkycobvflyqwrttalqqjidosyjrodkiuxcokwjrftfyyttipfvtwodwrnvsre')

  static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password) {
    return [Chacha20]::Encrypt($Bytes, $Password, [ChaCha20]::Salt)
  }
  static [Byte[]] Encrypt([Byte[]]$bytes, [Byte[]]$key, [Byte[]]$nonce) {
    # Write-Debug "Nptb64: $([convert]::ToBase64String($bytes))" -Debug
    [byte[]]$hash = [SHA256CryptoServiceProvider]::new().ComputeHash($bytes)
    [byte[]]$bytes = $bytes + $hash # Used for integrity check ie: We append a cryptographic hash (e.g., SHA-256) before encryption, and then check the hash of the decrypted plainBytes against the original hash after decryption.
    [Byte[]]$EncrBytes = [Byte[]]::new($bytes.Length)
    [Byte[]]$block = [Byte[]]::new([ChaCha20]::blockSize)
    [Int32]$bytesIndex = 0
    [Int32]$EncrnIndex = 0
    [Int32]$blockCounter = 0
    while ($bytesIndex -lt $bytes.Length) {
      $block = [ChaCha20]::GenerateBlock($blockCounter, $key, $nonce)
      [Int32]$bytesToCopy = [Math]::Min($bytes.Length - $bytesIndex, [ChaCha20]::blockSize)
      for ([Int32]$i = 0; $i -lt $bytesToCopy; $i++) {
        $EncrBytes[$EncrnIndex + $i] = $bytes[$bytesIndex + $i] -bxor $block[$i]
      }
      $bytesIndex += $bytesToCopy
      $EncrnIndex += $bytesToCopy
      $blockCounter++
    }
    # Write-Debug "Encb64: $([convert]::ToBase64String($EncrBytes))" -Debug
    return $EncrBytes
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [byte[]]$Salt) {
    return [Chacha20]::Encrypt($Bytes, $Password, $Salt, 1)
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [int]$iterations) {
    return [Chacha20]::Encrypt($Bytes, $Password, [ChaCha20]::Salt, $iterations)
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [byte[]]$Salt, [int]$iterations) {
    [byte[]]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value ([Rfc2898DeriveBytes]::new(($Password | xconvert ToString), $Salt, 10000, [HashAlgorithmName]::SHA1).GetBytes(32));
    $_bytes = $bytes; if ([string]::IsNullOrWhiteSpace([ChaCha20]::caller)) { [ChaCha20]::caller = '[ChaCha20]' }
    for ($i = 1; $i -lt $iterations + 1; $i++) {
      Write-Host "$([ChaCha20]::caller) [+] Encryption [$i/$iterations] ...$(
                # Generate a random IV for each iteration:
                [byte[]]$IV = $null; Set-Variable -Name IV -Scope Local -Visibility Private -Option Private -Value ([Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1, [HashAlgorithmName]::SHA1).GetBytes(16));
                $_bytes = [Shuffl3r]::Combine([Chacha20]::Encrypt($_bytes, $Key, $IV), $IV, $Password)
            ) Done" -ForegroundColor Yellow
    }
    return $_bytes
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [securestring]$Password) {
    return [ChaCha20]::Decrypt($Bytes, $Password, [ChaCha20]::Salt)
  }
  static [byte[]] Decrypt([byte[]]$bytes, [byte[]]$key, [byte[]]$nonce) {
    [byte[]]$decrBytes = [byte[]]::new($bytes.Length);
    [Int32]$bytesIndex = 0
    [Int32]$decrnIndex = 0
    while ($bytesIndex -lt $bytes.Length) {
      [Int32]$blockCounter = $bytesIndex / [ChaCha20]::blockSize
      [Int32]$bytesToCopy = [Math]::Min($bytes.Length - $bytesIndex, [ChaCha20]::blockSize)
      [Byte[]]$block = [ChaCha20]::GenerateBlock($blockCounter, $key, $nonce)
      for ($i = 0; $i -lt $bytesToCopy; $i++) {
        $decrBytes[$decrnIndex + $i] = $bytes[$bytesIndex + $i] -bxor $block[$i]
      }
      $bytesIndex += [ChaCha20]::blockSize
      $decrnIndex += $bytesToCopy
    }
    $hash = $decrBytes | Select-Object -Last 32
    $decr = $decrBytes | Select-Object -First ($decrBytes.Length - 32)
    if ([convert]::ToBase64String([SHA256CryptoServiceProvider]::new().ComputeHash($decr)) -ne [convert]::ToBase64String($hash)) {
      throw [IntegrityCheckFailedException]"Integrity check failed"
    }
    # Write-Debug "Decb64: $([convert]::ToBase64String($decr))" -Debug
    return $decr
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [securestring]$Password, [byte[]]$Salt) {
    return [ChaCha20]::Decrypt($Bytes, $Password, $Salt, 1)
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [securestring]$Password, [int]$iterations) {
    return [ChaCha20]::Decrypt($Bytes, $Password, [ChaCha20]::Salt, $iterations)
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [securestring]$Password, [byte[]]$Salt, [int]$iterations) {
    [byte[]]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value ([Rfc2898DeriveBytes]::new(($Password | xconvert ToString), $Salt, 10000, [HashAlgorithmName]::SHA1).GetBytes(32));
    $_bytes = $bytes; if ([string]::IsNullOrWhiteSpace([ChaCha20]::caller)) { [ChaCha20]::caller = '[ChaCha20]' }
    for ($i = 1; $i -lt $iterations + 1; $i++) {
      Write-Host "$([ChaCha20]::caller) [+] Decryption [$i/$iterations] ...$(
                $bytes = $null; $IV = $null
                ($bytes, $IV) = [Shuffl3r]::Split($_bytes, $Password, 16);
                $_bytes = [Chacha20]::Decrypt($bytes, $Key, $IV)
            ) Done" -ForegroundColor Yellow
    }
    return $_bytes
  }
  static hidden [Byte[]] GenerateBlock([Int32]$blockCounter, [Byte[]]$key, [Byte[]]$nonce) {
    [Int32[]]$state = [Int32[]]@(
      0x61707865, 0x3320646E, 0x79622D32, 0x6B206574, # constant
      0, 0, 0, 0, # block counter
      [BitConverter]::ToInt32($key[0..3], 0), [BitConverter]::ToInt32($key[4..7], 0), [BitConverter]::ToInt32($key[8..11], 0), [BitConverter]::ToInt32($key[12..15], 0), # key
      [BitConverter]::ToInt32($key[16..19], 0), [BitConverter]::ToInt32($key[20..23], 0), [BitConverter]::ToInt32($key[24..27], 0), [BitConverter]::ToInt32($key[28..31], 0),
      0, 0, # nonce
      0, 0
    )
    $state[12] = $blockCounter
    $state[14] = [BitConverter]::ToInt32($nonce[0..3], 0)
    $state[15] = [BitConverter]::ToInt32($nonce[4..7], 0)

    for ([Int32]$i = 0; $i -lt 10; $i++) {
      [BitwUtil]::QuaterRound([ref]$state[0], [ref]$state[4], [ref]$state[8], [ref]$state[12])
      [BitwUtil]::QuaterRound([ref]$state[1], [ref]$state[5], [ref]$state[9], [ref]$state[13])
      [BitwUtil]::QuaterRound([ref]$state[2], [ref]$state[6], [ref]$state[10], [ref]$state[14])
      [BitwUtil]::QuaterRound([ref]$state[3], [ref]$state[7], [ref]$state[11], [ref]$state[15])
      [BitwUtil]::QuaterRound([ref]$state[0], [ref]$state[5], [ref]$state[10], [ref]$state[15])
      [BitwUtil]::QuaterRound([ref]$state[1], [ref]$state[6], [ref]$state[11], [ref]$state[12])
      [BitwUtil]::QuaterRound([ref]$state[2], [ref]$state[7], [ref]$state[8], [ref]$state[13])
      [BitwUtil]::QuaterRound([ref]$state[3], [ref]$state[4], [ref]$state[9], [ref]$state[14])
    }
    [Byte[]]$result = [Byte[]]::new($state.Length * 4)
    for ([Int32]$i = 0; $i -lt $state.Length; $i++) {
      # Copy the bytes from the $i-th int in $state to the correct position in $result
      [Array]::Copy([BitConverter]::GetBytes($state[$i]), 0, $result, $i * 4, 4)
    }
    return $result
  }
}
#endregion CHACHA20

#region    Poly1305
# .DESCRIPTION
#     Using Poly1305 for integrity checking is a better option than using SHA-256 in terms of security.
#     Poly1305 is a faster and more secure message authentication code (MAC) algorithm compared to SHA-256.
# .NOTES
#     This Class would be amazing but it not functional; ...yet. Yeal its total bs :)
class Poly1305 : xcrypt {
  [Byte[]]$Key

  Poly1305([Byte[]]$key) {
    if ($key.Length -ne 32) {
      throw [ArgumentException]"Invalid key size. Key must be 32 bytes."
    }
    $this.Key = $key
  }
  [byte[]] ComputeHash([Byte[]]$nput) {
    # Constants
    $block = $null
    $blockSize = 16
    $blockLength = $blockSize * 4
    $r = New-Object 'UInt64[]' 16
    $h = New-Object 'UInt64[]' 17

    # Initialize r array
    for ($i = 0; $i -lt 16; $i++) {
      if (($i * 8) + 7 -lt $this.Key.Length) {
        $r[$i] = [BitConverter]::ToUInt64($this.Key, ($i * 8))
      } else {
        $r[$i] = 0
      }
    }
    for ($i = 0; $i -lt 17; $i++) {
      $h[$i] = 0
    }
    # Process input bytes
    for ($offset = 0; $offset -lt $nput.Length; $offset += $blockLength) {
      $block = New-Object 'Byte[]' $blockLength
      [Array]::Copy($nput, $offset, $block, 0, [Math]::Min($blockLength, $nput.Length - $offset))
            ($h, $r, $block) = $this.Poly1305_Block($h, $r, $block)
    }

    # Finalize
    [UInt64]$s = 0
    for ($i = 0; $i -lt 16; $i++) {
      $s = ($s + $h[$i]) -band 0xffffffff
      if ($i -eq 15) {
        break
      }
      $s = ($s -shr 26) -band 0xffffffff
    }
    $mac = [BitConverter]::GetBytes($s)
    [Array]::Reverse($mac)
    for ($i = 1; $i -lt 16; $i++) {
      [UInt64]$c = $h[$i] + 16 - $mac[$i - 1]
      $mac = $mac + [BitConverter]::GetBytes($c)
      [Array]::Reverse($mac[($mac.Length - 8)..($mac.Length - 1)])
    }
    return $mac[0..15]
  }
  [array] Poly1305_Block([UInt64[]]$h, [UInt64[]]$r, [UInt64[]]$m) {
    [UInt64[]]$h = [bitwUtil]::Reduce($h)
    [UInt64[]]$r = [bitwUtil]::Reduce($r)
    [UInt64[]]$m = [bitwUtil]::Reduce($m)
    [UInt64] $s = 0
    [UInt64] $d0 = 0
    [UInt64] $d1 = 0
    for ($i = 0; $i -lt 16; $i++) {
      $d0 = ($m[$i] + $h[$i]) -band 0xffffffff
      $d1 = ($d0 * $r[0]) -band 0xffffffff
      $d0 = ($d0 + ((($d1 * $r[1]) -band 0xffffffff) -shl 16)) -band 0xffffffff
      $d0 = ($d0 % 130) -band 0xffffffff
      $s = ($s + $d0) -band 0xffffffff
      if ($i -eq 15) {
        break
      }
      $s = ($s * 5) -band 0xffffffff
      $s = ($s + 0x800000000000) -band 0xffffffff
      $s = ($s % 130) -band 0xffffffff
    }
    $h[0] = $s -band 0xffffffff
    for ($i = 1; $i -lt 17; $i++) {
      $s = ($s -shr 26) -band 0xffffffff
      $h[$i] = ($h[$i] + $s) -band 0xffffffff
    }
    return ($h, $r, $m)
  }
}
#endregion Poly1305

#endregion Custom_EncClasses_&_Helpers

#region    FileCrypter
# .SYNOPSIS
#     Simple file encryption & some script obfuscation
# .NOTES
#     - Requires powershell core
#     - Obfuscation method was inspired by: https://netsec.expert/posts/write-a-crypter-in-any-language
#       I modified the functions from netsec blog and tried my best to avoid using Invoke-Expression in any possible way, since its like a red flag for Anti viruses. I Instead used "& ([scriptblock]::Create(...."
Class FileCryptr {
  static hidden [Object] $CommonFileExtensions;
  static hidden [ValidateNotNullOrEmpty()][string] $_salt;
  static hidden [ValidateNotNullOrEmpty()][securestring] $Password;
  static hidden [ValidateNotNullOrEmpty()][Compression] $Compression;
  FileCryptr() {
    [FileCryptr]::_salt = 'bz07LmY5XiNkXW1WQjxdXw=='
    [FileCryptr]::Compression = [Compression]::Gzip
    [FileCryptr]::CommonFileExtensions = New-Object System.Management.Automation.PSStyle+FileInfoFormatting+FileExtensionDictionary
  }
  static [void] Encrypt([string]$FilePath) {
    [FileCryptr]::Encrypt($FilePath, 1)
  }
  static [void] Encrypt([string]$FilePath, [string]$Outfile) {
    [FileCryptr]::Encrypt($FilePath, 1, $Outfile)
  }
  static [void] Encrypt([string]$FilePath, [int]$iterations) {
    [FileCryptr]::Encrypt($FilePath, $iterations, $FilePath)
  }
  static [void] Encrypt([string]$FilePath, [int]$iterations, [string]$Outfile) {
    [FileCryptr]::Password = [Encoding]::UTF8.GetString(
      [Rfc2898DeriveBytes]::new(
        [xcrypt]::GetUniqueMachineId(),
        [convert]::FromBase64String([FileCryptr]::_salt),
        1000,
        [HashAlgorithmName]::SHA1
      ).GetBytes(256 / 8)
    ) | xconvert ToSecurestring
    [FileCryptr]::Encrypt($FilePath, [FileCryptr]::Password, $iterations, $Outfile)
  }
  static [void] Encrypt([string]$FilePath, [securestring]$passwr0d, [int]$iterations) {
    [FileCryptr]::Encrypt($FilePath, $passwr0d, $iterations, $FilePath)
  }
  static [void] Encrypt([string]$FilePath, [securestring]$passwr0d, [int]$iterations, [string]$Outfile) {
    [byte[]]$clearData = [File]::ReadAllBytes($FilePath);
    $Outfile = [xcrypt]::GetUnResolvedPath($Outfile); if (![IO.File]::Exists($Outfile)) { New-Item -Path $Outfile -ItemType File }
    $encryptedBytes = [AesGCM]::Encrypt($clearData, $passwr0d, [convert]::FromBase64String([FileCryptr]::_salt), $iterations)
    [File]::WriteAllBytes($Outfile, $encryptedBytes)
  }
  static [void] Decrypt([string]$FilePath) {
    [FileCryptr]::Decrypt($FilePath, 1)
  }
  static [void] Decrypt([string]$FilePath, [string]$Outfile) {
    [FileCryptr]::Decrypt($FilePath, 1, $Outfile)
  }
  static [void] Decrypt([string]$FilePath, [int]$iterations) {
    [FileCryptr]::Decrypt($FilePath, $iterations, $FilePath)
  }
  static [void] Decrypt([string]$FilePath, [int]$iterations, [string]$Outfile) {
    [FileCryptr]::Password = [Encoding]::UTF8.GetString(
      [Rfc2898DeriveBytes]::new(
        [xcrypt]::GetUniqueMachineId(), [convert]::FromBase64String([FileCryptr]::_salt),
        1000, [HashAlgorithmName]::SHA1
      ).GetBytes(256 / 8)
    ) | xconvert ToSecurestring
    [FileCryptr]::Decrypt($FilePath, [FileCryptr]::Password, $iterations, $Outfile)
  }
  static [void] Decrypt([string]$FilePath, [securestring]$passwr0d, [int]$iterations) {
    [FileCryptr]::Decrypt($FilePath, $passwr0d, $iterations, $FilePath)
  }
  static [void] Decrypt([string]$FilePath, [securestring]$passwr0d, [int]$iterations, [string]$Outfile) {
    [byte[]]$encryptedData = [File]::ReadAllBytes($FilePath);
    $Outfile = [xcrypt]::GetUnResolvedPath($Outfile); if (![IO.File]::Exists($Outfile)) { New-Item -Path $Outfile -ItemType File }
    $decryptedBytes = [AesGCM]::Decrypt($encryptedData, $passwr0d, [convert]::FromBase64String([FileCryptr]::_salt), $iterations)
    [File]::WriteAllBytes($Outfile, $decryptedBytes)
  }
  static [string] GetStub([string]$filePath) {
    [int]$keySize = 256;
    [byte[]]$salt = [convert]::FromBase64String([FileCryptr]::_salt);
    [string]$b64k = [convert]::ToBase64String(
      [Rfc2898DeriveBytes]::new(
        [FileCryptr]::RNdvar(), $salt, 10000,
        [HashAlgorithmName]::SHA1
      ).GetBytes($keySize / 8)
    );
    return [FileCryptr]::GetStub($filePath, $b64k);
  }
  static [string] RNdvar() {
    return [FileCryptr]::RNdvar(15)
  }
  static [string] RNdvar([string]$Length) {
    return [Guid]::NewGuid().Guid.subString($Length).replace('-', [string]::Join('', (0..9 | Get-Random -Count 1)))
  }
  static [string] GetStub([string]$filePath, [string]$base64key) {
    return [FileCryptr]::GetStub($filePath, $base64key, [FileCryptr]::_salt)
  }
  static hidden [string] GetStub([string]$filePath, [string]$base64key, [string]$salt) {
    Write-Verbose "[+] Reading file: '$($filePath)' ..."
    $filePath = [xcrypt]::GetUnResolvedPath($filePath)
    if (![IO.File]::Exists($filePath)) { throw [FileNotFoundException]::new("Unable to find the file: $filePath") }
    $codebytes = [Encoding]::UTF8.GetBytes([File]::ReadAllText($filePath, [Encoding]::UTF8));
    $Comprssnm = [FileCryptr]::Compression.ToString()
    $EncrBytes = $null
    Write-Verbose "[+] Encrypting ...$(
            $Passw = [SecureString]($base64key | xconvert ToSecurestring)
            $bSalt = [byte[]][Convert]::FromBase64String($salt); [int]$KeySize = 256; $CryptoProvider = $null;
            if ($Comprssnm -notin ([Enum]::GetNames('Compression' -as 'Type'))) { Throw [InvalidCastException]::new("The name '$Comprssnm' is not a valid [Compression]`$typeName.") };
            Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([AesCryptoServiceProvider]::new());
            $CryptoProvider.KeySize = [int]$KeySize;
            $CryptoProvider.Padding = [PaddingMode]::PKCS7;
            $CryptoProvider.Mode = [CipherMode]::CBC;
            $CryptoProvider.Key = [Rfc2898DeriveBytes]::new(($Passw | xconvert ToString), $bSalt, 10000, [HashAlgorithmName]::SHA1).GetBytes($KeySize / 8);
            $CryptoProvider.IV = [Rfc2898DeriveBytes]::new(($passw | xconvert ToString), $bsalt, 1, [HashAlgorithmName]::SHA1).GetBytes(16);
            Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $($CryptoProvider.IV + $CryptoProvider.CreateEncryptor().TransformFinalBlock($codebytes, 0, $codebytes.Length));
            Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $(Compress-Data -b $EncrBytes -c $Comprssnm));
            $CryptoProvider.Clear(); $CryptoProvider.Dispose()
        ) Done."
    $base64encString = [convert]::ToBase64String($EncrBytes)
    $base64encbArray = $base64encString.ToCharArray(); [array]::Reverse($base64encbArray);
    $base64encrevstr = -join $base64encbArray
    [string]$xorPassword = [Convert]::ToBase64String([Encoding]::UTF8.GetBytes([xcrypt]::GeneratePassword(30, $true, $false, $true, $true)))
    [byte[]]$Passwdbytes = [Encoding]::UTF8.GetBytes($xorPassword); $xkey64 = [convert]::ToBase64String($Passwdbytes)
    $base64XOREncPayload = [Convert]::ToBase64String([xor]::Encrypt([Encoding]::UTF8.GetBytes($base64encrevstr), $Passwdbytes, 1))
    Write-Verbose "[+] Finalizing Code Layer ..."
    $s = [string]::Empty
    $l = @(); $n = "`r`n"
    $l += '${9} = [int][Encoding]::UTF8.GetString([convert]::FromBase64String("MjU2"))' + $n
    $l += '${7} = [Convert]::FromBase64String("LkNyZWF0ZURlY3J5cHRvcigpLlRyYW5zZm9ybUZpbmFsQmxvY2s=")' + $n
    $l += '${2} = [Convert]::FromBase64String("{25}")' + $n
    $l += '${3} = [Convert]::FromBase64String("{0}")' + $n
    $l += '${4} = [byte[]]$(for (${6} = 0; ${6} -lt ${3}.length) {' + $n
    $l += '        for (${5} = 0; ${5} -lt ${2}.length; ${5}++) {' + $n
    $l += '            ${3}[${6}] -bxor ${2}[${5}]' + $n
    $l += '            ${6}++' + $n
    $l += '            if (${6} -ge ${3}.Length) {' + $n
    $l += '                ${5} = ${2}.length' + $n
    $l += '            }' + $n
    $l += '        }' + $n
    $l += '    }' + $n
    $l += ')' + $n
    $s += $l -join ''; $l = @()
    $l += '[array]::Reverse(${4});' + $n
    $l += '${19} = -join [char[]]${4};' + $n
    $l += '${20} = $null; ${11} = $null; ${12} = $null' + $n
    $l += '${10} = [Encoding]::UTF8.GetString([System.Convert]::FromBase64String("RGVjb21wcmVzcw=="));' + $n
    $l += '${21} = & ([scriptblock]::Create("$([Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5JTy5NZW1vcnlTdHJlYW1dOjpuZXc=")))([System.Convert]::FromBase64String(`"${19}`"))"));' + $n
    $l += '${13} = & ([scriptblock]::Create([Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W0lPLkNvbXByZXNzaW9uLkNvbXByZXNzaW9uTW9kZV0="))));' + $n
    $l += '${14} = switch ("{23}") {' + $n
    $l += '    "Gzip" { New-Object ([Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLklPLkNvbXByZXNzaW9uLkd6aXBTdHJlYW0="))) ${21}, (${13}::${10}) }' + $n
    $l += '    "Deflate" { New-Object ([Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLklPLkNvbXByZXNzaW9uLkRlZmxhdGVTdHJlYW0="))) ${21}, (${13}::${10}) }' + $n
    $l += '    "ZLib" { New-Object (([Encoding]::UTF8.GetString([System.Convert]::FromBase64String("U3lzdGVtLklPLkNvbXByZXNzaW9uLlpMaWJTdHJlYW0=")))) ${21}, (${13}::${10}) }' + $n
    $l += '    Default { throw ([Encoding]::UTF8.GetString([convert]::FromBase64String("RmFpbGVkIHRvIERlQ29tcHJlc3MgQnl0ZXMuIENvdWxkIE5vdCByZXNvbHZlIENvbXByZXNzaW9uIQ=="))) }' + $n
    $l += '}' + $n
    $s += $l -join ''; $l = @()
    $l += '${15} = & ([scriptblock]::Create([Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5JTy5NZW1vcnlTdHJlYW1dOjpOZXcoKQ=="))))' + $n
    $l += '[void]${14}.CopyTo(${15}); ${14}.Close(); ${14}.Dispose(); ${21}.Close();' + $n
    $l += '[byte[]]${12} = ${15}.ToArray(); ${15}.Close();' + $n
    $l += 'Set-Variable -Name {20} -Scope Local -Visibility Private -Option Private -Value (& ([scriptblock]::Create([Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQWVzQ3J5cHRvU2VydmljZVByb3ZpZGVyXTo6bmV3KCk=")))));' + $n
    $l += '${18} = & ([scriptblock]::Create([Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQ2lwaGVyTW9kZV06OkNCQw=="))))' + $n
    $l += '${17} = & ([scriptblock]::Create([Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpQS0NTNw=="))))' + $n
    $l += '${16} = & ([scriptblock]::Create([Encoding]::UTF8.GetString([System.Convert]::FromBase64String("W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuSGFzaEFsZ29yaXRobU5hbWVdOjpTSEEx"))))' + $n
    $l += '${8} = & ([scriptblock]::Create([Encoding]::UTF8.GetString([convert]::FromBase64String("W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUmZjMjg5OERlcml2ZUJ5dGVzXTo6bmV3")) + "(`"{1}`", [Convert]::FromBase64String(`"{24}`"), 10000, `"${16}`")"))' + $n
    $l += '${20}.KeySize = ${9};' + $n
    $l += '${20}.Padding = ${17}' + $n
    $l += '${20}.Mode = ${18}' + $n
    $l += '${20}.Key = ${8}.GetBytes(${9} / 8)' + $n
    $l += '${20}.IV = ${12}[0..15];' + $n
    $l += 'Set-Variable -Name {11} -Scope Local -Visibility Private -Option Private -Value $(${20}.CreateDecryptor().TransformFinalBlock(${12}, 16, ${12}.Length - 16))' + $n
    $l += '${20}.Clear(); ${20}.Dispose();' + $n
    $l += '${7} = [Encoding]::UTF8.GetString(${11});' + $n
    if ([FileInfo]::new($filePath).Extension -in ('.ps1', '.psm1', '.cmd', '.bat', '.sh')) {
      # Why only these Extension? Well I mainly wrote this crypter to hide scripts from WDefender.
      $l += '& ([scriptblock]::Create("${7}"));' + $n
    } else {
      $l += 'echo ${7}' + $n
    }
    $s += $l -join ''
    $s = $s.Replace("{0}", $base64XOREncPayload)
    $s = $s.Replace("{1}", $base64key)
    $s = $s.Replace("{25}", $xkey64)
    $s = $s.Replace("{23}", $Comprssnm)
    $s = $s.Replace("{24}", $salt)
    2..21 | ForEach-Object { $s = $s.Replace("{$_}", [FileCryptr]::RNdvar()) }
    return $s
  }
  static [string] Obfuscate([string]$filePath) {
    return [FileCryptr]::Obfuscate($filePath, $filePath)
  }
  static [string] Obfuscate([string]$filePath, [string]$OutputFile) {
    if (![FileCryptr]::IsTextFile($filePath)) {
      throw [Exception]::new("Error: $filePath is not a text file.")
    }
    $stub = [FileCryptr]::GetStub($filePath)
    $OutputFile = [xcrypt]::GetUnResolvedPath($OutputFile)
    return (Set-Content -Path $OutputFile -Value $stub -Encoding UTF8 -PassThru)
  }
  static [string] Deobfuscate([string]$base64EncodedString) {
    throw 'Idk! Just run the damn file; (and hope its not a virus).'
  }
  static [bool] IsTextFile([string]$filePath) {
    @(# Default file extensions to speed up the detection process.
      ".txt", ".log", ".ini", ".env", ".cfg", ".conf", ".cnf",
      ".properties", ".props", ".prop", ".rtf", ".csv", ".jsx",
      ".tsv", ".ssv", ".dsv", ".csv", ".tab", ".vcf",
      ".js", ".json", ".py", ".pl", ".pm", ".t", ".php",
      ".php3", ".php4", ".php5", ".phtml", ".inc", ".phps",
      ".asp", ".aspx", ".asax", ".ascx", ".ashx", ".asmx",
      ".css", ".html", ".htm", ".shtml", ".xhtml", ".md",
      ".markdown", ".mdown", ".mkd", ".rst", ".xml", ".yml",
      ".ps1", ".psm1", ".psd1", ".pssc", ".cdxml", ".clixml",
      ".xaml", ".toml", ".resx", ".restext", ".unity", ".sln", ".csproj",
      ".vbproj", ".vcxproj", ".vcxproj.filters", ".proj", ".projitems",
      ".shproj", ".scc", ".suo", ".sln", ".cs", ".vb", ".vc", ".vcx",
      ".cxx", ".cpp", ".h", ".hpp", ".hh", ".hxx", ".inc", ".inl",
      ".ipp", ".tcc", ".tpp", ".cc", ".c", ".mm", ".m", ".s",
      ".sx", ".S", ".rs", ".rlib", ".def", ".odl", ".idl",
      ".odl", ".hdl", ".vhd", ".vhdl", ".ucf", ".qsf",
      ".tcl", ".tk", ".itk", ".tkm", ".blt", ".tcl"
    ) | ForEach-Object { [FileCryptr]::CommonFileExtensions.Add($_, '') }
    if ([FileCryptr]::CommonFileExtensions.ContainsKey([IO.Path]::GetExtension($filePath))) {
      return $true;
    }
    try {
      $null = [IO.File]::ReadAllText($filePath);
      return $true;
    } catch [Exception] {
      return $false;
    }
  }
}
#endregion FileCrypter

#region    Custom_Cryptography_Wrappers
class k3y {
  [ValidateNotNullOrEmpty()][CredManaged]$User;
  [ValidateNotNullOrEmpty()][Expiration]$Expiration;
  [ValidateNotNullOrEmpty()][securestring]hidden $UID;
  [ValidateNotNullOrEmpty()][int]hidden $_PID = [Environment]::ProcessId;
  [ValidateNotNullOrEmpty()][keyStoreMode]hidden $Storage = [KeyStoreMode]::Securestring;
  [ValidateNotNullOrEmpty()][version]hidden $version = [version]::new("1.0.0.1");
  [ValidateNotNullOrEmpty()][byte[]] static hidden $Salt = [Encoding]::UTF7.GetBytes('hR#ho"rK6FMu mdZFXp}JMY\?NC]9(.:6;>oB5U>.GkYC-JD;@;XRgXBgsEi|%MqU>_+w/RpUJ}Kt.>vWr[WZ;[e8GM@P@YKuT947Z-]ho>E2"c6H%_L2A:O5:E)6Fv^uVE; aN\4t\|(*;rPRndSOS(7& xXLRKX)VL\/+ZB4q.iY { %Ko^<!sW9n@r8ihj*=T $+Cca-Nvv#JnaZh'); #this is the default salt, change it if you want.

  k3y([string]$Passw0rd) {
    $Password = $Passw0rd | xconvert ToSecurestring
    $this.User = [CredManaged]::new([pscredential]::new($(whoami), $Password));
    $this.Expiration = [expiration]::new(0, 1);
    $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
  }
  k3y([securestring]$Password) {
    $this.User = [CredManaged]::new([pscredential]::new($(whoami), $Password));
    $this.Expiration = [expiration]::new(0, 1);
    $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
  }
  k3y([CredManaged]$User, [Datetime]$Expiration) {
    $this.User = $User
    $this.Expiration = [expiration]::new($Expiration);
    $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
  }
  k3y([securestring]$Password, [Datetime]$Expiration) {
    $this.User = [CredManaged]::new([pscredential]::new($(whoami), $Password));
    $this.Expiration = [Expiration]::new($Expiration);
    $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
  }
  k3y([securestring]$Password, [byte[]]$salt, [Datetime]$Expiration) {
    $this.User = [CredManaged]::new([pscredential]::new($(whoami), $Password));
    [k3y]::Salt = $salt; $this.Expiration = [Expiration]::new($Expiration);
    $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
  }
  k3y([pscredential]$User, [Datetime]$Expiration) {
        ($this.User, $this.Expiration) = ([CredManaged]::new($User), [Expiration]::new($Expiration));
    $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
  }
  k3y([string]$UserName, [securestring]$Password) {
    $this.User = [CredManaged]::new([pscredential]::new($UserName, $Password));
    $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
  }
  k3y([string]$UserName, [securestring]$Password, [Datetime]$Expiration) {
        ($this.User, $this.Expiration) = ([CredManaged]::new([pscredential]::new($UserName, $Password)), [Expiration]::new($Expiration));
    $this.SetUID(); $this.PsObject.Methods.Remove('SetUID');
  }
  [void]hidden SetUID() {
    $assocdataProps = ($this | Get-Member -Force | Where-Object { $_.MemberType -eq "Property" -and $_.Name -notin ('UID', 'Salt') }) | Select-Object -ExpandProperty Name
    $s = [string]::Empty
    $s += '"' + ($assocdataProps -join '","') + '"' + "`n"; $vals = $assocdataProps | ForEach-Object { $this.$_.Tostring() }; $fs = '"{' + ((0 .. ($vals.Count - 1)) -join '}","{') + '}"';
    $s += $fs -f $vals; $O = ConvertFrom-Csv $s; $O.User = $this.User
    $op = ($o.User | Get-Member -Force | Where-Object { $_.MemberType -eq "Property" }) | Select-Object -ExpandProperty Name
    $st = ("[PSCustomObject]@{`n " + $($op | ForEach-Object { "$_ = '$($O.User.$_)'`n" }) + '}').Replace(" Password = 'System.Security.SecureString'", " password = '$(($O.User.password | xconvert ToString))'")
    $O.User = [convert]::ToBase64String([Encoding]::UTF8.GetBytes($st)); $s = $(ConvertTo-Csv $O).Split('"Expiration","Storage","User","version","_PID"', [StringSplitOptions]::TrimEntries);
    $dt = [Encoding]::UTF8.GetBytes($s)
    $ps = $null; Set-Variable -Name ps -Scope Local -Visibility Private -Option Private -Value $((
        [convert]::ToBase64String(
          [Rfc2898DeriveBytes]::new(($this.User.Password | xconvert ToString), [k3y]::Salt, 10000, [HashAlgorithmName]::SHA1).GetBytes(256 / 8)
        )
      ) | xconvert ToSecurestring
    );
    Write-Verbose "[+] Res-password $($ps | xconvert ToString)"
    Write-Verbose "[+] Res-password Length: $([convert]::FromBase64String(($ps | xconvert ToString)).Length)"
    & ([scriptblock]::Create("`$this.psobject.Properties.Add([psscriptproperty]::new('UID', { ConvertTo-SecureString -AsPlainText -String '$([convert]::ToBase64String([Shuffl3r]::Combine([AesGcm]::Encrypt($dt, $ps, [k3y]::Salt), [convert]::FromBase64String(($ps | xconvert ToString)), [xcrypt]::GetUniqueMachineId())))' -Force }))"));
  }
  [psobject] GetInfo([string]$passw0rd) {
    return $this.GetInfo(($passw0rd | xconvert ToSecurestring))
  }
  [psobject] GetInfo([securestring]$password) {
    return $this.GetInfo(($this.UID | xconvert ToString), $password, [k3y]::Salt)
  }
  [psobject] GetInfo([string]$UID, [securestring]$password, [byte[]]$salt) {
    return [Encoding]::UTF8.GetString([AesGcm]::Decrypt([System.Convert]::FromBase64String($UID), $this.ResolvePassword($Password), $salt)) | ConvertFrom-Csv
  }
  [bool] IsValid() { return $this.IsValid($false) }
  [bool] IsValid([bool]$ThrowOnFailure) {
    # Verifies if The password has already been set.
    $IsValid = $false; [bool]$SetValu3Exception = $false; [securestring]$kUID = $this.UID; $InnerException = [Exception]::new()
    try {
      $this.UID = [securestring]::new()
    } catch [Management.Automation.SetValueException] {
      $SetValu3Exception = $true
    } catch {
      $InnerException = $_.Exception
    } finally {
      if ($SetValu3Exception) {
        $IsValid = $true
      } else {
        $this.UID = $kUID
      }
    }
    if ($ThrowOnFailure -and !$IsValid) {
      throw [InvalidOperationException]::new("The key Hasn't been used!`nEncrypt Something with this K3Y at least once or Manually Call SetK3YUID method.", $InnerException)
    }
    return $IsValid
  }
  # [securestring] hidden ResolvePassword([securestring]$Password) {
  #     if (!$this.IsHashed()) {
  #         $hashSTR = [string]::Empty; Set-Variable -Name hashSTR -Scope local -Visibility Private -Option Private -Value $([string]([HKDF2]::GetToken($password) | xconvert ToHexString));
  #         & ([scriptblock]::Create("`$this.User.psobject.Properties.Add([psscriptproperty]::new('Password', { ConvertTo-SecureString -AsPlainText -String '$hashSTR' -Force }))"));
  #     }
  #     $SecHash = $this.User.Password;
  #     return [ArgonCage]::Resolve($Password, $SecHash)
  # }
  [bool]IsHashed() {
    return $this.IsHashed($false);
  }
  static [bool] IsHashed([K3Y]$k3y) {
    $ThrowOnFailure = $false
    return [K3Y]::IsHashed($k3y, $ThrowOnFailure);
  }
  [bool]IsHashed([bool]$ThrowOnFailure) {
    return [K3Y]::IsHashed($this, $ThrowOnFailure);
  }
  static [bool] IsHashed([K3Y]$k3y, [bool]$ThrowOnFailure) {
    # Verifies if The password (the one only you know) has already been hashed
    [bool]$SetValu3Exception = $false; [securestring]$p = $k3y.User.Password; $InnerException = [Exception]::new()
    [bool]$IsHashed = [regex]::IsMatch([string]($k3y.User.Password | xconvert ToString), "^[A-Fa-f0-9]{72}$");
    try {
      $k3y.User.Password = [securestring]::new() # This will not work if the hash has been set
    } catch [Management.Automation.SetValueException] {
      $SetValu3Exception = $true
    } catch {
      $InnerException = $_.Exception
    } finally {
      $IsHashed = $IsHashed -and $SetValu3Exception
    }
    if (!$SetValu3Exception) {
      $k3y.User.Password = $p
    }
    if ($ThrowOnFailure -and !$IsHashed) {
      throw [InvalidOperationException]::new('Operation is not valid due to the current state of the object. No password Hash found.', $InnerException)
    }
    return $IsHashed
  }
  [void]Export([string]$FilePath) {
    $this.Export($FilePath, $false);
  }
  [void]Export([string]$FilePath, [bool]$encrypt) {
    $ThrowOnFailure = $true; [void]$this.IsValid($ThrowOnFailure)
    $FilePath = [xcrypt]::GetUnResolvedPath($FilePath)
    if (![IO.File]::Exists($FilePath)) { New-Item -Path $FilePath -ItemType File | Out-Null }
    Set-Content -Path $FilePath -Value ($this.Tostring()) -Encoding UTF8 -NoNewline;
    if ($encrypt) { Write-Verbose "[i] Export encrypted key to $FilePath"; [Filecryptr]::Encrypt($FilePath) };
  }
  static [K3Y] Create([FileInfo]$File) {
    $tmp = [IO.Path]::GetTempFileName()
    [Filecryptr]::Decrypt($File.FullName, $tmp)
    $_id = Get-Content $tmp; Remove-Item $tmp
    return [K3Y]::Create($_id)
  }
  static [K3Y] Create([string]$uid) {
    ($idb, $pb) = [Shuffl3r]::Split([convert]::FromBase64String($uid), [xcrypt]::GetUniqueMachineId(), 32)
    $dec = [AesGcm]::Decrypt($idb, ([convert]::ToBase64String($pb) | xconvert ToSecurestring), [k3y]::Salt)
    $Obj = ConvertFrom-Csv $('"Expiration","Storage","User","version","_PID"' + "`n" + ([Encoding]::UTF8.GetString($dec).Trim()))
    $Obj.User = & ([scriptblock]::Create([Encoding]::UTF8.GetString([convert]::FromBase64String($Obj.User)))); $Obj.user.password = ($Obj.user.password | xconvert ToSecurestring)
    $Obj.User = & { $usr = [credmanaged]::new(); $usr.psobject.properties.name | ForEach-Object { $usr.$_ = $Obj.User.$_ }; $usr }
    Write-Verbose "[i] Create new k3y object ..."
    $K3Y = [K3Y]::new($Obj.User, ($Obj.Expiration | xconvert ToDateTime))
    $K3Y._PID = $Obj._PID; $K3Y.version = [version]$Obj.version; $K3Y.Storage = [keyStoreMode]$Obj.Storage
    return $K3Y
  }

  [K3Y]Import([string]$uid) {
    $K3Y = $null; Set-Variable -Name K3Y -Scope Local -Visibility Private -Option Private -Value ([K3Y]::Create($uid));
    try {
      $this | Get-Member -Force | Where-Object { $_.Membertype -eq 'property' } | ForEach-Object { $this.$($_.Name) = $K3Y.$($_.Name) };
    } catch [Management.Automation.SetValueException] {
      throw [InvalidOperationException]::New('You can only Import One Key.')
    }
    $Key_UID = [string]::Empty; $hashSTR = [string]::Empty; Set-Variable -Name hashSTR -Scope local -Visibility Private -Option Private -Value $([string]($this.User.Password | xconvert ToString));
    if ([regex]::IsMatch($hashSTR, "^[A-Fa-f0-9]{72}$")) {
      & ([scriptblock]::Create("`$this.User.psobject.Properties.Add([psscriptproperty]::new('Password', { ConvertTo-SecureString -AsPlainText -String '$hashSTR' -Force }))"))
    }
    Set-Variable -Name Key_UID -Scope local -Visibility Private -Option Private -Value $([string]($K3Y.UID | xconvert ToString))
    & ([scriptblock]::Create("`$this.psobject.Properties.Add([psscriptproperty]::new('UID', { ConvertTo-SecureString -AsPlainText -String '$Key_UID' -Force }))"));
    return $K3Y
  }
  [void]SetPassword([securestring]$password) {}
  [void]SaveToVault() {
    $_Hash = $this.User.Password | xconvert ToString;
    if ([string]::IsNullOrWhiteSpace($_Hash)) {
      throw 'Please set a Password first.'
    }
    $RName = 'PNKey' + $_Hash
    $_Cred = New-Object -TypeName CredManaged -ArgumentList ($RName, $this.User.UserName, ($this | xconvert ToString))
    Write-Verbose "[i] Saving $RName To Vault .."
    # Note: Make sure file size does not exceed the limit allowed and cannot be saved.
    $_Cred.SaveToVault()
  }
  [string]Tostring() {
    return ($this.UID | xconvert ToString)
  }
}
#region    _The_K3Y
# The K3Y 'UID' [ see .SetK3YUID() method ] is a fancy way of storing the version, user/owner credentials, Compression alg~tm used and Other Info
# about the most recent use and the person who used it; so it can be analyzed later to verify some rules before being used again. This enables the creation of complex expiring encryptions.
# It does not store or use the actual password; instead, it employs its own 'KDF' and retains a 'SHA1' hash string as securestring objects. idk if this is the most secure way to use but it should work.

# [byte[]]Encrypt([byte[]]$BytesToEncrypt, [securestring]$Password, [byte[]]$salt, [string]$Compression, [Datetime]$Expiration, [CryptoAlgorithm]$Algorithm) {
#     $Password = [securestring]$this.ResolvePassword($Password); $this.SetK3YUID($Password, $Expiration, $Compression, $this._PID)
#     # $CryptoServiceProvider = [CustomCryptoServiceProvider]::new($bytesToEncrypt, $Password, $salt, [CryptoAlgorithm]$Algorithm)
#     # $encryptor = $CryptoServiceProvider.CreateEncryptor(); $result = $encryptor.encrypt();
#     return [AesGCM]::Encrypt($bytesToEncrypt, $Password, $salt);
# }

# [byte[]]Decrypt([byte[]]$BytesToDecrypt, [securestring]$Password, [byte[]]$salt) {
#     $Password = [securestring]$this.ResolvePassword($Password); # (Get The real Password)
#     ($IsValid, $Compression) = [k3Y]::AnalyseK3YUID($this, $Password, $false)[0, 2];
#     if (!$IsValid) { throw [Management.Automation.PSInvalidOperationException]::new("The Operation is not valid due to Expired K3Y.") };
#     if ($Compression.Equals('')) { throw [Management.Automation.PSInvalidOperationException]::new("The Operation is not valid due to Invalid Compression.", [ArgumentNullException]::new('Compression')) };
#     # todo: Chose the algorithm
#     # if alg -eq RSA then we RSA+AES hybrid
#     return [AesGCM]::Decrypt($bytesToDecrypt, $Password, $salt);
#     # $Compression
# }

class KeyManager {
  KeyManager() {}
}
#endregion _The_K3Y

#region Custom_Encryptor
# .DESCRIPTION
#     A custom encryptor to make it easy to combine several algorithms.
# .EXAMPLE
#     $encryptor = [Encryptor]::new($bytesToEncrypt, [securestring]$Password, [byte]$salt, [CryptoAlgorithm]$Algorithm);
#     $encrypted = $encryptor.encrypt();
class Encryptor {
  Encryptor([byte[]]$BytesToEncrypt, [securestring]$Password, [byte[]]$salt, [CryptoAlgorithm]$Algorithm) {
    $this.bytes = $bytesToEncrypt
    $this.Password = $Password
    $this.salt = $salt
    $this.setAlgorithm($Algorithm)
  }
  Encryptor([byte[]]$bytesToEncrypt, [K3Y]$key) {
    $this.bytes = $bytesToEncrypt
    # Dynamicaly create methods using [PsScriptMethod] : https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.psscriptmethod
    # $key.PSObject.Methods.Add(
    #     [psscriptmethod]::new(
    #         'MethodName', {
    #             param()
    #             return 'stuff'
    #         }
    #     )
    # )
  }
  [void]setAlgorithm([string]$Algorithm) {}
  [void]setAlgorithm([CryptoAlgorithm]$Algorithm) {}
  [byte[]] Encrypt() {
    $Encrypted = $null
    switch ([string]$this.Algorithm) {
      'AesGCM' {
        # {aes aesgcm} encrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
        $Encrypted = 'bytes encrypted Using aes aesgcm'
      }
      'ChaCha20' {
        $Encrypted = 'bytes encrypted Using ChaCha20 + SHA256'
      }
      'RsaAesHMAC' {
        # {aes + rsa} encrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
        #
        # Generate a random AES key and initialization vector
        # $aesKey = New-Object Byte[] 32
        # [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesKey)
        # $aesIV = New-Object Byte[] 16
        # [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesIV)

        # # Create an RSA key for encryption and decryption
        # $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
        # $rsaPublicKey = $rsa.ExportParameters(false)
        # $rsaPrivateKey = $rsa.ExportParameters(true)

        # # Encrypt the AES key using RSA encryption
        # $encryptedAesKey = $rsa.Encrypt($aesKey, $false)

        # # Create a HMACSHA256 object and compute the HMAC of the original data
        # $hmac = New-Object System.Security.Cryptography.HMACSHA256
        # $hmac.Key = $aesKey
        # $dataHMAC = $hmac.ComputeHash($bytes)

        # # Encrypt the data using AES encryption
        # $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        # $aes.Key = $aesKey
        # $aes.IV = $aesIV
        # $encryptor = $aes.CreateEncryptor()
        # $encryptedBytes = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)

        # # Combine the encrypted data, HMAC, and encrypted AES key into a single encrypted payload
        # $encryptedPayload = [Byte[]]::new($encryptedBytes.Length + $dataHMAC.Length + $encryptedAesKey.Length)
        # $encryptedBytes.CopyTo($encryptedPayload, 0)
        # $dataHMAC.CopyTo($encryptedPayload, $encryptedBytes.Length)
        # $encryptedAesKey.CopyTo($encryptedPayload, $encryptedBytes.Length + $dataHMAC.Length)
        # return $encryptedPayload
        $Encrypted = 'bytes encrypted Using RsaAesHMAC'
      }
      'RsaECDSA' {
        # RSA-ECDSA:  RSA and ECDSA (Elliptic Curve Digital Signature Algorithm) are public-key cryptography algorithms that are often used together. RSA can be used for encrypting data, while ECDSA can be used for digital signatures, providing both confidentiality and authenticity for the data.
        # {RSA + ECDSA} encrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
        # Create an RSA key for encryption and decryption
        # $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
        # $rsaPublicKey = $rsa.ExportParameters(false)
        # $rsaPrivateKey = $rsa.ExportParameters(true)

        # # Create an ECDSA key for signing and verifying
        # $ecdsa = New-Object Security.Cryptography.ECDsaCng
        # $ecdsaPublicKey = $ecdsa.Key.Export(Security.Cryptography.CngKeyBlobFormat::GenericPublicBlob)
        # $ecdsaPrivateKey = $ecdsa.Key.Export(Security.Cryptography.CngKeyBlobFormat::GenericPrivateBlob)

        # # Encrypt the data using RSA encryption
        # $encryptedBytes = $rsa.Encrypt($bytes, $false)

        # # Sign the encrypted data using ECDSA
        # $signature = $ecdsa.SignData($encryptedBytes)

        # # Combine the encrypted data and signature into a single encrypted payload
        # $encryptedPayload = [Byte[]]::new($encryptedBytes.Length + $signature.Length)
        # $encryptedBytes.CopyTo($encryptedPayload, 0)
        # $signature.CopyTo($encryptedPayload, $encryptedBytes.Length)

        $Encrypted = 'bytes encrypted Using RSA-ECDSA'
      }
      'RsaOAEP' {
        # Generate a new RSA key pair
        # $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        # $publicKey = $rsa.ExportParameters(False)
        # $privateKey = $rsa.ExportParameters(True)
        # # Encrypt the data using RSA-OAEP
        # $rsaEncryptor = New-Object System.Security.Cryptography.RSAPKCS1KeyExchangeFormatter($publicKey)
        # $encryptedBytes = $rsaEncryptor.Encrypt([Encoding]::UTF8.GetBytes("secret data"), "OAEP")
        $Encrypted = 'bytes encrypted Using RsaOAEP'
      }
      Default {
        throw "Please Provide a valid algorithm"
      }
    }
    return $Encrypted
  }
}
# .DESCRIPTION
#     A custom decryptor.
# .EXAMPLE
#     $decryptor = [Decryptor]::new($bytesToDecrypt, [securestring]$Password, [byte]$salt, [CryptoAlgorithm]$Algorithm);
#     $decrypted = $Decryptor.encrypt();
class Decryptor {
  Decryptor([byte[]]$BytesToDecrypt, [securestring]$Password, [byte[]]$salt, [CryptoAlgorithm]$Algorithm) {
    $this.bytes = $bytesToDecrypt
    $this.Password = $Password
    $this.salt = $salt
    $this.setAlgorithm($Algorithm)
  }
  [void]setAlgorithm([string]$Algorithm) {}
  [void]setAlgorithm([CryptoAlgorithm]$Algorithm) {}
  [byte[]]Decrypt() {
    $Decrypted = $null
    switch ([string]$this.Algorithm) {
      'AesGCM' {
        # {aesgcm} decrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
        $Decrypted = 'bytes decrypted Using aesgcm'
      }
      'ChaCha20' {
        $Decrypted = 'bytes decrypted Using ChaCha20 + SHA256'
      }
      'RsaAesHMAC' {
        # {aes + rsa} decrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
        #
        # # Split the encrypted payload into its three components: encrypted data, HMAC, and encrypted AES key
        # $encryptedBytes = $encryptedPayload[0..($encryptedBytes.Length - 1)]
        # $dataHMAC = $encryptedPayload[$encryptedBytes.Length..($encryptedBytes.Length + $dataHMAC.Length - 1)]
        # $encryptedAesKey = $encryptedPayload[($encryptedBytes.Length + $dataHMAC.Length)..($encryptedPayload.Length - 1)]

        # # Decrypt the AES key using RSA decryption
        # $aesKey = $rsa.Decrypt($encryptedAesKey, $false)

        # # Verify the HMAC of the encrypted data
        # $hmac = New-Object System.Security.Cryptography.HMACSHA256
        # $hmac.Key = $aesKey
        # $computedHMAC = $hmac.ComputeHash($encryptedBytes)
        # if ($computedHMAC -ne $dataHMAC)
        # {
        #     throw "HMAC verification failed"
        # }

        # # Decrypt the data using AES encryption
        # $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        # $aes.Key = $aesKey
        # $aes.IV = $aesIV
        # $decryptor = $aes.CreateDecryptor()
        # $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
        # return $decryptedBytes
        $Decrypted = 'bytes decrypted Using aes + rsa'
      }
      'RsaECDSA' {
        # {RSA + ECDSA} decrypt using: $this.bytes; $this.Password; $this.salt; $this.Algorithm
        # Decryption process:
        # # Split the encrypted payload into its two components: encrypted data and signature
        # $encryptedBytes = $encryptedPayload[0..($encryptedBytes.Length - 1)]
        # $signature = $encryptedPayload[$encryptedBytes.Length..($encryptedPayload.Length - 1)]

        # # Verify the signature of the encrypted data using ECDSA
        # if (!$ecdsa.VerifyData($encryptedBytes, $signature))
        # {
        #     throw "Signature verification failed"
        # }

        # # Decrypt the data using RSA decryption
        # $decryptedBytes = $rsa.Decrypt($encryptedBytes, $false)

        # # Return the decrypted data
        # return $decryptedBytes
        $Decrypted = 'bytes decrypted Using RsaECDSA'
      }
      'RsaOAEP' {
        # # Decrypt the data using RSA-OAEP
        # $rsaDecryptor = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        # $rsaDecryptor.ImportParameters($privateKey)
        # $decryptedBytes = $rsaDecryptor.Decrypt($encryptedBytes, "OAEP")
        # $decryptedMessage = [Encoding]::UTF8.GetString($decryptedBytes)
        $Decrypted = 'Bytes decrypted with RSA-OAEP'
        # Write-Output "Decrypted message: $decryptedMessage"
      }
      Default {
        throw "Please Provide a valid CryptoAlgorithm"
      }
    }
    return $Decrypted
  }
}
#endregion Custom_Cryptography_Wrappers

# Types that will be available to users when they import the module.
$typestoExport = @(
  [CredentialManager], [NativeCredential], [CryptoAlgorithm], [EncryptionScope], [KeyExportPolicy], [SignatureUtils],
  [FipsHmacSha256], [KeyProtection], [keyStoreMode], [ECCurveName], [Compression], [Expiration], [FileMonitor], [SecretStore],
  [VaultClient], [CredManaged], [RSAPadding], [CredFlags], [CredType], [BitwUtil], [Shuffl3r], [ChaCha20], [KeyUsage],
  [Poly1305], [TripleDES], [Encryptor], [Decryptor], [FileCryptr], [AesGCM], [AesCtr], [AesCng],
  [OTPKIT], [xcrypt], [X509], [MD5], [ECC], [RSA], [XOR], [k3y], [RC4]
)
$TypeAcceleratorsClass = [PsObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
foreach ($Type in $typestoExport) {
  if ($Type.FullName -in $TypeAcceleratorsClass::Get.Keys) {
    $Message = @(
      "Unable to register type accelerator '$($Type.FullName)'"
      'Accelerator already exists.'
    ) -join ' - '

    [Management.Automation.ErrorRecord]::new(
      [InvalidOperationException]::new($Message),
      'TypeAcceleratorAlreadyExists',
      [Management.Automation.ErrorCategory]::InvalidOperation,
      $Type.FullName
    ) | Write-Warning
  }
}
# Add type accelerators for every exportable type.
foreach ($Type in $typestoExport) {
  $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}
# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
  foreach ($Type in $typestoExport) {
    $TypeAcceleratorsClass::Remove($Type.FullName)
  }
}.GetNewClosure();

$scripts = @();
$Public = Get-ChildItem "$PSScriptRoot/Public" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += Get-ChildItem "$PSScriptRoot/Private" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += $Public

foreach ($file in $scripts) {
  Try {
    if ([string]::IsNullOrWhiteSpace($file.fullname)) { continue }
    . "$($file.fullname)"
  } Catch {
    Write-Warning "Failed to import function $($file.BaseName): $_"
    $host.UI.WriteErrorLine($_)
  }
}

$Param = @{
  Function = $Public.BaseName
  Cmdlet   = '*'
  Alias    = '*'
  Verbose  = $false
}
Export-ModuleMember @Param
