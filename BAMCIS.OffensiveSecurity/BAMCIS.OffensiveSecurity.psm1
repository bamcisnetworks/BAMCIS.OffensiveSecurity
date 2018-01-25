Function Start-PortScan {
	<#
		.SYNOPSIS
			Conducts a port scan on the selected computer.

		.DESCRIPTION
			Tries to connect to common ports on a targetted system and reports back the status of each.

		.PARAMETER ComputerName
			The name of the computer to scan. The parameter defaults to "localhost"

		.INPUTS
			System.String

				The input can be piped to Start-PortScan

		.OUTPUTS
			System.Management.Automation.PSCustomObject[]

				Each custom object has a property of Service, Port, and Status. Status is either Open or Closed.

		.EXAMPLE
			Start-PortScan -ComputerName remotecomputer.net

			Returns an array of open and closed ports on remotecomputer.net

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/26/2017

		.FUNCTIONALITY
			The intended use of this cmdlet is to conduct a security scan of ports on a computer.

	#>
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCustomObject[]])]
	Param(
		[Parameter(Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ComputerName = "localhost"
	)
	
	Begin
	{
		$Ports = $script:Ports | Sort-Object -Property Port
	}

	Process
	{
        $Results = @()
        foreach ($Port in $Ports)
        {
            Write-Progress -Activity "Running Port Scan" -Status "Scanning Port $($Port.Port) $($Port.Service)" -PercentComplete (($i++ / $Ports.Count) * 100)
            [System.Collections.Hashtable]$Splat = @{}

			if ($Port.Transport -ieq "UDP")
			{
				$Splat.Add("Udp", $true)
			}
			
			$Result = Test-Port -Port $Port.Port -ComputerName $ComputerName @Splat
            $Results += ([PSCustomObject]@{"Service"="$($Port.Service)";"Port"=$($Port.Port);"Transport"="$($Port.Transport)";"Status"="$(if ($Result) {"Open"} else {"Closed"})"})
        }

        Write-Progress -Completed -Activity "Running Port Scan"

        Write-Output -InputObject $Results
	}

	End {	
	}
}

Function Get-LsaSecret {
	<#
		.SYNOPSIS
			Enumerates the content of the LSA Secrets registry hive.

		.DESCRIPTION
			The cmdlet first duplicates the lsass process token and sets it to the current process thread. Then it copies each secret stored in HKLM:\SECURITY\Policy\Secrets to a temporary location.
			After the content is copied over, Lsa functions from AdvApi32.dll are called to decrypt the content. When the cmdlet finishes, it leaves the registry area unchanged and reverts the process thread token.

            The CmdLet must be run with elevated permissions.

		.EXAMPLE
			Get-LsaSecret

			Retrieves all of the stored secrets in the registry using HKLM:\SECURITY\Policy\Secrets\<Generated GUID> to store the temporary information.

		.INPUTS
			None

		.OUTPUTS
            None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/23/2017
	#>

	[CmdletBinding()]
	[OutputType()]
	Param()

	Begin {
		if (!([System.Management.Automation.PSTypeName]"BAMCIS.PowerShell.OffensiveSecurity.LSAUtil").Type) {
			Add-Type -TypeDefinition $script:LsaSignature
		}
	}

	Process {
		Get-ProcessToken -ProcessName lsass | Set-ProcessToken	

		$TempKey = [System.Guid]::NewGuid().ToString()

		#Set up a temporary location to copy the registry keys over so that we can enumerate them, we have to be the owner to get the unencrypted values
		$Destination = "HKLM:\SECURITY\Policy\Secrets\$TempKey"

		if ((Get-Item -Path $Destination -ErrorAction SilentlyContinue) -ne $null) {
			Remove-Item -Path $Destination -Recurse -Force | Out-Null
		}

		New-Item -Path $Destination | Out-Null
		$Secrets = @()

		#Get all sub keys in secrets, these are the accounts
		Get-ChildItem -Path "HKLM:\SECURITY\Policy\Secrets" | Where-Object  {$_.Name -notmatch $TempKey -and $_.Property -ne $null} | ForEach-Object {
			$AccountName = $_.PSChildName
			
			#Get all the sub keys of the accounts, these are keys like CurrVal, OldVal, CupdTime, etc			
			Get-ChildItem -Path $_.PSPath | ForEach-Object {
				$ItemName = $_.PSChildName

				#If the sub key exists at the temp destination, delete it
				if ((Test-Path -Path "$Destination\$ItemName")) {
					Remove-Item -Path "$Destination\$ItemName" -Recurse -Force | Out-Null
				}

				#Copy the value over to the new registry location
				[System.Byte[]]$Property = Get-ItemProperty -Path $_.PSPath | Select-Object -ExpandProperty "(Default)"
				New-Item -Path "$Destination\$ItemName" | Out-Null
				Set-ItemProperty -Path "$Destination\$ItemName" -Name '(Default)' -Value $Property
			}

			$LsaUtil = New-Object -TypeName BAMCIS.PowerShell.OffensiveSecurity.LSAUtil -ArgumentList @($TempKey)

			try {
				$Value = $LsaUtil.GetSecret()
			}
			catch [Exception] {
				$Value = [System.String]::Empty
			}

			if ($AccountName -match "^_SC_") {
				# Get Service Account
				$Service = $AccountName -Replace "^_SC_"
				Try {
					# Get Service Account				
					$Account = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$Service'" -Property StartName -ErrorAction Stop | Select-Object -ExpandProperty StartName
				}
				catch [Exception] {
					$Account = [System.String]::Empty
				}
			} else {
				$Account = [System.String]::Empty
			}

			$Hex = [System.Text.Encoding]::Unicode.GetBytes($Value) | ForEach-Object {
				Write-Output -InputObject $_.ToString("X2")
			}

			$EncryptedBinary = [System.Byte[]](Get-ItemProperty -Path "$Destination\CurrVal" -Name "(Default)" | Select-Object -ExpandProperty "(Default)")

			$Temp = Set-ItemProperty -Path "$Destination\CurrVal" -Name "(Default)" -Value (Get-ItemProperty -Path "$Destination\OldVal" -Name "(Default)" | Select-Object -ExpandProperty "(Default)") -PassThru

			try {
				$OldSecret = $LsaUtil.GetSecret()
			}
			catch [Exception] {
				$OldSecret = [System.String]::Empty
			}

			$Secrets += (New-Object -TypeName PSObject -Property @{Name = $AccountName; Secret = $Value; OldSecret = $OldSecret; SecretHex = ($Hex -join " "); Account = $Account; EncryptedBinary = $EncryptedBinary})  
		}

		Remove-Item -Path "$Destination" -Force -Recurse
		Reset-ProcessToken
		Write-Output -InputObject $Secrets
	}

	End {		
	}
}

Function Get-WebHistory {
	<#
		.SYNOPSIS
			Reads the Internet Explorer web history of a user from the WebCacheV01.dat file.

		.DESCRIPTION
			The Get-WebHistory cmdlet is a forensic tools that reads the actual web history of a given user. It uses the ESE database functions to read the WebCacheV01.dat file. This works in IE10+.

			It is recommended that you use a copy of the database and logs so that the original database is not modified.

		.EXAMPLE
			Get-WebHistory

			Gets the web history of all users on the local computer.

		.PARAMETER UserName
			The user name to get the web history for. This defaults to all users.

		.INPUTS
			System.String

		.OUTPUTS
			System.Management.Automation.PSObject[]

			The array of objects contain Url, AccessedTime, and UserName information

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 10/25/2017
	#>
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSObject[]])]
	Param(
		[Parameter(Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$UserName = [System.String]::Empty
	)

	Begin {
		$Verbose = $PSBoundParameters.ContainsKey("Verbose").IsPresent
		Import-Module -Name BAMCIS.Logging
		Import-Module -Name BAMCIS.Common -ErrorAction Stop
		Import-Module -Name ESENT -ErrorAction Stop
	}

	Process {
		$Data = @()

		$Profiles = Get-UserProfiles
		if (![System.String]::IsNullOrEmpty($UserName)) {
			$Profiles = $Profiles | Where-Object {$_ -like "*$UserName*"}
		}

		foreach ($Profile in $Profiles) {			
			$Parts = $Profile.Split("\")
			$CurrentUser = $Parts[$Parts.Length - 1]
			$Path = Join-Path -Path $Profile -ChildPath "AppData\Local\Microsoft\Windows\WebCache"
			$Destination = "$env:USERPROFILE\AppData\Local\Temp"

			Write-Log -Message "Processing user $CurrentUser at path $Path" -Level VERBOSE

			if ((Test-Path -Path $Path) -and (Test-Path -Path "$Path\WebCacheV01.dat")) {
				Stop-Process -Name dllhost -Force -ErrorAction SilentlyContinue
				Stop-Process -Name taskhostw -Force -ErrorAction SilentlyContinue

				Write-Log -Message "Copying WebCache folder." -Level VERBOSE 

				Copy-Item -Path $Path -Destination $Destination -Recurse -Force

				Write-Log -Message "Finished copy." -Level VERBOSE

				$DB = $null
				$DB = Get-ESEDatabase -Path "$Destination\WebCache\WebCacheV01.dat" -LogPrefix "V01" -ProcessesToStop @("dllhost","taskhostw") -Recovery $false -CircularLogging $true -Force
				Remove-Item -Path "$Destination\WebCache" -Force -Recurse
				foreach ($Table in $DB) {
					if ($Table.Rows.Count -gt 0 -and (Get-Member -InputObject $Table.Rows[0] -Name "Url" -MemberType Properties) -ne $null) {
						$Data += ($Table.Rows | Select-Object -Property AccessedTime,Url,@{Name="UserName";Expression = {$CurrentUser}})
					}
				}
			}
		}

		Write-Output -InputObject $Data
	}

	End {
	}
}

Function Get-WifiProfiles {
	<#
        .SYNOPSIS
            Retrieves the stored Wi-Fi profiles and any associated passwords.

        .DESCRIPTION
            This cmdlet enumerates all of the stored wi-fi profiles and decrypts any stored
            password for preshared key type access points.

        .PARAMETER OnlyPasswordProfiles
            This specifies that the results will contain only stored profiles that contain a password.

        .EXAMPLE
            $Profiles = Get-WifiProfiles

            The $Profiles variable is a hash table that contains top level keys for each saved
            profile and then has a hash table property that contains information about the Interface Id,
            SSID name, and unencrypted password, if one exists.

        .INPUTS
            None

        .OUTPUTS
            System.Collections.Hashtable

        .NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/25/2018
    #>
    [CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	Param(
        [Parameter()]
        [Switch]$OnlyPasswordProfiles
	)

	Begin {
		$Path = "$env:ProgramData\Microsoft\Wlansvc\Profiles\Interfaces"

		if (-not (Test-IsLocalAdmin))
		{
			Write-Error -Exception (New-Object -TypeName System.Exception("This cmdlet requires local admin privileges.")) -ErrorAction Stop
		}
	}

	Process {
		$Profiles = @{}

        try
        {
			# Run this as local system so the password decryption will work
            $Token = Get-ProcessToken -ProcessName lsass
            Set-ProcessToken -TokenHandle $Token -ElevatePrivileges

			# Iterate each stored profile for each interface
		    Get-ChildItem -Path $Path -Recurse | ForEach-Object {

				# Only process actual xml files, not directories
				if ([System.IO.File]::Exists($_.FullName))
				{
					Write-Verbose -Message "Processing $($_.FullName)."

					try {

						[Xml]$Xml = Get-Content -Path $_.FullName -Raw -ErrorAction SilentlyContinue
                
						if ($Xml -ne $null -and $Xml.HasChildNodes)
						{
							if (-not $OnlyPasswordProfiles -or ($OnlyPasswordProfiles -and ($Xml.WLANPRofile.MSM.security.sharedKey.keyMaterial -ne $null)))
							{
								$Name = $Xml.WLANPRofile.name
								$SSID = $Xml.WLANProfile.SSIDConfig.name

								# Make sure these both aren't null/empty
								if (-not [System.String]::IsNullOrEmpty($Name) -or -not [System.String]::IsNullOrEmpty($SSID))
								{
									# If this is null/empty, then SSID wasn't
									if ([System.String]::IsNullOrEmpty($Name))
									{
										$Name = $SSID
									}
									else
									{
										$SSID = $Name
									}

									$Profiles.Add($Name, @{})
                            
									$Profiles[$Name].Add("Interface", $($_.Directory.Name))

									$Profiles[$Name].Add("SSID", $SSID)

									$Profiles[$Name].Add("Filename", $_.Name)

									if ($Xml.WLANProfile.MSM.security.authEncryption -ne $null)
									{
										$Profiles[$Name].Add("Encryption", $Xml.WLANProfile.MSM.security.authEncryption.encryption)
										$Profiles[$Name].Add("Authentication", $Xml.WLANProfile.MSM.security.authEncryption.authentication)
									}

									if ($Xml.WLANProfile.MSM.security.sharedKey -ne $null)
									{
										$KeyType = $Xml.WLANProfile.MSM.security.sharedKey.keyType

										if ($KeyType -eq "passPhrase" -and ($Xml.WLANProfile.MSM.security.sharedKey.keyMaterial -ne $null))
										{
											[System.String]$EncryptedPasswordHexString = $Xml.WLANProfile.MSM.security.sharedKey.keyMaterial

											if ($EncryptedPasswordHexString.Length % 2 -eq 0)
											{
												[System.Byte[]]$Bytes = New-Object -TypeName System.Byte[] -ArgumentList ($EncryptedPasswordHexString.Length / 2)

												for ($i = 0; $i -lt $Bytes.Length; $i++)
												{
													[System.String]$HexByteString = "$($EncryptedPasswordHexString[2 * $i])$($EncryptedPasswordHexString[(2 * $i) + 1])"
													$Bytes[$i] = [System.Byte]::Parse($HexByteString, [System.Globalization.NumberStyles]::HexNumber)
												}

												Write-Verbose -Message "Preparing to decrypt $EncryptedPasswordHexString."

												[System.Byte[]]$UnEncryptedData = [System.Security.Cryptography.ProtectedData]::Unprotect($Bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)

												Write-Verbose -Message "Successfully unencrypted password."

												[System.String]$Password = [System.Text.Encoding]::UTF8.GetString($UnEncryptedData)
                                        
												Write-Verbose -Message "$Password"

												# The passwords are stored as a null terminated string, so remove any leading
												# or trailing null characters
												$Password = $Password.Trim([System.Char]0x00)
												Write-Verbose -Message "Password is $Password"

												$Profiles[$Name].Add("Password", $Password)
											}
											else
											{
												Write-Verbose -Message "The key material for $($_.FullName) did not have a correctly sized key."
											}
										}
									}
								}
							}
						}
					}
					catch [Exception] {}
				}
		    }
        }
        finally 
        {
            Reset-ProcessToken -Verbose
        }

        Write-Output -InputObject $Profiles
	}

	End {
	}
}

$script:Ports = @(
	[PSCustomObject]@{"Service"="FTP Data";"Port"=20;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="FTP Command";"Port"=21;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="SSH";"Port"=22;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="TelNet";"Port"=23;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="SMTP";"Port"=25;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="WINS";"Port"=42;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="DNS";"Port"=53;"Transport"="UDP"},
	[PSCustomObject]@{"Service"="DNS";"Port"=53;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="DHCP Server";"Port"=67;"Transport"="UDP"},
	[PSCustomObject]@{"Service"="DHCP Client";"Port"=68;"Transport"="UDP"},
	[PSCustomObject]@{"Service"="TFTP";"Port"=69;"Transport"="UDP"},
	[PSCustomObject]@{"Service"="HTTP";"Port"=80;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="Kerberos";"Port"=88;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="POP3";"Port"=110;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="SFTP";"Port"=115;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="NetBIOS Name Service";"Port"=137;"Transport"="UDP"},
	[PSCustomObject]@{"Service"="NetBIOS Datagram Service";"Port"=138;"Transport"="UDP"},
	[PSCustomObject]@{"Service"="NetBIOS Session Service";"Port"=139;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="SNMP";"Port"=161;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="LDAP";"Port"=389;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="LDAP";"Port"=389;"Transport"="UDP"},
	[PSCustomObject]@{"Service"="SSL";"Port"=443;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="SMB";"Port"=445;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="Syslog";"Port"=514;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="RPC";"Port"=135;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="LDAPS";"Port"=636;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="SOCKS";"Port"=1080;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="MSSQL";"Port"=1433;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="SQL Browser";"Port"=1434;"Transport"="UDP"},
	[PSCustomObject]@{"Service"="Oracle DB";"Port"=1521;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="NFS";"Port"=2049;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="RDP";"Port"=3389;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="XMPP";"Port"=5222;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="HTTP Proxy";"Port"=8080;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="Global Catalog";"Port"=3268;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="Global Catalog/SSL";"Port"=3269;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="POP3/SSL";"Port"=995;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="IMAP/SSL";"Port"=993;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="IMAP";"Port"=143;"Transport"="TCP"},
	[PSCustomObject]@{"Service"="NTP";"Port"=123;"Transport"="UDP"},
	[PSCustomObject]@{"Service"="BGP";"Port"=179;"Transport"="TCP"}
)

$script:LsaSignature = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace BAMCIS.PowerShell.OffensiveSecurity
{
    public class LSAUtil
    {

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        private enum LSA_AccessPolicy : long
        {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L
        }

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaRetrievePrivateData(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            out IntPtr PrivateData
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaStorePrivateData(
             IntPtr policyHandle,
             ref LSA_UNICODE_STRING KeyName,
             ref LSA_UNICODE_STRING PrivateData
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaOpenPolicy(
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaNtStatusToWinError(
            uint status
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaClose(
            IntPtr policyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaFreeMemory(
            IntPtr buffer
        );

        private LSA_OBJECT_ATTRIBUTES ObjectAttributes;
        private LSA_UNICODE_STRING LocalSystem;
        private LSA_UNICODE_STRING SecretName;

        public LSAUtil(string Key)
        {
            if (Key.Length == 0)
            {
                throw new ArgumentException("Key length zero");
            }

            this.ObjectAttributes = new LSA_OBJECT_ATTRIBUTES();
            this.ObjectAttributes.Length = 0;
            this.ObjectAttributes.RootDirectory = IntPtr.Zero;
            this.ObjectAttributes.Attributes = 0;
            this.ObjectAttributes.SecurityDescriptor = IntPtr.Zero;
            this.ObjectAttributes.SecurityQualityOfService = IntPtr.Zero;

            this.LocalSystem = new LSA_UNICODE_STRING();
            this.LocalSystem.Buffer = IntPtr.Zero;
            this.LocalSystem.Length = 0;
            this.LocalSystem.MaximumLength = 0;

            this.SecretName = new LSA_UNICODE_STRING();
            this.SecretName.Buffer = Marshal.StringToHGlobalUni(Key);
            this.SecretName.Length = (UInt16)(Key.Length * UnicodeEncoding.CharSize);
            this.SecretName.MaximumLength = (UInt16)((Key.Length + 1) * UnicodeEncoding.CharSize);
        }

        private IntPtr GetLsaPolicy(LSA_AccessPolicy Access)
        {
            IntPtr LsaPolicyHandle;

            uint NtsResult = LsaOpenPolicy(ref this.LocalSystem, ref this.ObjectAttributes, (uint)Access, out LsaPolicyHandle);

            uint WinErrorCode = LsaNtStatusToWinError(NtsResult);
            if (WinErrorCode != 0)
            {
                throw new Win32Exception(Convert.ToInt32(WinErrorCode));
            }

            return LsaPolicyHandle;
        }

        private static void ReleaseLsaPolicy(IntPtr LsaPolicyHandle)
        {
            uint NtsResult = LsaClose(LsaPolicyHandle);
            uint WinErrorCode = LsaNtStatusToWinError(NtsResult);

            if (WinErrorCode != 0)
            {
                throw new Win32Exception(Convert.ToInt32(WinErrorCode));
            }
        }

        private static void FreeMemory(IntPtr Buffer)
        {
            uint NtsResult = LsaFreeMemory(Buffer);
            uint WinErrorCode = LsaNtStatusToWinError(NtsResult);
            if (WinErrorCode != 0)
            {
                throw new Win32Exception(Convert.ToInt32(WinErrorCode));
            }
        }

        public void SetSecret(string Value)
        {
            LSA_UNICODE_STRING LusSecretData = new LSA_UNICODE_STRING();

            if (Value.Length > 0)
            {
                //Create data and key
                LusSecretData.Buffer = Marshal.StringToHGlobalUni(Value);
                LusSecretData.Length = (UInt16)(Value.Length * UnicodeEncoding.CharSize);
                LusSecretData.MaximumLength = (UInt16)((Value.Length + 1) * UnicodeEncoding.CharSize);
            }
            else
            {
                //Delete data and key
                LusSecretData.Buffer = IntPtr.Zero;
                LusSecretData.Length = 0;
                LusSecretData.MaximumLength = 0;
            }

            IntPtr LsaPolicyHandle = GetLsaPolicy(LSA_AccessPolicy.POLICY_CREATE_SECRET);
            uint Result = LsaStorePrivateData(LsaPolicyHandle, ref this.SecretName, ref LusSecretData);
            LSAUtil.ReleaseLsaPolicy(LsaPolicyHandle);

            uint WinErrorCode = LsaNtStatusToWinError(Result);
            if (WinErrorCode != 0)
            {
                throw new Win32Exception(Convert.ToInt32(WinErrorCode));
            }
        }

        public string GetSecret()
        {
            IntPtr PrivateData = IntPtr.Zero;

            IntPtr LsaPolicyHandle = GetLsaPolicy(LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION);
            uint NtsResult = LsaRetrievePrivateData(LsaPolicyHandle, ref this.SecretName, out PrivateData);
            LSAUtil.ReleaseLsaPolicy(LsaPolicyHandle);

            uint WinErrorCode = LsaNtStatusToWinError(NtsResult);

            if (WinErrorCode != 0)
            {
                throw new Win32Exception(Convert.ToInt32(WinErrorCode));
            }

            LSA_UNICODE_STRING LusSecretData = (LSA_UNICODE_STRING)Marshal.PtrToStructure(PrivateData, typeof(LSA_UNICODE_STRING));
            string Value = Marshal.PtrToStringAuto(LusSecretData.Buffer).Substring(0, LusSecretData.Length / 2);

            LSAUtil.FreeMemory(PrivateData);

            return Value;
        }
    }
}
"@