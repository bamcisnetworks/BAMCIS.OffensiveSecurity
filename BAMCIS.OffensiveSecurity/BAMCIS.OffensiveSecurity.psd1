#
# Module manifest for module 'BAMCIS.OffensiveSecurity'
#
# Generated by: Michael Haken
#
# Generated on: 10/25/2017
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'BAMCIS.OffensiveSecurity.psm1'

# Version number of this module.
ModuleVersion = '1.0.1.3'

# ID used to uniquely identify this module
GUID = 'd838839f-44ab-4099-ab58-87e7cd27d1c4'

# Author of this module
Author = 'Michael Haken'

# Company or vendor of this module
CompanyName = 'BAMCIS'

# Copyright statement for this module
Copyright = '(c) 2017 BAMCIS. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Provides security focused PowerShell cmdlets to conduct security testing and forensics.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @("ESENT", "BAMCIS.Logging", "BAMCIS.Common", "BAMCIS.TokenManipulation", "BAMCIS.Networking")

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module
FunctionsToExport = @(
	"Start-PortScan", "Get-WebHistory", "Get-LsaSecret", "Get-WifiProfiles"
)

# Cmdlets to export from this module
# CmdletsToExport = @()

# Variables to export from this module
# VariablesToExport = @()

# Aliases to export from this module
# AliasesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess
PrivateData = @{
	PSData = @{
		Title = "BAMCIS Offensive Security"

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @("PortScan", "Password", "LSASecrets", "WebHistory", "Forensics")

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/bamcisnetworks/BAMCIS.OffensiveSecurity/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/bamcisnetworks/BAMCIS.OffensiveSecurity'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = '*1.0.1.3
Removed excess verbose content.
		
*1.0.1.2
Fixed password decryption in Get-WifiProfiles cmdlet.
		
*1.0.1.1
Added additional output properties to Get-WifiProfiles cmdlet.
		
*1.0.1.0
Added the Get-WifiProfiles cmdlet.
		
*1.0.0.0
Initial Release. This module has been separated from the HostUtilities module to provide a lighter weight module that is more reusable across other modules.
'

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

