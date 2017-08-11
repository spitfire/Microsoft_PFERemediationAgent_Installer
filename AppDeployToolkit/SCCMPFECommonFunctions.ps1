<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2017 v5.4.140
	 Created on:   	07.07.2017 09:48
	 Created by:   	Mieszko Ślusarczyk
	 Organization: 	International Paper
	 Filename:     	
	===========================================================================
	.DESCRIPTION
		Creates a new folder called $FolderName and file share called $ShareName that's pointing to it. This is for SCCM PFE Client Health solution. It is mean to be ran on new SCCM primary servers.
#>
#region SCCM PFE Primary site functions

#region Create-SCCMPFEClientFolder
Function Create-SCCMPFEClientFolder
{
	$ShareName = "Client$"
	If (Get-SmbShare -Name PFEOutgoing$)
	{
		$FolderName = ((Get-SmbShare -Name PFEOutgoing$).Path).Replace('PFEOutgoing$', "$ShareName")
		$PFEOutgoingShare = (Get-SmbShare -Name PFEOutgoing$).Path
	}
	If (!(Test-Path "$FolderName"))
	{
		Try
		{
			
			Write-Log "Info: Folder $FolderName does not exist, creating it.." -Source Create-SCCMPFEClientFolder
			New-Item "$FolderName" –type directory
			If (Test-Path "$FolderName")
			{
				Write-Log "Info: Created folder $FolderName" -Source Create-SCCMPFEClientFolder
			}
			Else
			{
				Write-Log "Error: Failed to create $FolderName Folder" -Source Create-SCCMPFEClientFolder
				Read-Host -Prompt "Press enter to exit"
				Exit
			}
		}
		Catch
		{
			Write-Log "Failed to create $FolderName Folder" -Source Create-SCCMPFEClientFolder
			Exit-Script -ExitCode 69111
		}
		
	}
	Else
	{
		Write-Log "Folder $FolderName already exists" -Source Create-SCCMPFEClientFolder
	}
}

#endregion Create-SCCMPFEClientFolder

#region Apply-SCCMPFEClientFolderPermissions
Function Apply-SCCMPFEClientFolderPermissions
{
	Write-Log "Setting ACLs for $FolderName"
	If (!(Get-Module ActiveDirectory)) { Import-Module ActiveDirectory }
	$Domains = Get-ADForest | Select-Object -ExpandProperty Domains
	ForEach ($Domain in $Domains)
	{
		$Acl = Get-Acl "$FolderName"
		$Ar = New-Object  system.security.accesscontrol.filesystemaccessrule("$Domain\Domain Computers", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
		$Acl.SetAccessRule($Ar)
		Try
		{
			Write-Log "Info: Setting ACL for $Domain`\Domain Computers" -Source Apply-SCCMPFEClientFolderPermissions
			Set-Acl "$FolderName" $Acl
			Write-Log "Info: Applied ACL for $Domain`\Domain Computers" -Source Apply-SCCMPFEClientFolderPermissions
		}
		Catch
		{
			Write-Log "Error: Failed to set ACL for $Domain`\Domain Computers" -Source Apply-SCCMPFEClientFolderPermissions
			Exit-Script -ExitCode 69112
		}
	}
}

#endregion Apply-SCCMPFEClientFolderPermissions

#region Create-SCCMPFEClientShare
Function Create-SCCMPFEClientShare
{
	If (!(Get-SmbShare -Name "$ShareName" -ea 0))
	{
		Write-Log "Share $ShareName does not exist, creating it.." -Source Create-SCCMPFEClientShare
		New-SMBShare –Name "$ShareName" –Path "$FolderName" `
					 -ReadAccess "APACIPAPER\Domain Computers", "EMEAIPAPER\Domain Computers", "NAIPAPER\Domain Computers", "SAIPAPER\Domain Computers"
		Write-Log "Created share $ShareName" -Source Create-SCCMPFEClientShare
	}
	Else
	{
		Write-Log "Info Share already exists" -Source Create-SCCMPFEClientShare
	}
	If (Get-SmbShare -Name "$ShareName" -ea 0)
	{
		Write-Log "Share $ShareName created successfully" -Source Create-SCCMPFEClientShare
	}
	Else
	{
		Write-Log "Failed to create share" -Source Create-SCCMPFEClientShare
		Exit-Script -ExitCode 69113
	}
}

#endregion Create-SCCMPFEClientShare

#region Create-SCCMPFEConfiguration
Function Create-SCCMPFEConfiguration
{
	
	$myFQDN = (Get-WmiObject win32_computersystem).DNSHostName + "." + (Get-WmiObject win32_computersystem).Domain
	$SiteCode = Get-ItemProperty "HKLM:\Software\Microsoft\SMS\MP" -Name "Assignment Site" | Select "Assignment Site" -ExpandProperty "Assignment Site"
	$SiteXML = @"
		<sites>
			<default>
		    	<!--- Remediation Settings -->
					<CreateDDR>TRUE</CreateDDR>
			    	<HTTPDDR>FALSE</HTTPDDR>
			    	<ServerRemediation>FALSE</ServerRemediation>
			    	<WorkstationRemediation>FALSE</WorkstationRemediation>
			    	<Debug>FALSE</Debug>
			    <!--- Site Settings -->
			    	<PrimarySiteServer>$myFQDN</PrimarySiteServer>
			    	<PrimarySiteURL>http://$myFQDN</PrimarySiteURL>
			    	<SCCMEnv>2012</SCCMEnv>
					<SiteCode>$SiteCode</SiteCode>
			    <!--- Windows Service Remediation Settings -->
					<BITSService>TRUE</BITSService>
			    	<DCOMVerify>TRUE</DCOMVerify>
					<WMIService>TRUE</WMIService>
				<CCMService>TRUE</CCMService>
			    	<WUAService>TRUE</WUAService>
			    	<PolicyPlatformLocalAuthorityService>TRUE</PolicyPlatformLocalAuthorityService>
			    	<PolicyPlatformProcessorService>TRUE</PolicyPlatformProcessorService>
			    <!--- ConfigMgr Remediation Settings -->
					<LatestSCCMVersion>5.00.8498.1711</LatestSCCMVersion>
					<CCMRepository>TRUE</CCMRepository>
			    	<HWINV>TRUE</HWINV>
			    	<SWINV>TRUE</SWINV>
			    	<LanternAppCI>TRUE</LanternAppCI>
			    	<Heartbeat>TRUE</Heartbeat>
			    	<LogDaysStale>14</LogDaysStale>
			    <!--- WMI Remediation Settings -->
					<WMIReadRepository>TRUE</WMIReadRepository>
					<WMIRebuild>TRUE</WMIRebuild>
					<WMIWriteRepository>TRUE</WMIWriteRepository>
			    	<!--- Optional Client Install Settings -->
			    	<ExtraEXECommands></ExtraEXECommands>
			    	<ExtraMSICommands>FSP=$myFQDN</ExtraMSICommands>
			    <!--- Alternate Content Provider Remediation Settings -->
					<ACPService>FALSE</ACPService>    	
					<ACPInstallCmd></ACPInstallCmd>
			    	<ACPInstallArgs></ACPInstallArgs>
			    	<ACPServiceName></ACPServiceName>
			        <ACPServiceStartType>Automatic</ACPServiceStartType>
			</default>
		</sites>
"@
	
	$SiteXML | Out-File "$PFEOutgoingShare\PFERemediationSettings.xml"
}#endregion Create-SCCMPFEConfiguration

#region Create-SCCMPFEConfiguration
Function Copy-SCCMPFEConfiguration
{
	Copy-File "$dirSupportFiles\PFERemediationScript.ps1" -Destination "$PFEOutgoingShare\"
	Copy-File "$dirSupportFiles\PFERemediation.exe.config" -Destination "$PFEOutgoingShare\"
}#endregion Create-SCCMPFEConfiguration

#endregion SCCM PFE Primary site functions

#region Get-AllDomains
Function Get-AllDomains
{
	$Root = [ADSI]"LDAP://RootDSE"
	$oForestConfig = $Root.Get("configurationNamingContext")
	$oSearchRoot = [ADSI]("LDAP://CN=Partitions," + $oForestConfig)
	$AdSearcher = [adsisearcher]"(&(objectcategory=crossref)(netbiosname=*))"
	$AdSearcher.SearchRoot = $oSearchRoot
	$domains = $AdSearcher.FindAll()
	return $domains |ft
}#endregion Get-AllDomains

#region Get-ADSite
function Get-ADSite
{
	param
	(
		$ComputerName = $env:COMPUTERNAME
	)
	Try
	{
		Write-Log "Info: trying to extract site code using System.DirectoryServices.ActiveDirectory.ActiveDirectorySite" -Source Get-ADSite
		$ADSite = ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).Name
	}
	Catch
	{
		Write-Log "Warning: failed to extract site code using System.DirectoryServices.ActiveDirectory.ActiveDirectorySite, trying nltest" -Severity 2 -Source Get-ADSite
		If (!($ComputerName))
		{
			Write-Log "Error: Computer Name not passed" -Severity 3 -Source Get-ADSite
		}
		$site = nltest /server:$ComputerName /dsgetsite 2>$null
		if ($LASTEXITCODE -eq 0) { $ADSite = $site[0] }
	}
	If ($ADSite)
	{
		Write-Log "Info: AD Site Name is $ADSite" -Source Get-ADSite
	}
	Else
	{
		Write-Log "Error: Failed to find AD Site Name" -Source Get-ADSite
	}
	$ADSite
}#endregion Get-ADSite

#region Get-ADSiteCode
function Get-ADSiteCode
{
	param
	(
		$ADSite
	)
	
	
	If (!($ADSite))
	{
		$ADSite = Get-ADSite
	}
	Write-Log "ADSiteName $ADSite" -Source Get-ADSiteCode
	try
	{
		$ADSiteCode = ($ADSite.split('-'))[1]
		Write-Log "AD Site Code $ADSiteCode" -Source Get-ADSiteCode
	}
	catch
	{
	}
	Return $ADSiteCode
}#endregion Get-ADSiteCode

#region Get-SMSSiteCode
Function Get-SMSSiteCode
{
	param
	(
		[ValidateSet('AD', 'WMI')]
		[string]$Source = "AD",
		[bool]$Primary = $true
	)
	
	If ($Source -eq "AD")
	{
		If ($Primary -eq $true)
		{
			$SMSSiteCode = Get-SMSSiteCode -Source AD -Primary $false
			If ($SMSSiteCode)
			{
				Try
				{
					Write-Log "Info: Looking for $SMSSiteCode in $($Domain.Properties.ncname[0])" -Source Get-SMSSiteCode
					$ADSysMgmtContainer = [ADSI]("LDAP://CN=System Management,CN=System," + "$($Domain.Properties.ncname[0])")
					$AdSearcher = [adsisearcher]"(&(mSSMSSiteCode=$SMSSiteCode)(ObjectClass=mSSMSSite))"
					$AdSearcher.SearchRoot = $ADSysMgmtContainer
					$CMSiteFromAD = $AdSearcher.FindONE()
					$SMSPrimarySiteCode = $CMSiteFromAD.Properties.mssmsassignmentsitecode
					If ($SMSPrimarySiteCode)
					{
						Write-Log "Success: Found SCCM primary site code in AD $SMSPrimarySiteCode" -Source Get-SMSSiteCode
						$SMSSiteCode = $SMSPrimarySiteCode
					}
					Else
					{
						Write-Log "Error: Could not find SCCM primary site code" -Severity 3 -Source Get-SMSSiteCode
					}
				}
				Catch
				{
					Write-Log "Error: Failed to find SCCM primary site code" -Severity 3 -Source Get-SMSSiteCode
				}
			}
			Else
			{
				Write-Log "Error: Get-SMSSiteCode did not return SMSSiteCode" -Severity 3 -Source Get-SMSSiteCode
			}
			
			Return $SMSSiteCode
		}
		ElseIf ($Primary -eq $false)
		{
			$domains = Get-AllDomains
			$ADSite = Get-ADSite
			Foreach ($script:domain in $domains)
			{
				Try
				{
					Write-Log "Info: Looking for $ADSite in $($Domain.Properties.ncname[0])" -Source Get-SMSSiteCode
					$ADSysMgmtContainer = [ADSI]("LDAP://CN=System Management,CN=System," + "$($Domain.Properties.ncname[0])")
					$AdSearcher = [adsisearcher]"(&(mSSMSRoamingBoundaries=$ADSite)(ObjectClass=mSSMSSite))"
					$AdSearcher.SearchRoot = $ADSysMgmtContainer
					$CMSiteFromAD = $AdSearcher.FindONE()
					$SMSSiteCode = $CMSiteFromAD.Properties.mssmssitecode
					If ($SMSSiteCode)
					{
						Write-Log "Success: Found SCCM site code $SMSSiteCode" -Source Get-SMSSiteCode
						Break
					}
				}
				Catch { }
			}
			Return $SMSSiteCode
		}
	}
	ElseIf ($Source -eq "WMI")
	{
		If ($Primary -eq $true)
		{
			Try
			{
				Write-Log "Info: Trying to get primary site code assignment from WMI" -Source Get-SMSSiteCode
				$SMSPrimarySiteCode = ([wmiclass]"ROOT\ccm:SMS_Client").GetAssignedSite().sSiteCode
				If ($SMSPrimarySiteCode)
				{
					Write-Log "Success: Found SCCM primary site code in WMI $SMSPrimarySiteCode" -Source Get-SMSSiteCode
					$SMSSiteCode = $SMSPrimarySiteCode
				}
				Else
				{
					Write-Log "Error: Failed to get primary site code assignment from WMI" -Severity 3 -Source Get-SMSSiteCode
				}
			}
			Catch
			{
				Write-Log "Error: Failed to get primary site code assignment from WMI" -Severity 3 -Source Get-SMSSiteCode
			}
			Return $SMSSiteCode
		}
		ElseIf ($Primary -eq $false)
		{
			Try
			{
				Write-Log "Info: Trying to get site code assignment from WMI" -Source Get-SMSSiteCode
				$SMSSiteCode = Get-WmiObject -Namespace "ROOT\ccm" -Class "SMS_MPProxyInformation" -Property SiteCode | select -ExpandProperty SiteCode
				If ($SMSSiteCode)
				{
					Write-Log "Success: Found SCCM site code in WMI $SMSSiteCode" -Source Get-SMSSiteCode
				}
			}
			Catch
			{
				Write-Log "Error: Failed to get primary site code assignment from WMI" -Severity 3 -Source Get-SMSSiteCode
			}
		}
	}
	
	
	If ($Primary -eq $true)
	{
		$SMSSiteCode = $SMSPrimarySiteCode
	}
}#endregion Get-SMSSiteCode

#region Get-SMSMP
Function Get-SMSMP
{
	param
	(
		[ValidateSet('AD', 'WMI')]
		[string]$Source = "AD",
		[bool]$Primary = $true
	)
	If ($Source -eq "AD")
	{
		If ($Primary -eq $true)
		{
			$SMSSiteCode = Get-SMSSiteCode -Source AD -Primary $true
			[string]$SMSMPType = "Primary Site Management Point"
		}
		ElseIf ($Primary -eq $false)
		{
			$SMSSiteCode = Get-SMSSiteCode -Source AD -Primary $false
			[string]$SMSMPType = "Management Point"
		}
		
		If ($SMSSiteCode)
		{
			Write-Log "Info: Trying to find SCCM $SMSMPType in AD" -Source Get-SMSMP
			Try
			{
				$ADSysMgmtContainer = [ADSI]("LDAP://CN=System Management,CN=System," + "$($Domain.Properties.ncname[0])")
				$AdSearcher = [adsisearcher]"(&(Name=SMS-MP-$SMSSiteCode-*)(objectClass=mSSMSManagementPoint))"
				$AdSearcher.SearchRoot = $ADSysMgmtContainer
				$CMManagementPointFromAD = $AdSearcher.FindONE()
				$MP = $CMManagementPointFromAD.Properties.mssmsmpname[0]
				If ($MP)
				{
					Write-Log "Success: Found SCCM $SMSMPType $MP in AD" -Source Get-SMSMP
				}
				Else
				{
					Write-Log "Error: Failed to find SCCM $SMSMPType in AD" -Severity 3 -Source Get-SMSMP
				}
			}
			Catch
			{
				Write-Log "Error: Failed to find SCCM $SMSMPType in AD" -Severity 3 -Source Get-SMSMP
			}
		}
		Else
		{
			Write-Log "Error: Get-SMSSiteCode did not return SMSPrimarySiteCode" -Severity 3 -Source Get-SMSMP
		}
	}
	ElseIf ($Source -eq "WMI")
	{
		If ($Primary -eq $true)
		{
			[string]$SMSMPType = "Primary Site Management Point"
		}
		ElseIf ($Primary -eq $false)
		{
			[string]$SMSMPType = "Management Point"
		}
		Write-Log "Info: Trying to find SCCM $SMSMPType in WMI" -Source Get-SMSMP
		
		Try
		{
			If ($Primary -eq $true)
			{
				$MP = Get-WmiObject -Namespace "ROOT\ccm" -Class "SMS_LookupMP" -Property Name | select -ExpandProperty Name
			}
			ElseIf ($Primary -eq $false)
			{
				$MP = Get-WmiObject -Namespace "ROOT\ccm" -Class "SMS_LocalMP" -Property Name | select -ExpandProperty Name
			}
			If ($MP)
			{
				Write-Log "Scuccess: SCCM $SMSMPType in WMI is $MP" -Source Get-SMSMP
			}
			Else
			{
				Write-Log "Error: Failed to find SCCM $SMSMPType in WMI" -Severity 3 -Source Get-SMSMP
			}
		}
		Catch
		{
			Write-Log "Error: Failed to find SCCM $SMSMPType in WMI" -Severity 3 -Source Get-SMSMP
		}
	}
	
	Return $MP
}#endregion Get-SMSMP