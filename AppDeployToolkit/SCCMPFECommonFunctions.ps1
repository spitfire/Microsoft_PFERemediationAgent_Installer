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
		Creates a new folder called $ClientShareName and file share called $ClientShareName that's pointing to it. This is for SCCM PFE Client Health solution. It is mean to be ran on new SCCM primary servers.
#>
#region SCCM PFE Primary site functions
$ClientShareName = "Client$"
Try
{
	Write-Log "Info Trying to find domains using ActiveDirectory module" -Source Apply-SCCMPFEClientFolderPermissions
	If (!(Get-Module ActiveDirectory)) { Import-Module ActiveDirectory }
	$script:Domains = Get-ADForest | Select-Object -ExpandProperty Domains
}
Catch
{
	Write-Log "Warning: Failed to find domains using ActiveDirectory module" -Severity 2 -Source Apply-SCCMPFEClientFolderPermissions
	Try
	{
		Write-Log "Trying to find domains using system.directoryservices.activedirectory.Forest" -Source Apply-SCCMPFEClientFolderPermissions
		$script:Domains = (([system.directoryservices.activedirectory.Forest]::GetCurrentForest()).Domains) | %{ $_.Name }
	}
	Catch
	{
		Write-Log "Error: Failed to find domains using system.directoryservices.activedirectory.Forest" -Severity 3 -Source Apply-SCCMPFEClientFolderPermissions
	}
}

#region Create-SCCMPFEClientFolder
Function Create-SCCMPFEClientFolder
{
	
	If (Get-SmbShare -Name PFEOutgoing$)
	{
		$script:PFEClientSharePath = ((Get-SmbShare -Name PFEOutgoing$).Path).Replace('PFEOutgoing$', "$ClientShareName")
	}
	If (!(Test-Path "$script:PFEClientSharePath"))
	{
		Try
		{
			
			Write-Log "Info: Folder $script:PFEClientSharePath does not exist, creating it.." -Source Create-SCCMPFEClientFolder
			New-Item "$script:PFEClientSharePath" –type directory
			If (Test-Path "$script:PFEClientSharePath")
			{
				Write-Log "Info: Created folder $script:PFEClientSharePath" -Source Create-SCCMPFEClientFolder
			}
			Else
			{
				Write-Log "Error: Failed to create $script:PFEClientSharePath Folder" -Source Create-SCCMPFEClientFolder
				Read-Host -Prompt "Press enter to exit"
				Exit
			}
		}
		Catch
		{
			Write-Log "Failed to create $script:PFEClientSharePath Folder" -Source Create-SCCMPFEClientFolder
			Exit-Script -ExitCode 69111
		}
		
	}
	Else
	{
		Write-Log "Folder $script:PFEClientSharePath already exists" -Source Create-SCCMPFEClientFolder
	}
}

#endregion Create-SCCMPFEClientFolder

#region Apply-SCCMPFEClientFolderPermissions
Function Apply-SCCMPFEClientFolderPermissions
{
	
	$script:PFEOutgoingShare = (Get-SmbShare -Name PFEOutgoing$).Path
	$script:PFEIncomingShare = (Get-SmbShare -Name PFEIncoming$).Path
	If (Get-SmbShare -Name "$ClientShareName" -ea 0)
	{
		$script:PFEClientSharePath = (Get-SmbShare -Name "$ClientShareName").Path
	}
	$Folders = @("$script:PFEClientSharePath", "$script:PFEOutgoingShare")
	
	foreach ($Folder in $Folders)
	{
		Write-Log "Setting ACLs for $Folder" -Source Apply-SCCMPFEClientFolderPermissions
		
		
		ForEach ($Domain in $script:Domains)
		{
			$Acl = Get-Acl "$Folder"
			$Ar = New-Object  system.security.accesscontrol.filesystemaccessrule("$Domain\Domain Computers", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
			$Acl.SetAccessRule($Ar)
			Try
			{
				Write-Log "Info: Setting ReadAndExecute ACL on $Folder for $Domain`\Domain Computers" -Source Apply-SCCMPFEClientFolderPermissions
				Set-Acl "$Folder" $Acl
				Write-Log "Info: Applied ReadAndExecute ACL on $Folder for $Domain`\Domain Computers" -Source Apply-SCCMPFEClientFolderPermissions
			}
			Catch
			{
				Write-Log "Error: Failed to set ReadAndExecute ACL on $Folder for $Domain`\Domain Computers" -Source Apply-SCCMPFEClientFolderPermissions
				Exit-Script -ExitCode 69112
			}
		}
	}
	$Folder = $script:PFEIncomingShare
	ForEach ($Domain in $script:Domains)
	{
		$Acl = Get-Acl "$Folder"
		$Ar = New-Object  system.security.accesscontrol.filesystemaccessrule("$Domain\Domain Computers", "Read, Write, ReadAndExecute, Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
		$Acl.SetAccessRule($Ar)
		Try
		{
			Write-Log "Info: Setting ReadWriteExecuteModify ACL on $Folder for $Domain`\Domain Computers" -Source Apply-SCCMPFEClientFolderPermissions
			Set-Acl "$Folder" $Acl
			Write-Log "Info: Applied ReadWriteExecuteModify ACL on $Folder for $Domain`\Domain Computers" -Source Apply-SCCMPFEClientFolderPermissions
		}
		Catch
		{
			Write-Log "Error: Failed to set ReadWriteExecuteModify ACL on $Folder for $Domain`\Domain Computers" -Source Apply-SCCMPFEClientFolderPermissions
			Exit-Script -ExitCode 69112
		}
	}
}

#endregion Apply-SCCMPFEClientFolderPermissions

#region Create-SCCMPFEClientShare
Function Create-SCCMPFEClientShare
{
	If (!(Get-SmbShare -Name "$ClientShareName" -ea 0))
	{
		Write-Log "Share $ClientShareName does not exist, creating it.." -Source Create-SCCMPFEClientShare
		New-SMBShare –Name "$ClientShareName" –Path "$script:PFEClientSharePath" `
					 -ReadAccess "APACIPAPER\Domain Computers", "EMEAIPAPER\Domain Computers", "NAIPAPER\Domain Computers", "SAIPAPER\Domain Computers"
		#Write-Log "Created share $ClientShareName" -Source Create-SCCMPFEClientShare
		If (Get-SmbShare -Name "$ClientShareName" -ea 0)
		{
			Write-Log "Share $ClientShareName created successfully" -Source Create-SCCMPFEClientShare
		}
		Else
		{
			Write-Log "Failed to create share" -Source Create-SCCMPFEClientShare
			Exit-Script -ExitCode 69113
		}
	}
	Else
	{
		Write-Log "Info: Share already exists, applying permissions" -Source Create-SCCMPFEClientShare
		
		foreach ($domain in $script:Domains)
		{
			Write-Log "Info: Applying Read permissions on $ClientShareName for $domain\Domain Computers" -Source Create-SCCMPFEClientShare
			Grant-SmbShareAccess -Name "$ClientShareName" -AccountName "$domain\Domain Computers" -AccessRight Read -Confirm:$false
		}
		
	}
}#endregion Create-SCCMPFEClientShare

#region Create-SCCMPFESharesPermissions
Function Create-SCCMPFESharesPermissions
{
	foreach ($domain in $script:Domains)
	{
		Write-Log "Info: Applying Change permissions on PFEIncoming$ for $domain\Domain Computers" -Source Create-SCCMPFEClientShare
		Grant-SmbShareAccess -Name 'PFEIncoming$' -AccountName "$domain\Domain Computers" -AccessRight Change -Confirm:$false
	}
	foreach ($domain in $script:Domains)
	{
		Write-Log "Info: Applying Read permissions on PFEOutgoing$ for $domain\Domain Computers" -Source Create-SCCMPFEClientShare
		Grant-SmbShareAccess -Name 'PFEOutgoing$' -AccountName "$domain\Domain Computers" -AccessRight Read -Confirm:$false
	}
}#endregion Create-SCCMPFESharesPermissions

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

#region Copy-SCCMPFEConfiguration
Function Copy-SCCMPFEConfiguration
{
	Copy-File "$dirSupportFiles\PFERemediationScript.ps1" -Destination "$PFEOutgoingShare\"
	Copy-File "$dirSupportFiles\PFERemediation.exe.config" -Destination "$PFEOutgoingShare\"
}#endregion Copy-SCCMPFEConfiguration

#endregion SCCM PFE Primary site functions

#region Get-AllDomains
Function Get-AllDomains
{
	$Root = [ADSI]"LDAP://RootDSE"
	$oForestConfig = $Root.Get("configurationNamingContext")
	$oSearchRoot = [ADSI]("LDAP://CN=Partitions," + $oForestConfig)
	$AdSearcher = [adsisearcher]"(&(objectcategory=crossref)(netbiosname=*))"
	$AdSearcher.SearchRoot = $oSearchRoot
	$script:Domains = $AdSearcher.FindAll()
	return $script:Domains |ft
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
			$script:Domains = Get-AllDomains
			$ADSite = Get-ADSite
			Foreach ($script:domain in $script:Domains)
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