#The following script randomizes your MAC address.

#NOTE:  This script requires being as an administrator.
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (! $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    "This script must be run as an administrator.  Please rerun with appropriate credentials."
    exit
}

#First, enter the hardware MAC address for the interface whose MAC you want to randomize.  This can be obtained by using ipconfig /all in the
# "Physical Address" field.

# A Media Access Control address is 12 hex digits.  Generally, the first 6 hex digits are the OUI (organizationally unique identifier).
# The OUI should not be randomly generated; and should match some OUI derived from a real device.  This script will use the OUI from
# the hardware MAC you provide.
$HardwareMAC = ""
if ($HardwareMAC -eq "")
{
    'Please enter a MAC address into the $HardwareMAC variable.'
    exit
}

$HardwareMACNoDashes = $HardwareMAC.Replace("-","")
$OUI = $HardwareMACNoDashes.Substring(0,6)

#The Windows Registry key that we want to set is in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}
#At that location, there are several keys in the format 0000, 0001, 0002, etc.  Prior to running the script, browse to the key above and
#determine which of the keys inside contains your NIC.  The DriverDesc value contains a description of the NIC.  Set NICKey appropriately.
$NICKey="0005"

#Obtain 6 randomly-generated seeds to assist with PRNG generation of each hex digit
$SeedsString = (Invoke-WebRequest -URI "https://www.random.org/integers/?num=6&min=1&max=1000000000&col=1&base=10&format=plain&rnd=new").Content.Split("`r`n")

#Generate 6-hex-digit string
function Get-RandomHexDigit {
    Param([Parameter(Mandatory=$True)] $Seed)
    '{0:x}' -f (Get-Random -SetSeed $Seed -Min 1 -Max 15)
}

$GenDigits=@()

For ($i = 0; $i -lt 6; $i++)
{    
    $GenDigits = "$GenDigits$(Get-RandomHexDigit -Seed $SeedsString[$i])"
}

$GenDigitsString = $GenDigits.ToString()
$GenDigitsString = $GenDigitsString.ToUpper()

$NewMACAddress = "$OUI$GenDigitsString"

$OldMACAddress = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\$NICKey").NetworkAddress

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\$NICKey" -Name "NetworkAddress" -Value $NewMACAddress

#Disable/reenable the NIC to enable the new MAC address to take effect
$Adapter = Get-NetAdapter | Where-Object{$_.MacAddress -eq $HardwareMAC}
$Adapter | Disable-NetAdapter -Confirm:$false
$Adapter | Enable-NetAdapter -Confirm:$false

"Done.

Adapter specified:"
$Adapter | Select Name,InterfaceDescription,InterfaceIndex,MacAddress | fl
"Old MAC Address:$OldMACAddress -> New MAC Address:$NewMACAddress"