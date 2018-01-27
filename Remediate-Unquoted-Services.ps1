
function Remediate-Unquoted-Services{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline=$True)]
        [String[]]$ComputerName
    )
    Begin{
        Write-Verbose "Remediating unquoted service path vulnerability."
    }
    Process{
        if($ComputerName.Length>1){
            foreach($Computer in $ComputerName){
                if(-not (Test-Connection $Computer)){
                    Write-Error "Unable to connect to $Computer"
                }
                else{
                    Find-Unquoted-Services -ComputerName $Computer | Repair-Unquoted-Service
                }
            }
        }
        elseif($ComputerName.Length==1)
        {
            $Computer=$ComputerName[0];
            if(-not (Test-Connection $Computer)){
                Write-Error "Unable to connect to $Computer"
            }
            else{
                Find-Unquoted-Services -ComputerName $Computer | Repair-Unquoted-Service
            }
        }
        else{
            Find-Unquoted-Services | Repair-Unquoted-Service
        }
    }
    End{}
}

function Find-Unquoted-Services{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline=$True)]
        [String]$ComputerName
    )
    Begin{
        Write-Verbose "Finding Unquoted Services on computer: $ComputerName"
    }
    Process{
        if($ComputerName==null){
            $Services=Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" 
            $UnquotedServices = $services | ForEach-Object {get-itemproperty $_.PsPath | Where-Object {($_.ImagePath -match '^[^\"].*\s') -and -not (Test-Path $_.ImagePath.split(" ")[0] -pathtype leaf)}} | Select-Object PSPath, ImagePath
            # TODO: Rename Properties before passing in as pipeline input to Repair cmdlet
            $UnquotedServices | Repair-Unquoted-Service
        }
        else{
        }
    }
    End{}
}
function Repair-Unquoted-Service{
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline=$True)]
        [String]$ServicePSPath,
        [String]$UnquotedImagePath
    )
    Begin{
        Write-Debug "Repairing unquoted service string: $UnquotedImagePath"
    }
    Process{
        # TODO: Build loop to find the end of the path that needs to be quoted (Do not use .exe to find it as it is not robust)
        # TODO: Set the quoted string in the registry at the PSPath location
    }
    End{}
}