$outDirectory = "C:\temp\"
$putFile = $outDirectory + "neo4j.zip"
$driverDirectory = $outDirectory + "neo4jdriver"
$driverPath = $driverDirectory + "\lib\netstandard1.3\Neo4j.Driver.dll"
$neo4jDriver = "https://az320820.vo.msecnd.net/packages/neo4j.driver.1.7.0.nupkg"
#(New-Object System.Net.WebClient).DownloadFile($neo4jDriver, $putFile)
#Expand-Archive -Path $putFile -DestinationPath $driverDirectory 

Add-Type -Path $driverPath 

function run_query{
    param([string]$query)

    $authToken = [Neo4j.Driver.V1.AuthTokens]::Basic('neo4j', 'neon4j')
    $dbDriver = [Neo4j.Driver.V1.GraphDatabase]::Driver("bolt://localhost:7687", $authToken)
    $session = $dbDriver.Session()
    try {
        $result = $session.Run($query)
    
        Write-Host ($result | ConvertTo-JSON -Depth 5)
    }
    finally {
        $session = $null
        $dbDriver = $null
    }
}

function deleteAllNodes{ 
        $deleteQuery = @"
        MATCH (n)
        OPTIONAL MATCH (n)-[r]-()
        DELETE n,r
"@    

    run_query $deleteQuery
}

function createHostNodes{
    param($collection)

    $collection | ForEach-Object {
        $type = $_.type
        $_.objects | ForEach-Object {
            "CREATE (:$type{name:$($_.name)})"
        }
        #$createQuery
    }
}

Clear-Host
$countQuery = "MATCH (n) RETURN Count(n) AS NumNodes"
run_query $countQuery

$json =  Get-Content -Path "C:\CodeRepository\Security-Assessement\configuration scripts\platforms.json" | ConvertFrom-Json
createHostNodes $json 


<#
$attackPatternFilter = "attack-pattern"
$courseOfActionFilter = "course-of-action"
$identityFilter = "identity"
$intrusionSetFilter = "intrusion-set"
$malwareFilter = "malware"
$markingDefinitionFilter = "marking-definition"
$relationShipFilter = "relationship"
$toolFilter = "tool"
$mitreMatrixFilter = "x-mitre-matrix"
$mitreTacticFilter = "x-mitre-tactic"

$mitre = Get-Content -Path .\enterprise-attack.json | ConvertFrom-Json
$attackPattern = $mitre.objects | Where-Object {$_.type -eq $attackPatternFilter }
$courseOfAction = $mitre.objects | Where-Object {$_.type -eq $courseOfActionFilter }
$identity = $mitre.objects | Where-Object {$_.type -eq $identityFilter }
$intrusionSet = $mitre.objects | Where-Object {$_.type -eq $intrusionSetFilter }
$malware = $mitre.objects | Where-Object {$_.type -eq $malwareFilter }
$markingDefinition = $mitre.objects | Where-Object {$_.type -eq $markingDefinitionFilter }
$relationShi = $mitre.objects | Where-Object {$_.type -eq $relationShipFilter }
$tool = $mitre.objects | Where-Object {$_.type -eq $toolFilter }
$mitreMatrix = $mitre.objects | Where-Object {$_.type -eq $mitreMatrixFilter }
$mitreTactic = $mitre.objects | Where-Object {$_.type -eq $mitreTacticFilter }

$json =  Get-Content -Path "C:\CodeRepository\Security-Assessement\configuration scripts\platforms.json" | ConvertFrom-Json

$typeID = 0
add_id($json)
$json | ForEach {add_id($_.objects)}

function add_id{
    param($collection)

    $collection | ForEach {$Global:typeID++; $_ | Add-Member ID $typeID }
}

#>
