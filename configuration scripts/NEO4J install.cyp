//==============================NEO4J Threat assessment mapping=======================================
//Author: M Evans
//Notes:
//CREATE (:SolutionType{type:"Cloud"}),(:SolutionType{type:"Web"})
//CREATE (:DataProtectionLevel{level:"PIR 0"}), (:DataProtectionLevel{level:"PIR 1"}), (:DataProtectionLevel{level:"PIR 2"}), (:DataProtectionLevel{level:"PIR 3"}), (:DataProtectionLevel{level:"PIR 4"}), (:DataProtectionLevel{level:"PIR 5"})
//CREATE (:ThreatActor{name:"External threat"}),(:ThreatActor{name:"Internal threat"}),(:ThreatActor{name:"Third party"})


//Step 1
LOAD CSV WITH HEADERS FROM "file:///Controls.csv" AS line 
CREATE (:Control{name:line.NAME, family:line.FAMILY, title: line.TITLE, priority:line.PRIORITY, impact:line.BASELINE})

//Step 2
LOAD CSV WITH HEADERS FROM "file:///Threats.csv" AS line 
CREATE (:Threat{threatId:line.ThreatID, threat:line.Threat})

//Step 3
LOAD CSV WITH HEADERS FROM "file:///Relations.csv" AS line
MATCH(c:Control) WHERE c.title IN split(line.Controls, ",")
MATCH(t:Threat) WHERE t.threat IN line.Threat
CREATE (t)-[:Mitigation]->(c)

//Step 4
LOAD CSV WITH HEADERS FROM "file:///DetailedThreats.csv" AS line 
CREATE (:DetailedThreat{threatId:line.ThreatID, threat:line.Threat})

//Step 5
LOAD CSV WITH HEADERS FROM "file:///Features.csv" AS line 
CREATE (f:Feature{featureId:line.FeatureID, feature:line.Feature})
WITH f, line
MATCH (dt:DetailedThreat) WHERE dt.threatId IN split(line.DetailedThreatIDs, ",")
CREATE (f)-[:AttackVector]->(dt)

//Step6
LOAD CSV WITH HEADERS FROM "file:///Features.csv" AS line 
MATCH (f:Feature) WHERE f.featureId = line.FeatureID
MATCH (t:Threat) WHERE t.threatId IN split(line.ThreatIDs, ",")
CREATE (f)-[:VulnerabilityFrom]->(t)

CREATE(p:project{id:1, name:'VSTS'})
MATCH (t:Threat),(p:Project) WHERE (t)-[]->() CREATE (p)-[:RiskOf]->(t)