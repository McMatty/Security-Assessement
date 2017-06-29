
from django.http import HttpResponse
from neo4j.v1 import GraphDatabase, basic_auth
from django.template import loader
from sqlite3 import dbapi2 as sqlite3
import json

from Assessement.settings import DATABASES

def index(request):
    return HttpResponse()

def new_project(request):
    template = loader.get_template('level0/threats.html')
    threatList = get_threats()
    context = {
        'container': "level0/project-content.html",
        'id' : 0,
        'threats' : threatList
    }
    return HttpResponse(template.render(context, request))

def threats(request, id=0):
    template = loader.get_template('level0/threats.html')
    context = {
        'container': "level0/assessment-content.html",
        'id': id,
    }
    return HttpResponse(template.render(context, request))

def get_json_model(request, id=0):
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "neon40j"))
    session = driver.session()
    result = session.run("MATCH (p:project)-[r:RiskOf]-(t:Threat)-[m:Mitigation]-(c:Control) WHERE p.id = $id RETURN p.name as projectName, t.threat as threat, collect(c) as control", id=int(id))
    session.close()
    db = connect_db() #sqlite

    nodes = []
    for record in result.data():
        projectName = record["projectName"]
        childnodes =[]
        for control in record["control"]:

                cur = db.execute('SELECT description,guidance from controls where id=? ', [control.properties['name']])
                details = cur.fetchone()

                #TODO: Fix data in neo4j so I dont need to lowercase strings
                title = control.properties['title']
                name = title[0] + title[1:].lower()
                control = {"name": name, "description" : details[0], "implementation" : details[1]}
                childnodes.append(control)

        nodes.append({"name": record["threat"], "children" : childnodes})

    return HttpResponse(json.dumps({"children": nodes, "name": projectName}), content_type="application/json")

def get_threats():
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "neon40j"))
    session = driver.session()
    result = session.run("MATCH(t:Threat) WHERE EXISTS(t.threat) RETURN t as threat")
    session.close()

    nodes = []
    for threatData in result.data():
        properties = threatData['threat'].properties
        threat = {"id": properties['threatId'],"name": properties['threat']}
        nodes.append(threat)
    return nodes

def get_json_threats(request):
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "neon40j"))
    session = driver.session()
    result = session.run("MATCH(t:Threat) WHERE EXISTS(t.threat) RETURN t as threat")
    session.close()

    nodes = []
    for threatData in result.data():
        properties = threatData['threat'].properties
        threat = {"id": properties['threatId'],"name": properties['threat']}
        nodes.append(threat)

    return HttpResponse(json.dumps(nodes), content_type="application/json")

def contains (list, filter):
    for x in list:
        if filter(x):
            return True;
        return False;

def connect_db():
    """Connects to the specific database."""
    databaselocation = DATABASES['default']['NAME']
    rv = sqlite3.connect(databaselocation)
    rv.row_factory = sqlite3.Row
    return rv