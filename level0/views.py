
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

def list_project(request):
    template = loader.get_template('level0/threats.html')
    projectList = get_projects()
    context = {
        'container': "level0/project-list.html",
        'id': 0,
        'projectList': projectList
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
    query = "MATCH(p: Project)-[r: RiskOf]-(t: Threat) WHERE  p.id = $id"
    query +=" OPTIONAL MATCH(t)-[m: Mitigation]-(c: Control)"
    query +=" RETURN p.name as projectName, t.threat as threat, collect(c) as control"

    result = session.run(query, id=int(id))
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

def connect_db():
    """Connects to the specific database."""
    databaselocation = DATABASES['default']['NAME']
    rv = sqlite3.connect(databaselocation)
    rv.row_factory = sqlite3.Row
    return rv

def add_project(request):
    if request.method == 'GET':
        #TODO: transactional + exception handling
        projectName = request.GET['projectName']

        db = connect_db()  # sqlite
        cur = db.cursor()
        result = cur.execute('INSERT INTO projects (Name) VALUES(?)', [projectName])
        projectId = result.lastrowid
        db.commit()

        query = "MATCH (t:Threat) WHERE t.threatId IN [{0}]".format(request.GET['threatList'])
        query += " CREATE (p:Project{{name: '{0}', id:$id}})".format(projectName)
        query += " CREATE (p)-[:RiskOf]->(t)"

        driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "neon40j"))
        session = driver.session()
        session.run(query, id=int(projectId))

    return HttpResponse('{{"success":true, "projectId": {0}}}'.format(projectId))

def get_projects():
    db = connect_db()
    cur = db.execute('SELECT * FROM projects')
    projects = []
    for record in cur.fetchall():
        projects.append({"id": record['id'], "projectName": record['name']})

    return projects

def delete_project(request, id=0):
    #TODO: For the moment project id cannot be removed as it is a Demo project
    #plus there is no security or restrictions so uploading data would be a pain
    projectId = int(id)
    if projectId != 1:
        #TODO: Transaction again + exception handling
        db = connect_db()
        db.execute('DELETE FROM projects WHERE id =?',[projectId])
        db.commit()

        query = "MATCH (p:Project) WHERE p.id = $id DETACH DELETE p"

        driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "neon40j"))
        session = driver.session()
        session.run(query, id=int(projectId))

    return HttpResponse('{{"deleted":true, "projectId": {0}}}'.format(projectId))




