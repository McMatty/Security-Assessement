
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
    hostList = get_hosts()
    context = {
        'container': "level0/project-content.html",
        'metaContainer': "level0/project-details-add.html",
        'id' : 0,
        'hosts' : hostList        
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
        "jsonAPI" : "/level0/json_model/{0}/".format(id),
    }
    return HttpResponse(template.render(context, request))

def features(request, id=0):
    template = loader.get_template('level0/threats.html')
    context = {
        'container': "level0/assessment-content.html",
        "jsonAPI" : "/level0/get_features_json_model/{0}/".format(id),
    }
    return HttpResponse(template.render(context, request))

def run_graph_query(query, id=0):
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "neon4j"))
    session = driver.session()
    result = session.run(query, id=int(id))
    session.close()

    return result

def get_json_model(request, id=0):   
    query = "MATCH(p: Project)-[r: RiskOf]-(t: Threat) WHERE  p.id = $id"
    query +=" OPTIONAL MATCH(t)-[m: Mitigation]-(c: Control)"
    query +=" RETURN p.name as projectName, t.threat as threat, collect(c) as control"
    result = run_graph_query(query, id=int(id))
  
    db = connect_db() #sqlite

    nodes = []
    for record in result.data():
        projectName = record["projectName"]
        childnodes =[]
        for control in record["control"]:

                cur = db.execute('SELECT description,guidance from controls where id=? ', [control._properties['name']])
                details = cur.fetchone()

                #TODO: Fix data in neo4j so I dont need to lowercase strings
                title = control._properties['title']
                name = title[0] + title[1:].lower()
                control = {"name": name, "description" : details[0], "implementation" : details[1]}
                childnodes.append(control)

        nodes.append({"name": record["threat"], "children" : childnodes})

    return HttpResponse(json.dumps({"children": nodes, "name": projectName}), content_type="application/json")

def get_graphData(fieldName):    
    result = run_graph_query("MATCH(t:{0}) RETURN t as {0}".format(fieldName))   

    nodes = []
    for graphData in result:
        properties = graphData[fieldName]._properties
        threat = {"id": properties['id'],"name": properties['name']}
        nodes.append(threat)

    return nodes

def get_hosts():    
    return get_graphData("host")    

def get_applicationComponent(request):    
    nodes = get_graphData("application_component")
    return HttpResponse(json.dumps(nodes), content_type="application/json")

def get_hostComponent(request):    
    nodes = get_graphData("host_component")
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
        projectName     = request.GET['projectName']
        testPeriod      = request.GET['testPeriod']
        owner           = request.GET['projectOwner']
        contract        = request.GET['projectContact']
        reviewer        = request.GET['reviewer']
        classification  = request.GET['classification']
        repositories    = request.GET['codeRepository']
        endpoints       = request.GET['endPoint']

        db = connect_db()  # sqlite
        cur = db.cursor()
        result = cur.execute('INSERT INTO projects (Name, TestPeriod, Owner, Contact, Reviewer, Classification, Repositories, Endpoints) VALUES(?, ?, ?, ?, ?, ?, ?, ?)', [projectName,testPeriod,owner,contract,reviewer,classification,repositories,endpoints])
        projectId = result.lastrowid
        db.commit()

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
        run_graph_query(query, id=int(projectId))

    return HttpResponse('{{"deleted":true, "projectId": {0}}}'.format(projectId))