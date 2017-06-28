import os

from django.http import HttpResponse
from neo4j.v1 import GraphDatabase, basic_auth
from django.template import loader
from sqlite3 import dbapi2 as sqlite3
import json

from Assessement.settings import DATABASES


def index(request):
    return HttpResponse()

def threats(request):
    template = loader.get_template('level0/threats.html')

    return HttpResponse(template.render())

def graph(request):
    template = loader.get_template('level0/graph.html')
    db = connect_db()
    return HttpResponse(template.render())

def get_json_model(request):
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "neon40j"))
    session = driver.session()
    result = session.run("MATCH(t:Threat)-[m:Mitigation]-(c:Control) RETURN t.threat as threat, collect(c) as control")
    session.close()
    db = connect_db()

    nodes = []
    for record in result.data():
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

    return HttpResponse(json.dumps({"children": nodes, "name": "VSTS" }), content_type="application/json")

def get_json_graph(request):
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "neon40j"))
    session = driver.session()
    result = session.run("MATCH(t:Threat)-[m:Mitigation]-(c:Control) RETURN t.threat as threat, collect(c.title) as control")
    session.close()

    nodes =[]
    rels = []
    id = 0
    for record in result:
        id+=1
        source = id;
        nodes.append({"id": source, "name": record["threat"], "nodeType" : "threat", "cluster": 1})

        for title in record["control"]:
            #This function isn't working correctly and adding each time
            if not (contains(nodes, lambda x: x["name"] == title)):
                id+=1
                control = {"id": id, "name" : title, "nodeType" : "control", "cluster" : 2}
                nodes.append(control)
                rels.append({"source": source, "target": id})


    return HttpResponse(json.dumps({"nodes" : nodes, "edges" : rels}), content_type="application/json")

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