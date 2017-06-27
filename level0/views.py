from django.http import HttpResponse
from neo4j.v1 import GraphDatabase, basic_auth
from django.template import loader
import json

def index(request):
    return HttpResponse()

def threats(request):
    template = loader.get_template('level0/threats.html')

    return HttpResponse(template.render())

def graph(request):
    template = loader.get_template('level0/graph.html')

    return HttpResponse(template.render())

def get_json_model(request):
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "neon40j"))
    session = driver.session()
    result = session.run("MATCH(t:Threat)-[m:Mitigation]-(c:Control) RETURN t.threat as threat, collect(c.title) as control")
    session.close()

    nodes = []
    for record in result:
        childnodes =[]
        for title in record["control"]:
                #TODO: Fix data in neo4j so I dont need to lowercase strings
                name = title[0] + title[1:].lower()
                control = {"name": name, "description" : "Control fixes all!", "implementation" : "Implement all the things!"}
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
