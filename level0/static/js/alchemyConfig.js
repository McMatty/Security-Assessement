var config = {
  dataSource: 'http://localhost:8000/level0/json_graph',
  cluster: false,
  nodeCaption: "name",
  nodeCaptionsOnByDefault : true,
  rootNodeRadius: 30,
  nodeTypes: {nodeType: ["threat",
                           "control"]},
  nodeStyle: {
        "threat":{
            color: "#66A61E",
            borderColor: "#66A61E"

        },
        "control": {
            color: "lightblue",
            borderColor: "lightblue",
            radius : "6"
        }
    },
  edgeStyle: {
        "threat": {
            color: "#00fffa",
            width: 5
        },
        "control": {
            color: "#ff00f3",
            borderWidth: 10
        }
    }  ,
  clusterColours:  ["#DD79FF", "#00FF30", "#5168FF", "#f83f00", "#ff8d8f"]
};