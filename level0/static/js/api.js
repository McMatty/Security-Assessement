$(function(){
    $('.threat-list li').click(function(e) {
        e.preventDefault()
        
        $that = $(this);
        
        if($that.hasClass('threat')) {
            $that.removeClass('threat');
            $that.addClass('active-threat');
        }
        else
        {
            $that.removeClass('active-threat');
            $that.addClass('threat');
        }
    });
})

function deleteProject(projectId){
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {       
        location.reload()
    }
    };
    xhttp.open("GET", "/level0/threats/delete/" + projectId, true);
    xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhttp.send(); 
}

function generatePostData(){
    let elements = document.getElementById("project-metadata").getElementsByTagName("input")
    let postData = null
    for(let element of elements)
    {
       if(postData == null){
           postData = element.id.concat("=").concat(element.value)
       }
       else
       {
        postData = postData.concat("&").concat(element.id.concat("=").concat(element.value))
       }
    }     

    return postData;
}

function generateFeaturesPostData(threatList){
    postData="projectID=" + document.getElementById('project').value
    
    if(threatList && threatList.length > 0)
    {
        postData+="&threatList="
        threatList.forEach(function(item, index){
            postData+= "'" + item.id + "'";
            if(index < threatList.length - 1)                {
                postData+= ","
            }
        });
    }

    return postData;
}

function postProjectData(){    
        var data = generatePostData();
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {       
            var responseObj = JSON.parse(this.response)
            if(responseObj.success === true)
            {
                window.location.href ='/level0/threats/' + responseObj.projectId
            }
        }
        };
        xhttp.open("GET", "/level0/threats/add?" + data, true);
        xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        xhttp.send(); 
}

function postProjectFeatures(){
    //Need to do a modal loading icon on screen to prevent reclicking
    var threatList = Array.from(document.getElementsByClassName("active-threat"))
    if (threatList && threatList.length > 0 && document.getElementById('project').value.length > 0){
        var data = generateFeaturesPostData(threatList);
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {       
            var responseObj = JSON.parse(this.response)
            if(responseObj.success === true)
            {
                window.location.href ='/level0/features/' + responseObj.projectId
            }
        }
        };
        xhttp.open("GET", "/level0/features/add?" + data, true);
        xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
        xhttp.send(); 
    }
    else
    {
        alert('Fill the fields out (TODO: Nice modal message telling user they are dumb)')
    }
}