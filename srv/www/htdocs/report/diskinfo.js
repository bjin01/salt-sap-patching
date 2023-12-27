async function getJSON() {
    const response = await fetch('/report/diskinfo.json');
    return response.json();
}


function creatTable(data) {
    console.log("type of data is: " + data.constructor.name);
    //var table = document.querySelector("#mytable");
    // read from json first row as table header
    var mydiv = document.getElementById("myDiv");

    var table = document.createElement("table");
    table.className = "table table-bordered table-hover";
    table.setAttribute("id", "myTable")
    var header = table.createTHead();
    var row = header.insertRow(0);
    //row.classList.add("table-success");
    row.className = "table-success";
    
    for (var key in data[0]) {
        /* var cell = row.insertCell(-1);
        cell.setAttribute("scope", "col");
        cell.innerHTML = key; */
        var headerCell = document.createElement("TH");
        headerCell.setAttribute("scope", "col");
        headerCell.innerHTML = key;
        row.appendChild(headerCell);
    }
    // read from json data
    var tbody = table.createTBody();
    for (var i = 0; i < data.length; i++) {
        var row = tbody.insertRow(-1);
        for (var key in data[i]) {
            
            var cell = row.insertCell(-1);
            if (key === "host") {
                cell.className = "table-primary";
                cell.setAttribute("scope", "row");
            }
            //console.log("key: " + key + " value: " + data[i][key])
            cell.setAttribute("data-bs-toggle", "tooltip")
            cell.setAttribute("data-bs-placement", "bottom")
            cell.title = key
            if (data[i][key] == "n/a") {
                cell.innerHTML = "";
            } else {
              cell.innerHTML = data[i][key];
            }
            
        }
    }
    
    mydiv.appendChild(table);
    document.body.appendChild(mydiv);
};

let myhtml = document.addEventListener("DOMContentLoaded", function(event) {
    event.defaultPrevented;
    console.log("DOM fully loaded and parsed");
    getJSON().then((mydata) => {
        console.log("type of mydata is: " + mydata.constructor.name);
        console.log(mydata);
        creatTable(mydata);
    });
});

function myFunction() {
    var input, filter, table, tr, td, i, txtValue;
    input = document.getElementById("myInput");
    filter = input.value.toUpperCase();
    table = document.getElementById("myTable");
    tr = table.getElementsByTagName("tr");
    for (i = 0; i < tr.length; i++) {
      td = tr[i].getElementsByTagName("td")[0];
      if (td) {
        txtValue = td.textContent || td.innerText;
        if (txtValue.toUpperCase().indexOf(filter) > -1) {
          tr[i].style.display = "";
        } else {
          tr[i].style.display = "none";
        }
      }       
    }
  }