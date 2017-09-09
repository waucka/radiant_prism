var React = require('react');
var ReactDOM = require('react-dom');
var hmacSha256 = require("crypto-js/hmac-sha256");
var encBase64 = require("crypto-js/enc-base64");
var fetch = require("whatwg-fetch");

function getAPIKey() {
    var storageItem = localStorage.getItem("apikey");
    if (storageItem != null && storageItem != undefined) {
        var keyMap = JSON.parse(storageItem);
        return encBase64.parse(keyMap['api_key']);
    }
    return null;
}

function logOut() {
    localStorage.removeItem("apikey");
    window.location.href = "/webui";
}

function makeAPIRequest(apikey, method, path, content_type, body) {
    var sig = encBase64.stringify(hmacSha256(body, apikey))
    return fetch(path, {
	method: method,
	headers: {
	    'Content-Type': content_type
	},
	body: body
    });
}

class LogOutButton extends React.Component {
  render() {
      return <button onClick={logOut}>Log Out</button>;
  }
}

class Content extends React.Component {
    render() {
        var apiKey = getAPIKey();
        if (apiKey != null) {
            return (
                    <div>
		    <LogOutButton />
                    </div>
            );
        } else {
            return (
                    <div>
		    <a href="/v1/authenticate">Log in via Google</a>
                    </div>
            );
        }
    }
}

ReactDOM.render(<Content />, document.getElementById('content'));
