var React = require('react');
var ReactDOM = require('react-dom');
var hmacSha256 = require("crypto-js/hmac-sha256");
var encBase64 = require("crypto-js/enc-base64");
var fetch = require("whatwg-fetch");

function getAPIKey() {
    return encBase64.parse(localstorage.getItem("apikey"));
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

var Content = React.createClass({
    render: function() {
        return (
        <div>
		<b>Congratulations</b>, {doit()}
        </div>
        );
    }
});
ReactDOM.render(<Content />, document.getElementById('content'));
