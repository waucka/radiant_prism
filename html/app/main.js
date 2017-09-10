var React = require('react');
var ReactDOM = require('react-dom');
var hmacSha256 = require("crypto-js/hmac-sha256");
var encBase64 = require("crypto-js/enc-base64");

import 'whatwg-fetch';
import { RingLoader } from 'react-spinners';
import { Col, Modal } from 'react-bootstrap';

function after(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function getAPIKeyInfo() {
  var storageItem = localStorage.getItem("apikey");
  if (storageItem != null && storageItem != undefined) {
    var keyMap = JSON.parse(storageItem);
    return {
      api_key_id: keyMap['api_key_id'],
      api_key: encBase64.parse(keyMap['api_key'])
    };
  }
  return null;
}

function logOut() {
  localStorage.removeItem("apikey");
  window.location.href = "/webui";
}

function makeAPIRequest(method, path, content_type, body) {
  var apiKeyInfo = getAPIKeyInfo();
  if (apiKeyInfo == null) {
    console.log("Not logged in?")
    return null;
  }
  var sig = encBase64.stringify(hmacSha256(body, apiKeyInfo.api_key))
  return fetch(path, {
    method: method,
    headers: {
      'Prism-Api-Key-Id': apiKeyInfo.api_key_id,
      'Request-Signature': sig,
      'Content-Type': content_type
    },
    body: body
  });
}

class ProvisionComponent extends React.Component {
  constructor(props) {
    super(props);
    this.state = {clientName: '', loading: false, loaded: false, results: ""};

    this.handleChange = this.handleChange.bind(this);
    this.handleSubmit = this.handleSubmit.bind(this);
    this.closeResults = this.closeResults.bind(this);
  }

  handleChange(event) {
    this.setState({clientName: event.target.value});
  }

  handleSubmit(event) {
    event.preventDefault();
    console.log(this.state.clientName);
    this.setState({clientName: '', loading: true, loaded: false});
    var provisionReq = {
      unix_time: Math.floor((new Date()).getTime() / 1000),
      client_name: this.state.clientName,
      key_type: 'ecdsa',
      key_details: {
        curve: 'p256'
      }
    };
    var req = makeAPIRequest('PUT', '/v1/provision', 'application/json', JSON.stringify(provisionReq));
    var parent = this;
    after(2000).then(function() {
      req.then(function(response){
        parent.setState({loading: false});
        if (response.status != 200 && response.status != 204) {
          return null;
        }
        return response.json();
      }).then(function(resp) {
        if (resp != null) {
          //console.log(resp.certificate);
          //console.log(resp.key);
          parent.setState({loaded: true, results: resp.certificate + "\n" + resp.key});
        }
      });
    });
  }

  closeResults() {
    this.setState({loaded: false, results: ""});
  }

  render() {
    return (
      <div>
      <form onSubmit={this.handleSubmit}>
      <Col md={4}>
      <label>Client Name
      <input type="text" value={this.state.clientName} onChange={this.handleChange} />
      </label>
      <input type="submit" disabled={!this.state.clientName} value="Provision" />
      </Col>
      <TaskModal show={this.state.loading} title="Provisioning client..." />
      <PreResultModal show={this.state.loaded} title="Provisioned client!" description="Copy the following certificate and key to the client:" content={this.state.results} onHide={this.closeResults} />
      </form>
      </div>
    );
  }
}

class LogOutButton extends React.Component {
  render() {
    return <button onClick={logOut}>Log Out</button>;
  }
}

class TaskModal extends React.Component {
  constructor(props) {
    super(props);
  }

  render() {
    return (
      <Modal show={this.props.show}>
      <Modal.Header>
      <Modal.Title>{this.props.title}</Modal.Title>
      </Modal.Header>
      <Modal.Body>
      <div className="center-align-outer">
      <div className="center-align-inner">
      <RingLoader color={'#123abc'} loading={true} size={80} />
      </div>
      </div>
      </Modal.Body>
      </Modal>
    );
  }
}

class PreResultModal extends React.Component {
  constructor(props) {
    super(props);
  }

  render() {
    return (
      <Modal show={this.props.show} onHide={this.props.onHide}>
      <Modal.Header closeButton>
      <Modal.Title>{this.props.title}</Modal.Title>
      </Modal.Header>
      <Modal.Body>
      <p>{this.props.description}</p>
      <pre>
      {this.props.content}
      </pre>
      </Modal.Body>
      </Modal>
    );
  }
}

class Content extends React.Component {
  render() {
    var apiKeyInfo = getAPIKeyInfo();
    if (apiKeyInfo != null) {
      return (
        <div>
        <ProvisionComponent />
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
