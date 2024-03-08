// Define the Score check API URL
const scoreCheckRootUrl = 'http://127.0.0.1:8000/score_checkapi/?vector=';

// Define the KEV check API URL
const kevCheckRootUrl = 'http://127.0.0.1:8000/kev_checkapi/?search_cve=';

// Define the modifier check API URL
const envScoreRootUrl = 'http://127.0.0.1:8000/score_modifierapi/?vectorString=';

// Function to simply check a score
function returnScore(string) {

  let apiUrl = scoreCheckRootUrl.concat(string)

  fetch(apiUrl)
  .then(response => {
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    return response.json();
  })
  .then(data => {
    var node = document.getElementById('score');
    var newNode = document.createElement('p');
    newNode.appendChild(document.createTextNode(data));
    node.appendChild(newNode);
    console.log(data);
  })
  .catch(error => {
    console.error('Error:', error);
  });
  
  };

// Function to check if a CVE is in the KEV
function kevCheck(string) {

  let apiUrl = kevCheckRootUrl.concat(string)

  fetch(apiUrl)
  .then(response => {
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    return response.json();
  })
  .then(data => {
    var node = document.getElementById('kevState');
    var newNode = document.createElement('p');
    newNode.appendChild(document.createTextNode(data));
    node.appendChild(newNode);
    console.log(data);
  })
  .catch(error => {
    console.error('Error:', error);
  });
  
  };

// Function to perform checks and return an environmental score
function envScore(cve, string) {

  let apiUrl = envScoreRootUrl.concat(string, "&cve=", cve)

  fetch(apiUrl)
  .then(response => {
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    return response.json();
  })
  .then(data => {
    var node = document.getElementById('magicNumber');
    var newNode = document.createElement('p');
    newNode.appendChild(document.createTextNode(data));
    node.appendChild(newNode);
    console.log(data);
  })
  .catch(error => {
    console.error('Error:', error);
  });
  
  };
