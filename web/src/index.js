function component() {
    const element = document.createElement('div');
    const CryptoJS = require('crypto-js');
    const hash = CryptoJS.SHA1('hunter2');

    // Lodash, currently included via a script, is required for this line to work
    element.innerHTML = 'Hello, hash=' + hash

    return element;
}

document.body.appendChild(component());
