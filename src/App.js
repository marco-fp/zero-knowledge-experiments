import React, { Component } from 'react'
import './App.css'
import Button from '@material-ui/core/Button'
import TextField from '@material-ui/core/TextField'

const deriveKey = (key, salt, iterations = 10000) =>
  window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    key,
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt', 'unwrapKey', 'wrapKey']
  )

const generateAES256Key = () =>
  window.crypto.subtle.generateKey(
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt', 'unwrapKey', 'wrapKey']
  )

const keyToStr = key => {
  const decoder = new TextDecoder()
  return btoa(encodeURIComponent(decoder.decode(key)))
}
class App extends Component {
  state = {
    password: 'mock-password',
    salt1: '1234567890',
    salt2: '0987654321',
    kdk: null,
    auth: null,
    kek: null,
    rkek: null,
    dek: null,
    strKdk: null,
    strkAuth: null,
    entity: {
      name: 'Elon Musquito',
      company: 'SpatialZ',
      powerLevel: 9001,
    },
  }

  handlePasswordChange = ev => {
    this.setState({ password: ev.target.value })
  }

  generateInitialKeys = () => {
    const encoder = new TextEncoder()
    const { salt1, salt2, password } = this.state
    const authSalt = encoder.encode(salt1).buffer
    const kdkSalt = encoder.encode(salt2).buffer
    const passwordKey = encoder.encode(password).buffer

    window.crypto.subtle
      .importKey('raw', passwordKey, { name: 'PBKDF2' }, false, [
        'deriveBits',
        'deriveKey',
      ])
      .then(key =>
        Promise.all([
          deriveKey(key, authSalt),
          deriveKey(key, kdkSalt),
          generateAES256Key(),
        ]).then(result => {
          const auth = result[0]
          const kdk = result[1]
          const kek = result[2]
          this.setState({ kdk, auth, kek }, this.encryptKekWithKdk)
        })
      )
      .catch(err => {
        console.log('Error - ', err)
      })
  }

  stringifyInitialKeys = () => {
    const { kdk, auth, kek, encKek } = this.state
    Promise.all([
      window.crypto.subtle.exportKey('raw', kdk),
      window.crypto.subtle.exportKey('raw', auth),
      window.crypto.subtle.exportKey('raw', kek),
    ]).then(result => {
      const rawKdk = result[0]
      const rawAuth = result[1]
      const rawKek = result[2]
      const strKdk = keyToStr(rawKdk)
      const strAuth = keyToStr(rawAuth)
      const strKek = keyToStr(rawKek)
      const strEncKek = keyToStr(encKek)
      this.setState({
        strKdk,
        strAuth,
        strKek,
        strEncKek,
      })
    })
  }

  encryptKekWithKdk = () => {
    const { kdk, kek } = this.state
    return crypto.subtle
      .wrapKey('raw', kek, kdk, {
        name: 'AES-CBC',
        iv: new ArrayBuffer(16),
      })
      .then(encKek => {
        this.setState({ encKek }, this.stringifyInitialKeys)
      })
      .catch(err => {
        console.log('Error - ', err)
      })
  }

  render() {
    const {
      password,
      strAuth,
      strKdk,
      strKek,
      strEncKek,
    } = this.state
    return (
      <div className="App">
        <h1 className="App-title">
          Zero-Knowledge stuff & WebCrypto API Experiments
        </h1>
        <div className="generate-kdk-auth">
          <div className="password-input-wrapper">
            <TextField
              className="password-input"
              label="Password"
              value={password}
              onChange={this.handlePasswordChange}
              margin="normal"
            />
            <Button
              className="button"
              variant="contained"
              color="primary"
              onClick={this.generateInitialKeys}
            >
              Go
            </Button>
          </div>

          <div className="display-kdk-auth">
            <div className="key-display">
              <b>KDK: </b>
              {strKdk && <span className="key-text">{strKdk}</span>}
            </div>

            <div className="key-display">
              <b>Auth: </b>
              {strAuth && <span className="key-text">{strAuth}</span>}
            </div>

            <div className="key-display">
              <b>Kek: </b>
              {strKek && <span className="key-text">{strKek}</span>}
            </div>

            <div className="key-display">
              <b>Encrypted Kek (with Kdk): </b>
              {strEncKek && (
                <span className="key-text">{strEncKek}</span>
              )}
            </div>
          </div>
        </div>
      </div>
    )
  }
}

export default App
