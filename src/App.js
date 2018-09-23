import React, { Component } from 'react'
import './App.css'
import CssBaseline from '@material-ui/core/CssBaseline'
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
    ['encrypt', 'decrypt']
  )

class App extends Component {
  state = {
    password: 'mock-password',
    salt1: '1234567890',
    salt2: '0987654321',
    kdk: null,
    rkdk: null,
    auth: null,
    rauth: null,
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

  generateKDK = () => {
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
        ]).then(result => {
          const auth = result[0]
          const kdk = result[1]
          this.setState({ kdk, auth }, this.stringifyKDK)
        })
      )
      .catch(err => {
        console.log('Error - ', err)
      })
  }

  stringifyKDK = () => {
    const { kdk, auth } = this.state
    Promise.all([
      window.crypto.subtle.exportKey('raw', kdk),
      window.crypto.subtle.exportKey('raw', auth),
    ]).then(result => {
      const decoder = new TextDecoder()
      const rawKdk = result[0]
      const rawAuth = result[1]
      const strKdk = btoa(encodeURIComponent(decoder.decode(rawKdk)))
      const strAuth = btoa(
        encodeURIComponent(decoder.decode(rawAuth))
      )
      console.log(strKdk, strAuth)
    })
  }

  render() {
    return (
      <div className="App">
        <CssBaseline />
        <h1 className="App-title">
          Zero-Knowledge stuff & WebCrypto API Experiments
        </h1>
        <TextField
          className="password-input"
          label="Password"
          value={this.state.password}
          onChange={this.handlePasswordChange}
          margin="normal"
        />
        <Button
          className="button"
          variant="contained"
          color="primary"
          onClick={this.generateKDK}
        >
          Go
        </Button>
      </div>
    )
  }
}

export default App
