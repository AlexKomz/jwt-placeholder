import express from 'express'
import cors from 'cors'
import morgan from 'morgan'
import jwt from 'jsonwebtoken'

// CONSTANTS

const TOKEN_SECRET_KEY = {
  access: 'HI_IAM_A_SECRET_KEY_NICE_TO_MEET_YOU_ACCESS',
  refresh: 'HI_IAM_A_SECRET_KEY_NICE_TO_MEET_YOU_REFRESH'
}

const TOKEN_EXPIRES_IN = {
  access: '15m',
  refresh: '30m'
}

const ROUTE = {
    test: '/jwt/auth/test',
    login: '/jwt/auth/login',
    refresh: '/jwt/auth/refresh',
}

// HELPERS

function getToken(username, secret, expiresIn) {
  return jwt.sign(
    { username },
    secret,
    { expiresIn }
  )
}

function getResponce(username) {
  const accessToken = getToken(username, TOKEN_SECRET_KEY.access, TOKEN_EXPIRES_IN.access)
  const refreshToken = getToken(username, TOKEN_SECRET_KEY.refresh, TOKEN_EXPIRES_IN.refresh)

  const expiresIn = jwt.decode(accessToken).exp
  const refreshExpiresIn = jwt.decode(refreshToken).exp

  return { accessToken, expiresIn, refreshToken, refreshExpiresIn }
}

function getError(status, detail) {
  return {
    code: `${status}`,
    status,
    detail
  }
}

// EXPRESS

const app = express()
const port = 8080

app.use(cors())
app.use(morgan('tiny'))
app.use(express.json())

app.get(
  ROUTE.test,
  async (req, res) => {
    const accessToken = req.headers.authorization.split(' ')[1]

    if (!accessToken) {
      return res.status(401).json(getError(401, 'No authorization'));
    }

    try {
      jwt.verify(accessToken, TOKEN_SECRET_KEY.access)

      return res.status(200).json('There is an authorization')
    } catch (error) {
      return res.status(401).json(getError(401, error.message))
    }
  }
)

app.post(
  ROUTE.login,
  async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) {
      return res.status(400).json(getError(400, 'username & password are required'));
    }

    const responce = getResponce(username)

    return res.json(responce)
  }
)

app.post(
  ROUTE.refresh,
  (req, res) => {
    const { refreshToken: oldRefreshToken } = req.body

    if (!oldRefreshToken) {
      return res.status(400).json(getError(400, 'refreshToken is required'));
    }

    try {
      const { username } = jwt.verify(oldRefreshToken, TOKEN_SECRET_KEY.refresh)

      const responce = getResponce(username)

      return res.json(responce)
    } catch(error) {
      return res.status(401).json(getError(401, error.message))
    }
  }
)

app.listen(port, () => {
    console.log(`jwt-placeholder listening on localhost:${port}`)
})
