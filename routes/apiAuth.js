'use strict';

const crypto = require('crypto');
const express = require('express');

const KEYS = require('../lib/redisKeys');
const { hashIp } = require('../lib/ip');
const { createAuthToken, validateAuthToken } = require('../auth');
const createTokenBucket = require('../utils/tokenBucket');
const { normalizeUsername, isValidUsername } = require('../lib/validation');
const { ensureStoredUsername } = require('../lib/usernames');
const { getAuthTokenFromRequest, setAuthCookie } = require('../lib/authCookie');

const AUTH_TTL_SEC = 24 * 60 * 60;

function createAuthCookieOptions(httpsEnabled) {
  return {
    maxAge: AUTH_TTL_SEC,
    sameSite: 'lax',
    secure: httpsEnabled === true,
  };
}

function createApiAuthRouter({ redisClient, httpsEnabled = false }) {
  const router = express.Router();
  const tokenBucket = createTokenBucket(redisClient);

  router.post('/auth', async (req, res) => {
    try {
      const providedUsername = normalizeUsername(req.body?.username);
      if (providedUsername && !isValidUsername(providedUsername)) {
        return res.status(400).json({ error: 'Username too long', code: 'invalid_username' });
      }

      const incomingToken = getAuthTokenFromRequest(req);
      const existingClientId = incomingToken ? await validateAuthToken(redisClient, incomingToken) : null;

      let clientId = existingClientId;
      let token = incomingToken;
      let username = providedUsername || '';

      if (clientId) {
        const usernameKey = KEYS.username(clientId);
        const storedUsername = await ensureStoredUsername(redisClient, usernameKey, AUTH_TTL_SEC);
        username = username || storedUsername;

        if (storedUsername !== username) {
          await redisClient.set(usernameKey, username, 'EX', AUTH_TTL_SEC);
        }

        setAuthCookie(res, token, createAuthCookieOptions(httpsEnabled));
        return res.json({ ok: true, username });
      }

      const ip = typeof req.ip === 'string' && req.ip ? req.ip : '0.0.0.0';
      const rateKey = KEYS.tokenBucketAuthIp(hashIp(ip));

      const result = await tokenBucket.allow(rateKey, {
        capacity: 3,
        refillPerSec: 3 / AUTH_TTL_SEC,
      });

      if (!result.allowed) {
        return res.sendStatus(429);
      }

      username = username || `guest-${crypto.randomBytes(3).toString('hex')}`;
      clientId = crypto.randomUUID();
      token = createAuthToken();

      const tx = redisClient.multi();
      tx.set(KEYS.token(token), clientId, 'EX', AUTH_TTL_SEC);
      tx.set(KEYS.username(clientId), username, 'EX', AUTH_TTL_SEC);

      const resultSet = await tx.exec();
      if (!Array.isArray(resultSet) || resultSet.some(([err]) => err)) {
        throw new Error('Failed to persist auth session');
      }

      setAuthCookie(res, token, createAuthCookieOptions(httpsEnabled));
      return res.json({ ok: true, username });
    } catch (err) {
      console.error('auth route failed', err);
      return res.status(500).json({ error: 'Server error', code: 'server_error' });
    }
  });

  return router;
}

module.exports = createApiAuthRouter;
