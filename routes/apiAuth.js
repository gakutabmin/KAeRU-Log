'use strict';

const crypto = require('crypto');
const express = require('express');

const KEYS = require('../lib/redisKeys');
const { shortSha256Hex } = require('../lib/hash');
const { createAuthToken, validateAuthToken } = require('../auth');
const createTokenBucket = require('../utils/tokenBucket');
const { normalizeUsername, isValidUsername } = require('../lib/validation');
const { getAuthTokenFromRequest, setAuthCookie } = require('../lib/authCookie');

const AUTH_TTL_SEC = 24 * 60 * 60;

function isCrossOriginCookieRequest(req, frontendUrl) {
  if (typeof frontendUrl !== 'string' || frontendUrl.trim() === '') {
    return false;
  }

  const requestOrigin = typeof req?.headers?.origin === 'string' ? req.headers.origin.trim() : '';
  if (!requestOrigin) {
    return false;
  }

  try {
    return new URL(requestOrigin).origin !== new URL(frontendUrl).origin;
  } catch {
    return false;
  }
}

function createAuthCookieOptions(req, frontendUrl) {
  const crossOrigin = isCrossOriginCookieRequest(req, frontendUrl);

  return {
    maxAge: AUTH_TTL_SEC,
    sameSite: crossOrigin ? 'none' : 'lax',
    secure: crossOrigin || Boolean(req?.secure),
  };
}

function createApiAuthRouter({ redisClient, frontendUrl }) {
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
        username = username || (await redisClient.get(KEYS.username(clientId))) || '';

        if (!username) {
          username = `guest-${crypto.randomBytes(3).toString('hex')}`;
        }

        const currentUsername = await redisClient.get(KEYS.username(clientId));
        if (normalizeUsername(currentUsername) !== username) {
          await redisClient.set(KEYS.username(clientId), username, 'EX', AUTH_TTL_SEC);
        }

        setAuthCookie(res, token, createAuthCookieOptions(req, frontendUrl));
        return res.json({ ok: true, username });
      }

      const ip = typeof req.ip === 'string' && req.ip ? req.ip : '0.0.0.0';
      const rateKey = KEYS.tokenBucketAuthIp(shortSha256Hex(ip, 16));

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

      setAuthCookie(res, token, createAuthCookieOptions(req, frontendUrl));
      return res.json({ ok: true, username });
    } catch (err) {
      console.error('auth route failed', err);
      return res.status(500).json({ error: 'Server error', code: 'server_error' });
    }
  });

  return router;
}

module.exports = createApiAuthRouter;
