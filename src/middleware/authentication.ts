import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { ERROR_MESSAGES } from "../constants/messages";
import { redisClient } from '../utils/redis';

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET!;

export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
    return;
  }

  try {
    const isBlacklisted = await redisClient.get(`blacklist_${token}`);
    if (isBlacklisted) {
      res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
      return;
    }


    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET) as {
      id: string;
    };
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
    return;
  }
};
