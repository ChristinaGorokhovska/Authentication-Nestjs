import mongoose from 'mongoose';
import { IEmailToken } from '../interfaces/auth.interface';

export const EmailTokenSchema = new mongoose.Schema<IEmailToken>({
  userId: { type: mongoose.Types.ObjectId, required: true, ref: 'User' },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now(), expires: '300' },
});
