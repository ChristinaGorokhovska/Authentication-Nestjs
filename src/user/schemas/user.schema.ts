import mongoose from 'mongoose';
import { IUser, role } from '../interfaces/user.interface';

export const UserSchema = new mongoose.Schema<IUser>(
  {
    firstName: { type: String, required: true },
    lastName: { type: String },
    birthDate: { type: Date },
    phone: { type: String },
    email: { type: String, required: true },
    valid: { type: Boolean, default: false, required: true },
    password: { type: String, required: true },
    avatar: { type: String },
    roles: {
      type: [{ type: String }],
      default: [role.user],
      required: true,
    },
    refreshToken: {
      token: { type: String, default: '' },
      modifiedAt: { type: Date, default: Date.now },
    },
  },
  { timestamps: true },
);
