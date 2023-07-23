import { ObjectId, Types } from 'mongoose';

export interface IEmailToken {
  _id: Types.ObjectId;
  userId: ObjectId;
  token: string;
  createdAt: Date;
}
