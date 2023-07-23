import { Types } from 'mongoose';

export enum role {
  admin = 'admin',
  user = 'user',
}

export interface IUser {
  _id: Types.ObjectId;
  firstName: string;
  lastName: string;
  birthDate: Date;
  phone: string;
  email: string;
  valid: boolean;
  password: string;
  avatar: string;
  roles: role[];
  refreshToken: {
    token: string;
    modifiedAt: Date;
  };
}
