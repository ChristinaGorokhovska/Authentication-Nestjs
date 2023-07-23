import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { NewUserDto } from './dto/newUser.dto';
import { IUser } from './interfaces/user.interface';
import { Model, Types } from 'mongoose';
import * as argon from 'argon2';
import { ProfileDto } from './dto/profile.dto';

@Injectable()
export class UserService {
  constructor(@InjectModel('User') private readonly userModel: Model<IUser>) {}

  async createUser(credentials: NewUserDto) {
    const foundUser = await this.userModel
      .findOne({ email: credentials.email })
      .exec();
    if (foundUser)
      throw new HttpException(
        `Such email ${credentials.email} exists`,
        HttpStatus.FORBIDDEN,
      );

    credentials.password = await argon.hash(credentials.password);
    const newUser = new this.userModel(credentials);
    return await newUser.save();
  }

  async updateProfile(userId: Types.ObjectId, profileDto: ProfileDto) {
    const foundUser = await this.userModel.findOne({ _id: userId }).exec();
    if (!foundUser)
      throw new HttpException('User is not found', HttpStatus.NOT_FOUND);

    if (profileDto.firstName) foundUser.firstName = profileDto.firstName;
    if (profileDto.lastName) foundUser.lastName = profileDto.lastName;
    if (profileDto.birthDate) foundUser.birthDate = profileDto.birthDate;
    if (profileDto.phone) foundUser.phone = profileDto.phone;

    return await foundUser.save();
  }

  async uploadAvatar(userId: Types.ObjectId, fileUrl: string) {
    const foundUser = await this.userModel.findOne({ _id: userId }).exec();
    if (!foundUser)
      throw new HttpException('User is not found', HttpStatus.NOT_FOUND);

    foundUser.avatar = `${process.env.ROOT_IMAGE}/${fileUrl}`;
    await foundUser.save();
    return foundUser;
  }
}
