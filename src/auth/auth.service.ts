import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { IUser } from 'src/user/interfaces/user.interface';
import { IEmailToken } from './interfaces/auth.interface';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2';
import { IEmailInfo } from './interfaces/emailInfo.interface';
import * as nodemailer from 'nodemailer';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('User') private readonly userModel: Model<IUser>,
    @InjectModel('EmailToken')
    private readonly emailTokenModel: Model<IEmailToken>,
    @InjectModel('PasswordToken')
    private readonly passwordTokenModel: Model<IEmailToken>,
  ) {}

  async generateEmailToken(userId: Types.ObjectId) {
    const foundToken = await this.emailTokenModel
      .findOne({ userId: userId })
      .exec();

    if (foundToken)
      throw new HttpException(
        ' A token has already been sent',
        HttpStatus.NOT_MODIFIED,
      );

    const generatedToken = [...Array(128)]
      .map(() => Math.random().toString(36)[2])
      .join('');

    const newEmailToken = new this.emailTokenModel({
      userId: userId,
      token: generatedToken,
    });

    return await newEmailToken.save();
  }

  async sendEmail(
    MAIL_HOST: string,
    MAIL_PORT: number,
    MAIL_SECURE: boolean,
    MAIL_USER: string,
    MAIL_PASS: string,
    emailInfo: IEmailInfo,
  ) {
    const transporter = nodemailer.createTransport({
      host: MAIL_HOST,
      port: MAIL_PORT,
      secure: MAIL_SECURE,
      auth: {
        user: MAIL_USER,
        pass: MAIL_PASS,
      },
    });

    const verificationEmail = await new Promise<boolean>(async function (
      resolve,
      reject,
    ) {
      return transporter.sendMail(emailInfo, async (error, data) => {
        if (error) return reject(false);
        return resolve(true);
      });
    });

    return verificationEmail;
  }

  async sendVerificationEmailMessage(userId: Types.ObjectId, email: string) {
    const foundToken = await this.emailTokenModel
      .findOne({ userId: userId })
      .exec();
    if (!foundToken?.token)
      throw new HttpException(
        'Email token is not found',
        HttpStatus.UNAUTHORIZED,
      );

    const emailInfo = {
      from: 'User NestJS',
      to: email,
      subject: 'Verification',
      text: 'Please, confirm your email',
      html: `<a href=${process.env.HOST_URL}:${process.env.HOST_PORT}/auth/verification/
        ${foundToken.token}>Verify email</a>`,
    };

    return await this.sendEmail(
      process.env.MAIL_HOST,
      Number(process.env.MAIL_PORT),
      Boolean(process.env.MAIL_SECURE),
      process.env.MAIL_USER,
      process.env.MAIL_PASS,
      emailInfo,
    );
  }

  async verifyEmail(token: string) {
    console.log(token);
    const all = await this.emailTokenModel.find({});
    console.log(all);
    const foundToken = await this.emailTokenModel
      .findOne({ token: token })
      .exec();
    if (!foundToken)
      throw new HttpException('Token is not found', HttpStatus.NOT_FOUND);

    const foundUser = await this.userModel
      .findOne({ _id: foundToken.userId })
      .exec();
    if (!foundUser)
      throw new HttpException('User is not found', HttpStatus.NOT_FOUND);

    foundUser.valid = true;
    return await foundUser.save();
  }

  async verifyLogin(authDto: AuthDto) {
    const foundUser = await this.userModel
      .findOne({ email: authDto.email })
      .exec();
    if (!foundUser)
      throw new HttpException('User is not found', HttpStatus.NOT_FOUND);

    if (!foundUser.valid)
      throw new HttpException('Email is not verified', HttpStatus.FORBIDDEN);

    const correctPassword = await argon.verify(
      foundUser.password,
      authDto.password,
    );

    if (!correctPassword)
      throw new HttpException(
        'Password is not correct',
        HttpStatus.UNAUTHORIZED,
      );

    return {
      userId: foundUser._id,
      email: foundUser.email,
      roles: foundUser.roles,
    };
  }

  async logout(userId: Types.ObjectId) {
    const foundUser = await this.userModel.findOne({ _id: userId }).exec();
    if (!foundUser)
      throw new HttpException('User is not found', HttpStatus.NOT_FOUND);

    foundUser.refreshToken.token = null;
    return await foundUser.save();
  }

  async generatePasswordToken(userId: Types.ObjectId) {
    const foundToken = await this.passwordTokenModel
      .findOne({ userId: userId })
      .exec();

    if (foundToken) return;

    const generatedToken = [...Array(128)]
      .map(() => Math.random().toString(36)[2])
      .join('');

    const newPasswordToken = new this.passwordTokenModel({
      userId: userId,
      token: generatedToken,
    });

    return await newPasswordToken.save();
  }

  async sendForgotPasswordMessage(userId: Types.ObjectId, email: string) {
    const foundToken = await this.passwordTokenModel
      .findOne({ userId: userId })
      .exec();
    if (!foundToken?.token)
      throw new HttpException(
        'Password token is not found',
        HttpStatus.UNAUTHORIZED,
      );

    const emailInfo = {
      from: 'User NestJS',
      to: email,
      subject: 'Forgot password',
      text: 'Please, go by link to change password',
      html: `<a href=${process.env.HOST_URL}:${process.env.HOST_PORT}/auth/reseting/password/
      ${foundToken.token}>Reset password</a>`,
    };
    return await this.sendEmail(
      process.env.MAIL_HOST,
      Number(process.env.MAIL_PORT),
      Boolean(process.env.MAIL_SECURE),
      process.env.MAIL_USER,
      process.env.MAIL_PASS,
      emailInfo,
    );
  }

  async getPasswordToken(token: string) {
    const foundToken = await this.passwordTokenModel
      .findOne({ token: token })
      .exec();
    if (!foundToken)
      throw new HttpException('Token is not found', HttpStatus.NOT_FOUND);
    return foundToken;
  }

  async setPassword(userId: Types.ObjectId, password: string) {
    const foundUser = await this.userModel.findOne({ _id: userId }).exec();
    if (!foundUser)
      throw new HttpException('User is not found', HttpStatus.NOT_FOUND);

    foundUser.password = await argon.hash(password);
    return !!(await foundUser.save());
  }

  async comparePasswords(userId: Types.ObjectId, password: string) {
    const foundUser = await this.userModel.findOne({ _id: userId }).exec();
    if (!foundUser)
      throw new HttpException('User is not found', HttpStatus.NOT_FOUND);

    return await argon.verify(foundUser.password, password);
  }
}
