import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { IUser } from 'src/user/interfaces/user.interface';
import * as argon from 'argon2';

@Injectable()
export class JwtTokenService {
  constructor(
    @InjectModel('User') private readonly userModel: Model<IUser>,
    private jwtService: JwtService,
  ) {}

  async generateTokens(userId: Types.ObjectId, email: string, roles: string[]) {
    const accessToken = await this.jwtService.signAsync(
      {
        sub: userId,
        email: email,
        roles: roles,
      },
      { secret: process.env.ACCESS_TOKEN_SECRET, expiresIn: '10m' },
    );

    const refreshToken = await this.jwtService.signAsync(
      {
        sub: userId,
        email: email,
        roles: roles,
      },
      { secret: process.env.REFRESH_TOKEN_SECRET, expiresIn: '20d' },
    );

    return { accessToken, refreshToken };
  }

  async updateRefreshToken(userId: Types.ObjectId, newToken: string) {
    const hashedToken = await argon.hash(newToken);
    await this.userModel.findOneAndUpdate(
      { _id: userId },
      { refreshToken: { token: hashedToken } },
    );
  }

  async refreshTokens(userId: Types.ObjectId, token: string) {
    const foundUser = await this.userModel.findOne({ _id: userId }).exec();
    if (!foundUser || !foundUser.refreshToken.token)
      throw new HttpException(
        'User or token are not found',
        HttpStatus.FORBIDDEN,
      );

    const correctToken = await argon.verify(
      foundUser.refreshToken.token,
      token,
    );
    if (!correctToken)
      throw new HttpException('Incorrect token', HttpStatus.FORBIDDEN);

    const generatedTokens = await this.generateTokens(
      foundUser.id,
      foundUser.email,
      foundUser.roles,
    );
    await this.updateRefreshToken(foundUser._id, generatedTokens.refreshToken);

    return generatedTokens;
  }
}
