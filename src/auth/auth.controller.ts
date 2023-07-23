import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Param,
  Post,
  Put,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { NewUserDto } from 'src/user/dto/newUser.dto';
import { UserService } from 'src/user/user.service';
import { AuthDto } from './dto/auth.dto';
import { JwtTokenService } from './jwt.service';
import { Request, Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { PasswordDto } from './dto/password.dto';
import { Types } from 'mongoose';
import { Roles } from './decorators/roles.decorator';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UserService,
    private readonly jwtTokenService: JwtTokenService,
  ) {}

  @Post('/signup')
  async signup(@Body() newUserDto: NewUserDto) {
    try {
      const newUser = await this.userService.createUser(newUserDto);
      await this.authService.generateEmailToken(newUser._id);

      const sent = await this.authService.sendVerificationEmailMessage(
        newUser._id,
        newUser.email,
      );

      if (!sent)
        return new HttpException(
          'Email is not sent',
          HttpStatus.INTERNAL_SERVER_ERROR,
        );

      return { message: 'Email is sent' };
    } catch (error) {
      return new HttpException(
        `Error: ${error}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('/signin')
  @HttpCode(HttpStatus.OK)
  async signin(
    @Body() authDto: AuthDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      const verifiedUser = await this.authService.verifyLogin(authDto);

      const tokens = await this.jwtTokenService.generateTokens(
        verifiedUser.userId,
        verifiedUser.email,
        verifiedUser.roles,
      );

      await this.jwtTokenService.updateRefreshToken(
        verifiedUser.userId,
        tokens.refreshToken,
      );

      return { tokens, user: verifiedUser.userId };
    } catch (error) {
      return new HttpException(
        `Error: ${error}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('/verification/:token')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Param() params) {
    try {
      await this.authService.verifyEmail(params.token);
      return new HttpException('User is verified', HttpStatus.OK);
    } catch (error) {
      return new HttpException(
        `Error: ${error}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('/re-verification/:email/:userId')
  @HttpCode(HttpStatus.OK)
  async generateVerificationProcess(@Param() params) {
    try {
      await this.authService.generateEmailToken(params.userId);
      const verificationEmail =
        await this.authService.sendVerificationEmailMessage(
          params.userId,
          params.email,
        );

      if (!verificationEmail)
        return new HttpException(
          'Verification Letter is not sent',
          HttpStatus.INTERNAL_SERVER_ERROR,
        );
    } catch (error) {
      return new HttpException(
        `Error: ${error}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Put('/password/reset')
  async resetPassword(@Body() passwordDto: PasswordDto) {
    try {
      let passwordChanged = false;
      if (passwordDto.userId && passwordDto.currentPassword) {
        const validPassword = await this.authService.comparePasswords(
          passwordDto.userId,
          passwordDto.currentPassword,
        );
        if (!validPassword)
          return new HttpException(
            'Current password is not correct',
            HttpStatus.UNAUTHORIZED,
          );
        passwordChanged = await this.authService.setPassword(
          passwordDto.userId,
          passwordDto.newPassword,
        );
      } else if (passwordDto.token) {
        const foundToken = await this.authService.getPasswordToken(
          passwordDto.token,
        );

        passwordChanged = await this.authService.setPassword(
          foundToken.userId as unknown as Types.ObjectId,
          passwordDto.newPassword,
        );
        if (!passwordChanged)
          return new HttpException(
            'Password is not changed',
            HttpStatus.INTERNAL_SERVER_ERROR,
          );
      } else {
        return new HttpException(
          'Password is not changed',
          HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }

      return new HttpException('Password is changed', HttpStatus.OK);
    } catch (error) {
      return new HttpException(
        `Error: ${error}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request) {
    try {
      const user = req.user;
      return await this.authService.logout(user['sub']);
    } catch (error) {
      return new HttpException(
        `Error: ${error}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('/refresh')
  async refreshTokens(@Req() req: Request) {
    try {
      const user = req.user;
      return this.jwtTokenService.refreshTokens(
        user['sub'],
        user['refreshToken'],
      );
    } catch (error) {
      return new HttpException(
        `Error: ${error}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Roles('user')
  @UseGuards(AuthGuard('jwt'))
  @Post('/password/forgot/:userId/:email')
  async sendEmailForgotPassword(@Param() params) {
    try {
      await this.authService.generatePasswordToken(params.userId);
      const forgotPasswordEmail =
        await this.authService.sendForgotPasswordMessage(
          params.userId,
          params.email,
        );

      if (!forgotPasswordEmail)
        return new HttpException(
          'Verification Letter is not sent',
          HttpStatus.INTERNAL_SERVER_ERROR,
        );
    } catch (error) {
      return new HttpException(
        `Error: ${error}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
