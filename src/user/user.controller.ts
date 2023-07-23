import {
  Body,
  Controller,
  HttpCode,
  HttpException,
  HttpStatus,
  Patch,
  Post,
  Req,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { UserService } from './user.service';
import { ProfileDto } from './dto/profile.dto';
import { Request } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { RoleGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/auth/decorators/roles.decorator';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { editFileName, imageFileFilter } from './utils/file.utils';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Roles('user')
  @UseGuards(AuthGuard('jwt'), RoleGuard)
  @Patch('/profile/update')
  @HttpCode(HttpStatus.OK)
  async updateProfile(@Req() req: Request, @Body() profileDto: ProfileDto) {
    try {
      const user = req.user;
      await this.userService.updateProfile(user['sub'], profileDto);
    } catch (error) {
      return new HttpException(
        `Error: ${error}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Roles('user')
  @UseGuards(AuthGuard('jwt'), RoleGuard)
  @Post('/profile/avatar/update')
  @UseInterceptors(
    FileInterceptor('image', {
      storage: diskStorage({
        destination: './files',
        filename: editFileName,
      }),
      fileFilter: imageFileFilter,
    }),
  )
  async uploadedFile(@Req() req: Request, @UploadedFile() file) {
    try {
      const user = req.user;
      return await this.userService.uploadAvatar(user['sub'], file.filename);
    } catch (error) {
      return new HttpException(
        `Error: ${error}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
