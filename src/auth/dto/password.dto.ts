import { IsNotEmpty, IsOptional } from 'class-validator';
import { Types } from 'mongoose';

export class PasswordDto {
  readonly token: string;
  readonly currentPassword: string;
  readonly userId: Types.ObjectId;

  @IsNotEmpty()
  readonly newPassword: string;
}
