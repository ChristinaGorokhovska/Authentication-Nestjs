import { IsNotEmpty, IsOptional, IsEmail } from 'class-validator';

export class ProfileDto {
  @IsNotEmpty()
  readonly firstName: string;
  @IsNotEmpty()
  readonly lastName: string;
  readonly birthDate: Date;

  @IsOptional()
  readonly phone: string;
}
